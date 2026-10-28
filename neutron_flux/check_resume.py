"""Re-establish unfinished check prerequisites after stale VM cleanup."""

from __future__ import annotations

import dataclasses
from collections import defaultdict
from typing import Any

from .check_ledger import check_ledger, root_reporter
from .check_plan import batch_key


def conditional_ids(specs: list[Any], *, include_load: bool = True) -> set[str]:
    output = set()
    for spec in specs:
        bindings = spec.metadata.get("check_bindings", {})
        output.update(bindings.get("placement", {}).values())
        if bindings.get("post-migration"):
            output.add(bindings["post-migration"])
        if include_load and bindings.get("load"):
            output.add(bindings["load"])
        for measurements in bindings.get("performance", {}).values():
            output.update(measurements.values())
    return output


def conditional_pending(
    reporter: Any, specs: list[Any], *, include_load: bool = True
) -> bool:
    pending = {
        row["id"] for row in check_ledger(reporter) if row["outcome"] == "PENDING"
    }
    return bool(pending & conditional_ids(specs, include_load=include_load))


def prepare_check_resume(executor: Any) -> None:
    """Use fresh evidence IDs within the same approved logical checks.

    Completed historical observations remain evidence. Unfinished conditional
    checks need a fresh baseline because Suite has deleted stale resources.
    Exact host-pair suites have their own equivalent replay preparation.
    """
    if not executor.config.resume_run_id or getattr(executor, "scope", None):
        return
    reporter = executor.reporter
    root = root_reporter(reporter)
    if not getattr(getattr(root, "plan", None), "checks", None):
        return
    base = [
        spec
        for spec in executor.plan.tests
        if spec.phase in {"intra", "cross"}
        and not spec.metadata.get("supplemental")
        and not spec.metadata.get("resume_recheck")
    ]
    batches: dict[tuple[Any, ...], list[Any]] = defaultdict(list)
    for spec in base:
        batches[batch_key(spec)].append(spec)
    replay = []
    for specs in batches.values():
        if any(
            not reporter.has_result(spec.id) for spec in specs
        ) or conditional_pending(reporter, specs, include_load=False):
            replay.extend(specs)
    if not replay or not any(reporter.has_result(spec.id) for spec in replay):
        return
    generation = 1
    known = {spec.id for spec in root.plan.tests}
    while any(
        f"{spec.id}-RESUME-{generation}" in known
        or reporter.has_result(f"{spec.id}-RESUME-{generation}")
        for spec in replay
    ):
        generation += 1
    mapping = {
        spec.id: f"{spec.id}-RESUME-{generation}"
        if reporter.has_result(spec.id)
        else spec.id
        for spec in replay
    }
    clones = [
        dataclasses.replace(
            spec,
            id=mapping[spec.id],
            requires=[mapping.get(item, item) for item in spec.requires],
            requires_pass=[mapping.get(item, item) for item in spec.requires_pass],
            metadata={
                **spec.metadata,
                "resume_recheck": True,
                "source_spec_id": spec.id,
            },
        )
        for spec in replay
        if mapping[spec.id] != spec.id
    ]
    # A missing old-generation result is historical evidence, not a verdict on
    # the new generation's assessment. Preserve its record under the same check.
    stale = [
        spec
        for spec in executor.plan.tests
        if spec.metadata.get("supplemental") and not reporter.has_result(spec.id)
    ]
    for spec in stale:
        spec.metadata["check_sample"] = True
    reporter.save_plan()
    if stale:
        executor._mark_specs_unavailable(
            stale,
            "Previous VM generation ended before this observation; "
            "the planned check is being assessed on fresh resources",
            blocked=True,
        )
    executor._append_runtime_specs(clones)
    reporter.logger.log(
        f"Resume: refreshing {len(clones)} prerequisite observations for unfinished "
        "planned checks; the planned total is unchanged"
    )

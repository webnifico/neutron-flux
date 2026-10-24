from __future__ import annotations

import importlib.util
import runpy
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from neutron_flux.models import PlannedGroup, RuntimeGroup
from neutron_flux.resource_naming import (
    ResourceNameRegistry,
    claim_runtime_resource_name,
    endpoint_resource_stem,
    resource_name_registry,
)
from neutron_flux.resources import ResourceBuilder

ROOT = Path(__file__).resolve().parents[2]


def test_shared_registry_allocates_generations_across_workers():
    allocator = ResourceNameRegistry("nflux-concurrent-generation")
    with ThreadPoolExecutor(max_workers=16) as pool:
        generations = list(
            pool.map(
                lambda _: allocator.allocate_group_generation("shared-group"),
                range(128),
            )
        )
    assert sorted(generations) == list(range(1, 129))
    assert allocator.allocate_group_generation("shared-group") == 129


def test_per_zone_then_cross_zone_builds_allocate_fresh_names():
    prefix = "nflux-sample-generation-regression"
    builder = object.__new__(ResourceBuilder)
    builder.name_prefix = prefix
    builder.resource_name_registry = resource_name_registry(prefix)
    builder.runtime_groups = []
    builder.group_failures = {}
    builder.group_failure_types = {}
    builder.reporter = mock.Mock()
    builder.reporter.resources = []
    builder.logger = mock.Mock()

    group = PlannedGroup(
        id="provider-public3@bc-van1",
        kind="provider",
        label="Provider Public3 [bc-van1]",
        network_id="network-id",
        network_name="Public3",
        subnet_ids=["subnet-id"],
        families=[4],
    )
    observed_generations: list[int] = []
    observed_names: list[str] = []

    def build_provider(
        planned: PlannedGroup, *, sides: tuple[str, ...], generation: int
    ) -> RuntimeGroup:
        observed_generations.append(generation)
        server_name = endpoint_resource_stem(
            prefix, planned, generation=generation, side=sides[0]
        )
        claim_runtime_resource_name(builder, server_name, resource_type="server")
        observed_names.append(server_name)
        return RuntimeGroup(
            plan=planned,
            network_id="network-id",
            network_name="Public3",
            subnet_ids=["subnet-id"],
            router_id=None,
            endpoints=[],
            source_nat_enabled=None,
            fips={},
            generation=generation,
        )

    builder._build_provider_group = mock.Mock(side_effect=build_provider)

    per_zone = builder.build_group(group, sides=("A", "B"))
    builder.runtime_groups.clear()  # Simulate successful per-zone cleanup.
    cross_zone = builder.build_group(group, sides=("A",))

    assert per_zone is not None and per_zone.generation == 1
    assert cross_zone is not None and cross_zone.generation == 2
    assert observed_generations == [1, 2]
    assert len(set(observed_names)) == 2
    reservations = builder.resource_name_registry.snapshot()
    assert "|g1|" in reservations[observed_names[0]]["identity"]
    assert "|g2|" in reservations[observed_names[1]]["identity"]
    assert all(reservations[name]["claimed_for_create"] for name in observed_names)


def test_release_builder_excludes_generated_run_evidence(tmp_path):
    builder = runpy.run_path(str(ROOT / "support/scripts/build-release.py"))
    included = builder["included"]
    included.__globals__["ROOT"] = tmp_path

    source = tmp_path / "neutron_flux" / "module.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    evidence = tmp_path / "neutron-flux-reports" / "runs" / "run" / "results.json"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}\n", encoding="utf-8")

    assert included(source) is True
    assert included(evidence) is False


def test_coverage_shards_are_deterministic_and_exhaustive():
    validator = runpy.run_path(str(ROOT / "support/scripts/validate-release.py"))
    coverage_test_shards = validator["coverage_test_shards"]

    first = coverage_test_shards(8)
    second = coverage_test_shards(8)
    expected = sorted((ROOT / "support/tests").glob("test_*.py"))
    flattened = [path for shard in first for path in shard]

    assert first == second
    assert sorted(flattened) == expected
    assert len(flattened) == len(set(flattened))
    assert all(shard == sorted(shard) for shard in first)


def test_release_tests_use_only_declared_pytest_plugins(tmp_path):
    validator = runpy.run_path(str(ROOT / "support/scripts/validate-release.py"))
    gate = validator["run_test_and_coverage_gates"]
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    isolated_test = tmp_path / "support/tests/test_release_identity.py"
    isolated_test.parent.mkdir(parents=True)
    isolated_test.touch()

    def capture(*command: str, **kwargs: object) -> None:
        calls.append((command, kwargs))

    gate.__globals__["ROOT"] = tmp_path
    gate.__globals__["run"] = capture
    gate.__globals__["coverage_test_shards"] = lambda: [[isolated_test]]
    gate()

    pytest_calls = [call for call in calls if "pytest" in call[0]]
    assert len(pytest_calls) == 2
    for command, kwargs in pytest_calls:
        environment = kwargs["env"]
        assert isinstance(environment, dict)
        assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        plugin_pairs = list(zip(command, command[1:], strict=False))
        assert ("-p", "pytest_asyncio.plugin") in plugin_pairs
        assert isinstance(kwargs["timeout_seconds"], int)
    coverage_command, coverage_kwargs = pytest_calls[1]
    assert coverage_command[2:4] == ("coverage", "run")
    assert "--branch" in coverage_command
    assert "--source=neutron_flux" in coverage_command
    assert "--append" not in coverage_command
    assert "pytest_cov.plugin" not in coverage_command
    coverage_environment = coverage_kwargs["env"]
    assert isinstance(coverage_environment, dict)
    assert str(coverage_environment["COVERAGE_FILE"]).endswith(".coverage.shard-00")
    assert any(call[0][2:4] == ("coverage", "combine") for call in calls)


def test_release_validator_requires_an_executable_module(monkeypatch):
    validator = runpy.run_path(str(ROOT / "support/scripts/validate-release.py"))
    available = validator["executable_module_available"]
    real_find_spec = importlib.util.find_spec

    def fake_find_spec(name: str):
        if name == "build.__main__":
            return None
        return real_find_spec(name)

    monkeypatch.setattr(importlib.util, "find_spec", fake_find_spec)

    assert available("build") is False
    assert available("pip") is True

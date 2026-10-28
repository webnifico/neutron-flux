from __future__ import annotations

from .config import Config
from .log import Logger
from .models import Discovery, Plan, PlannedPathTest, TestSpec


class PlanDiagramRenderer:
    def __init__(
        self,
        config: Config,
        discovery: Discovery,
        plan: Plan,
        logger: Logger,
    ):
        self.config = config
        self.discovery = discovery
        self.plan = plan
        self.logger = logger
        self.tests = [self._path(item) for item in plan.tests]

    def render(self) -> None:
        self.logger.section("Adaptive execution plan")
        self.logger.log(
            f"Tests={len(self.plan.tests)}, groups={len(self.plan.groups)}, "
            f"peak_instances={self.plan.estimated.get('peak_instances')}, "
            f"peak_endpoint_instances={self.plan.estimated.get('peak_endpoint_instances')}"
        )
        self.logger.log(
            "Execution phases: controller bootstrap -> group-local A/B tests -> "
            "cross-topology A/A tests -> bounded cleanup verification"
        )
        if self.plan.checks:
            self.logger.log(
                f"Complete workload: {len(self.plan.checks)} checks including conditional work"
            )
            for check in self.plan.checks:
                if check["kind"] != "network":
                    self.logger.log(
                        f"  {check['id']}: {check['title']}; condition: {check['condition']}"
                    )
        for warning in self.plan.warnings:
            self.logger.log(f"Plan warning: {warning}", "WARNING")
        for index, spec in enumerate(self.plan.tests, start=1):
            source = self._endpoint_text(
                spec.source_group_id, spec.source_side, spec.source_subnet_id
            )
            destination = self._endpoint_text(
                spec.destination_group_id,
                spec.destination_side,
                spec.destination_subnet_id,
            )
            dependencies = ",".join(spec.dependencies) or "controller"
            self.logger.log(
                f"[{index:03d}/{len(self.plan.tests):03d}] {spec.id}: "
                f"{source} -> {destination}; protocol={spec.protocol or spec.operation}; "
                f"expected={spec.expectation}; authoritative={spec.authoritative}; "
                f"phase={spec.phase}; resources={dependencies}"
            )

    def _endpoint_text(
        self, group_id: str | None, side: str, subnet_id: str | None
    ) -> str:
        if not group_id:
            return "controller/external"
        try:
            group = self.plan.group(group_id)
        except StopIteration:
            return group_id
        subnet = "runtime subnet" if subnet_id in {None, "runtime"} else subnet_id
        return f"{group.label}:{side} [{subnet}]"

    def _path(self, spec: TestSpec) -> PlannedPathTest:
        control = ["IPv4-only runner", "SSH controller"]
        if spec.source_group_id:
            control.append(
                f"management SSH -> {spec.source_group_id}:{spec.source_side}"
            )
        data = []
        if spec.source_group_id:
            data.append(f"{spec.source_group_id}:{spec.source_side}")
        if spec.destination_group_id:
            data.append(f"{spec.destination_group_id}:{spec.destination_side}")
        if not data:
            data.append("controller bootstrap")
        return PlannedPathTest(
            test_id=spec.id,
            category=spec.category,
            family=spec.family,
            control_path=control,
            data_path=data,
            operation=spec.operation,
            expectation=spec.expectation,
        )

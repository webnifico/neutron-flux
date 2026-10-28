from __future__ import annotations

import shutil
from types import SimpleNamespace
from unittest import mock

import pytest

from neutron_flux.engine import TestEngine as FluxEngine
from neutron_flux.engine_handlers.registry import (
    OPERATION_METHODS,
)
from neutron_flux.engine_state import LifecycleStateStore
from neutron_flux.models import TestSpec as FluxTestSpec
from neutron_flux.reporting import ResourceTracker
from neutron_flux.resources import ResourceBuilder
from neutron_flux.runtime.context import ResourceRuntimeState, RuntimeDependencies

from ._shared import build_plan, make_reporter


def test_resource_builder_owns_mutable_state_in_typed_context(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    plan = build_plan(config, discovery_fixture, tmp_path)
    reporter = make_reporter(config, run_id="state-context")
    tracker = ResourceTracker(reporter)
    osc = mock.Mock()

    builder = ResourceBuilder(config, discovery_fixture, plan, osc, reporter, tracker)
    try:
        assert isinstance(builder.dependencies, RuntimeDependencies)
        assert isinstance(builder.state, ResourceRuntimeState)
        assert builder.dependencies.config is config
        assert builder.state.run_tag == reporter.run_tag
        assert builder.work_dir == builder.state.work_dir

        builder.image_id = "image-from-alias"
        assert builder.state.image_id == "image-from-alias"

        builder.state.selected_availability_zone = "az-context"
        assert builder.selected_availability_zone == "az-context"
    finally:
        shutil.rmtree(builder.work_dir, ignore_errors=True)


def test_state_descriptors_preserve_partial_builder_unit_tests():
    builder = ResourceBuilder.__new__(ResourceBuilder)
    builder.image_id = "partial-image"
    builder._aggregate_inventory_state = "partial"

    assert builder.image_id == "partial-image"
    assert builder._aggregate_inventory_state == "partial"
    assert "_state" not in builder.__dict__


def test_operation_registry_is_immutable_and_complete(
    config_factory, discovery_fixture, tmp_path
):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    plan = build_plan(config, discovery_fixture, tmp_path)
    planned_operations = {spec.operation for spec in plan.tests}

    assert planned_operations <= (
        set(OPERATION_METHODS) | {"controller-observation", "controller-ssh"}
    )
    with pytest.raises(TypeError):
        OPERATION_METHODS["unexpected"] = "_run_endpoint_probe"  # type: ignore[index]


def test_engine_binds_operation_handlers_once(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = make_reporter(config, run_id="engine-registry")
    builder = SimpleNamespace(
        ssh_endpoint=lambda endpoint, command: None,
        ssh_controller=lambda command: None,
        runtime_groups=[],
        osc=mock.Mock(),
    )
    engine = FluxEngine(config, SimpleNamespace(), builder, reporter)

    assert set(engine.operations) == set(OPERATION_METHODS)
    assert isinstance(engine.lifecycle, LifecycleStateStore)


def test_engine_rejects_unregistered_operation(config_factory, tmp_path):
    config = config_factory(action="run", report_dir=tmp_path / "reports")
    reporter = make_reporter(config, run_id="engine-unsupported")
    builder = SimpleNamespace(
        ssh_endpoint=lambda endpoint, command: None,
        ssh_controller=lambda command: None,
        runtime_groups=[],
        osc=mock.Mock(),
    )
    engine = FluxEngine(config, SimpleNamespace(), builder, reporter)
    spec = FluxTestSpec(
        id="UNREGISTERED",
        category="internal",
        operation="not-registered",
        family=4,
        expectation="reachable",
        expectation_reason="test",
        authoritative=True,
        dependencies=[],
    )

    with pytest.raises(Exception, match="Unsupported TestSpec operation"):
        engine._run_spec(spec)


def test_lifecycle_store_has_one_authoritative_missing_state_error():
    store = LifecycleStateStore()
    with pytest.raises(
        KeyError, match="Lifecycle baseline is unavailable: fip:missing"
    ):
        store.require("fip:missing")

    state = store["fip:group"] = {"baseline": True, "detach_requested": False}
    assert state["baseline"] is True
    assert store.require("fip:group") is state

from __future__ import annotations

import time

# mypy: disable-error-code="attr-defined"
from collections.abc import Callable, Iterable
from typing import Any

from .cancellation import raise_if_cancelled
from .errors import (
    DependentMeasurementUnavailable,
    MeasurementExecutionError,
    PathReachabilityError,
    RunCancelledError,
    SSHExecutionError,
)
from .models import TestSpec
from .mtu_contract import (
    classify_mtu_contract_probe,
    confirmed_fragmentation_path_mtu,
    confirmed_no_fragment_path_mtu,
    local_mtu_constraint,
)
from .utils import iso_utc


class PerformanceMeasurementMixin:
    """Coordinate independent performance families without inflating failures."""

    def _run_specs_isolated(self, specs: Iterable[TestSpec]) -> None:
        grouped: dict[str, list[TestSpec]] = {}
        unavailable_endpoints: dict[str, tuple[str, str]] = {}
        for spec in specs:
            path_id = str(spec.metadata.get("performance_path_id") or "")
            if path_id:
                grouped.setdefault(path_id, []).append(spec)
        for path_specs in grouped.values():
            self.reporter.logger.log(
                "Starting planned performance checks: "
                + ", ".join(spec.display_name or spec.operation for spec in path_specs)
            )
            path = self._planned[path_specs[0].id]
            started = time.monotonic()
            self._measurement_timings = {}
            self._partial_udp_samples = {}
            self._udp_active_profile = {}
            try:
                resolved = self._resolve(path)
            except RunCancelledError:
                raise
            except Exception as exc:
                self._record_path_error(path_specs, path, exc, started)
                continue
            unavailable = (
                next(
                    (
                        unavailable_endpoints[item.server_id]
                        for item in (resolved.source, resolved.destination)
                        if item.server_id in unavailable_endpoints
                    ),
                    None,
                )
                if unavailable_endpoints
                else None
            )
            if unavailable:
                for spec in path_specs:
                    dependency = DependentMeasurementUnavailable(
                        f"Management access for a required endpoint failed earlier in this measurement window: {unavailable[0]}"
                    )
                    dependency.root_incident_id = unavailable[1]
                    self._record_measurement_error(
                        spec, resolved, dependency, started=started
                    )
                continue
            try:
                with self._local_probe_server(resolved):
                    measurements, errors = self._measure(resolved)
            except RunCancelledError:
                raise
            except Exception as exc:
                measurements = {}
                errors = {}
                root_measurement = str(
                    path_specs[0].metadata.get("performance_measurement")
                    or "measurement"
                )
                errors[root_measurement] = exc
                for dependent_spec in path_specs[1:]:
                    dependent = str(
                        dependent_spec.metadata.get("performance_measurement")
                        or "measurement"
                    )
                    errors[dependent] = DependentMeasurementUnavailable(
                        f"{dependent.replace('-', ' ').title()} was not run because "
                        f"performance path setup failed: {exc}"
                    )
            for spec in path_specs:
                measurement = str(spec.metadata["performance_measurement"])
                if measurement in errors:
                    error = errors[measurement]
                    if isinstance(error, SSHExecutionError):
                        server_id = error.evidence.get("server_id")
                        if server_id:
                            unavailable_endpoints[str(server_id)] = (
                                str(error),
                                f"performance-path:{path.path_id}:execution",
                            )
                    self._record_measurement_error(
                        spec, resolved, errors[measurement], started=started
                    )
                    continue
                self._record_measurement(
                    spec,
                    resolved,
                    measurements[measurement],
                    started=float(measurements[measurement].get("started", started)),
                )
            self.session.completed_by_stage[path.stage] = (
                self.session.completed_by_stage.get(path.stage, 0) + 1
            )

    def _measure(
        self, path: Any
    ) -> tuple[dict[str, dict[str, Any]], dict[str, BaseException]]:
        self.reporter.logger.section(f"Performance path: {path.label}")
        self.reporter.logger.log(
            f"Path context: category={path.plan.category}, IPv{path.plan.family}, "
            f"placement={path.placement}, availability={path.availability_scope}, "
            f"stage={path.plan.stage}, directions={','.join(path.plan.directions)}"
        )
        measurements: dict[str, dict[str, Any]] = {}
        errors: dict[str, BaseException] = {}
        self._measurement_timings = {}
        self._partial_udp_samples = {}
        self._udp_active_profile = {}

        tcp_started = time.monotonic()
        tcp_result = self._capture_measurement(
            errors,
            ("tcp-throughput", "concurrency", "repeatability"),
            lambda: self._measure_tcp_family(path),
        )
        tcp_metrics = None
        if tcp_result is not None:
            tcp_metrics, payloads, tcp_error = tcp_result
            for payload in payloads.values():
                payload["started"] = tcp_started
            measurements.update(payloads)
            if tcp_error is not None:
                errors["tcp-throughput"] = self._classify_measurement_exception(
                    tcp_error
                )
        if isinstance(
            errors.get("tcp-throughput"), (PathReachabilityError, SSHExecutionError)
        ):
            self._mark_path_dependents(
                errors,
                root="tcp-throughput",
                names=("latency", "udp", "mtu-mss", "asymmetry"),
            )
            return measurements, errors

        latency_started = time.monotonic()
        latency_result = self._capture_measurement(
            errors, ("latency",), lambda: self._measure_latency_family(path)
        )
        latency_metrics = None
        if latency_result is not None:
            latency_metrics, payload = latency_result
            payload["started"] = latency_started
            measurements["latency"] = payload
        if isinstance(
            errors.get("latency"), (PathReachabilityError, SSHExecutionError)
        ):
            self._mark_path_dependents(
                errors, root="latency", names=("udp", "mtu-mss", "asymmetry")
            )
            return measurements, errors

        udp_started = time.monotonic()
        udp_result = self._capture_measurement(
            errors, ("udp",), lambda: self._measure_udp_family(path)
        )
        udp_metrics = None
        if udp_result is not None:
            udp_metrics, payload = udp_result
            payload["started"] = udp_started
            measurements["udp"] = payload
        if isinstance(errors.get("udp"), (PathReachabilityError, SSHExecutionError)):
            self._mark_path_dependents(
                errors, root="udp", names=("mtu-mss", "asymmetry")
            )
            return measurements, errors

        mtu_started = time.monotonic()
        mtu_result = self._capture_measurement(
            errors,
            ("mtu-mss",),
            lambda: self._measure_mtu_family(path, tcp_metrics),
        )
        if mtu_result is not None:
            mtu_result["started"] = mtu_started
            measurements["mtu-mss"] = mtu_result
        if isinstance(
            errors.get("mtu-mss"), (PathReachabilityError, SSHExecutionError)
        ):
            self._mark_path_dependents(errors, root="mtu-mss", names=("asymmetry",))
            return measurements, errors

        if "reverse" in path.plan.directions:
            if (
                tcp_metrics is not None
                and latency_metrics is not None
                and udp_metrics is not None
            ):
                asymmetry = self._asymmetry(
                    tcp_metrics["forward"],
                    tcp_metrics["reverse"],
                    latency_metrics["idle"],
                    udp_metrics,
                )
                payload = self._measurement_payload(
                    "Directional asymmetry", asymmetry, asymmetry["health"]
                )
                payload["started"] = time.monotonic()
                measurements["asymmetry"] = payload
            else:
                errors["asymmetry"] = DependentMeasurementUnavailable(
                    "Directional asymmetry was not calculated because one or more "
                    "directional TCP, latency, or UDP measurements did not complete"
                )
        return measurements, errors

    @staticmethod
    def _classify_measurement_exception(exc: BaseException) -> BaseException:
        if isinstance(
            exc,
            (
                RunCancelledError,
                DependentMeasurementUnavailable,
                PathReachabilityError,
                MeasurementExecutionError,
            ),
        ):
            return exc
        text = str(exc).lower()
        execution_markers = (
            "stdio forwarding failed",
            "command timed out",
            "returned no json",
            "invalid json",
            "json result must be an object",
            "command not found",
            "no such file or directory",
            "permission denied",
            "module not found",
            "modulenotfounderror",
            "syntaxerror",
            "traceback",
            "performance server did not become ready",
            "temporary runner performance listener",
            "connection refused",
        )
        if any(marker in text for marker in execution_markers):
            return exc
        routing_markers = (
            "no route to host",
            "network is unreachable",
            "destination host unreachable",
            "destination unreachable",
            "address unreachable",
            "connection timed out",
            "timeouterror: timed out",
            "[errno 110]",
            "[errno 101]",
            "100% packet loss",
        )
        if any(marker in text for marker in routing_markers):
            return PathReachabilityError(str(exc))
        return exc

    @classmethod
    def _mark_path_dependents(
        cls,
        errors: dict[str, BaseException],
        *,
        root: str,
        names: tuple[str, ...],
    ) -> None:
        reason = str(errors[root]).strip() or type(errors[root]).__name__
        cause = (
            "established that the path was unreachable"
            if isinstance(errors[root], PathReachabilityError)
            else "could not execute because the management transport was unavailable"
        )
        for name in names:
            errors.setdefault(
                name,
                DependentMeasurementUnavailable(
                    f"{name.replace('-', ' ').title()} was not run because the "
                    f"{root.replace('-', ' ')} measurement {cause}: {reason}"
                ),
            )

    def _capture_measurement(
        self,
        errors: dict[str, BaseException],
        names: tuple[str, ...],
        operation: Callable[[], Any],
    ) -> Any | None:
        started = time.monotonic()
        started_at = iso_utc()
        try:
            return operation()
        except RunCancelledError:
            raise
        except Exception as exc:
            classified = PerformanceMeasurementMixin._classify_measurement_exception(
                exc
            )
            if names:
                errors[names[0]] = classified
            for name in names[1:]:
                errors[name] = DependentMeasurementUnavailable(
                    f"{name.replace('-', ' ').title()} was not calculated because "
                    f"{names[0].replace('-', ' ')} failed: {classified}"
                )
            return None
        finally:
            timing = {
                "started_at": started_at,
                "finished_at": iso_utc(),
                "duration_ms": max(0, int((time.monotonic() - started) * 1000)),
            }
            if not hasattr(self, "_measurement_timings"):
                self._measurement_timings = {}
            for name in names:
                self._measurement_timings[name] = timing

    def _measure_tcp_family(
        self, path: Any
    ) -> tuple[
        dict[str, Any],
        dict[str, dict[str, Any]],
        BaseException | None,
    ]:
        tcp_metrics: dict[str, Any] = {
            "forward": self._tcp_direction(
                path.source,
                path.forward_source_ip,
                path.forward_destination_ip,
                path.plan.family,
            )
        }
        if "reverse" in path.plan.directions:
            tcp_metrics["reverse"] = self._tcp_direction(
                path.destination,
                path.reverse_source_ip,
                path.reverse_destination_ip,
                path.plan.family,
                expected_peer_ip=path.reverse_expected_peer_ip,
            )

        bidirectional_error: BaseException | None = None
        if "reverse" in path.plan.directions:
            try:
                tcp_metrics["bidirectional"] = self._bidirectional_tcp(path)
            except RunCancelledError:
                raise
            except Exception as exc:
                # Directional samples remain useful even if only the simultaneous
                # bidirectional load could not execute.
                bidirectional_error = exc

        concurrency = self._concurrency(tcp_metrics)
        repeatability = self._repeatability(tcp_metrics)
        payloads = {
            "concurrency": self._measurement_payload(
                "Concurrent-flow scaling", concurrency, concurrency["health"]
            ),
            "repeatability": self._measurement_payload(
                "Path repeatability", repeatability, repeatability["health"]
            ),
        }
        if bidirectional_error is None:
            payloads["tcp-throughput"] = self._measurement_payload(
                "TCP throughput", tcp_metrics, self._tcp_health(tcp_metrics)
            )
        return tcp_metrics, payloads, bidirectional_error

    def _measure_latency_family(
        self, path: Any
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        idle = {
            "forward": self._ping(
                path.source,
                path.forward_source_ip,
                path.forward_destination_ip,
                path.plan.family,
            )
        }
        loaded = {
            "forward": self._loaded_latency(
                path.source,
                path.forward_source_ip,
                path.forward_destination_ip,
                path.plan.family,
            )
        }
        if "reverse" in path.plan.directions:
            idle["reverse"] = self._ping(
                path.destination,
                path.reverse_source_ip,
                path.reverse_destination_ip,
                path.plan.family,
            )
            loaded["reverse"] = self._loaded_latency(
                path.destination,
                path.reverse_source_ip,
                path.reverse_destination_ip,
                path.plan.family,
                expected_peer_ip=path.reverse_expected_peer_ip,
            )
        metrics = self._latency_metrics(idle, loaded)
        return metrics, self._measurement_payload(
            "Idle and loaded latency", metrics, self._latency_health(metrics)
        )

    def _measure_udp_family(self, path: Any) -> tuple[dict[str, Any], dict[str, Any]]:
        metrics = self._udp_matrix(path)
        return metrics, self._measurement_payload(
            "UDP application-delivery loss, jitter, and packet rate",
            metrics,
            self._udp_health(metrics),
        )

    def _measure_mtu_family(
        self,
        path: Any,
        tcp_metrics: dict[str, Any] | None,
    ) -> dict[str, Any]:
        contract = path.mtu_contract
        forward = classify_mtu_contract_probe(
            self._fresh_mtu_probe(
                path.source,
                path.forward_source_ip,
                path.forward_destination_ip,
                path.plan.family,
                path.expected_mtu,
            ),
            expected_mtu=path.expected_mtu,
            contract_authoritative=bool(contract.get("authoritative")),
        )
        forward = self._post_migration_mtu_settlement(
            path,
            forward,
            source=path.source,
            source_ip=path.forward_source_ip,
            destination_ip=path.forward_destination_ip,
        )
        mtu = {"forward": forward}
        forward_path_mtu = confirmed_fragmentation_path_mtu(
            forward,
            path.expected_mtu,
        )
        mtu["forward"]["fragmentation"] = self._fragmentation_probe(
            path.source,
            path.forward_source_ip,
            path.forward_destination_ip,
            path.plan.family,
            path.source_mtu,
            forward_path_mtu,
            destination=path.destination,
            router_ids=path.router_ids,
            router_backend_evidence=path.router_backend_evidence,
        )
        if "reverse" in path.plan.directions:
            reverse = classify_mtu_contract_probe(
                self._fresh_mtu_probe(
                    path.destination,
                    path.reverse_source_ip,
                    path.reverse_destination_ip,
                    path.plan.family,
                    path.expected_mtu,
                ),
                expected_mtu=path.expected_mtu,
                contract_authoritative=bool(contract.get("authoritative")),
            )
            reverse = self._post_migration_mtu_settlement(
                path,
                reverse,
                source=path.destination,
                source_ip=path.reverse_source_ip,
                destination_ip=path.reverse_destination_ip,
            )
            mtu["reverse"] = reverse
            reverse_path_mtu = confirmed_fragmentation_path_mtu(
                reverse,
                path.expected_mtu,
            )
            mtu["reverse"]["fragmentation"] = self._fragmentation_probe(
                path.destination,
                path.reverse_source_ip,
                path.reverse_destination_ip,
                path.plan.family,
                path.destination_mtu,
                reverse_path_mtu,
                destination=path.source,
                router_ids=path.router_ids,
                router_backend_evidence=path.router_backend_evidence,
            )
        if tcp_metrics is not None:
            self._attach_mss(mtu, tcp_metrics, path.plan.family)
        else:
            overhead = 60 if path.plan.family == 6 else 40
            for _direction, item in mtu.items():
                discovered = confirmed_no_fragment_path_mtu(item)
                item.update(
                    expected_max_mss=(
                        max(0, int(discovered) - overhead)
                        if discovered is not None
                        else None
                    ),
                    mss_constraint_source=(
                        "confirmed-no-fragment-path-mtu"
                        if discovered is not None
                        else "path-boundary-unverified"
                    ),
                    client_mss=None,
                    server_mss=None,
                )
        metrics = {
            "expected_mtu": path.expected_mtu,
            "source_mtu": path.source_mtu,
            "destination_mtu": path.destination_mtu,
            "contract_authoritative": bool(contract.get("authoritative")),
            "contract_authority_summary": contract.get("authority_summary"),
            "mtu_constraints": contract.get("constraints") or [],
            "limiting_mtu_constraints": contract.get("limiting_constraints") or [],
            "mtu_contract_formula": contract.get("formula"),
            "mtu_contract_fallback_used": bool(contract.get("fallback_used")),
            "directions": list(path.plan.directions),
            **mtu,
        }
        return self._measurement_payload(
            "Path MTU, PMTUD, and TCP MSS",
            metrics,
            self._mtu_health(metrics, path.expected_mtu),
        )

    def _post_migration_mtu_settlement(
        self,
        path: Any,
        initial: dict[str, Any],
        *,
        source: Any,
        source_ip: str,
        destination_ip: str,
    ) -> dict[str, Any]:
        stage = str(path.plan.stage or "").lower()
        if "post-live-migration" not in stage:
            result = dict(initial)
            result["post_migration_persistence"] = {
                "classification": "not-applicable",
                "settled": True,
                "samples": [self._mtu_settlement_sample(initial, 0.0)],
                "reason": "This path was not measured in a post-live-migration phase.",
            }
            return result

        started = time.monotonic()
        samples = [dict(initial)]
        interval = max(
            0.2,
            min(float(getattr(self.config, "convergence_interval", 1) or 1), 2.0),
        )
        for _ in range(2):
            raise_if_cancelled()
            time.sleep(interval)
            candidate = classify_mtu_contract_probe(
                self._fresh_mtu_probe(
                    source,
                    source_ip,
                    destination_ip,
                    path.plan.family,
                    path.expected_mtu,
                ),
                expected_mtu=path.expected_mtu,
                contract_authoritative=bool(path.mtu_contract.get("authoritative")),
            )
            samples.append(candidate)
            classifications = [
                str(item.get("discovery_confidence") or "") for item in samples
            ]
            discovered = [item.get("discovered_mtu") for item in samples]
            if len(samples) >= 2 and classifications[-2:] == [
                "expected-confirmed",
                "expected-confirmed",
            ]:
                break
            if len(samples) >= 2 and (
                (
                    classifications[-2:]
                    == ["confirmed-lower-boundary", "confirmed-lower-boundary"]
                    and discovered[-1] == discovered[-2]
                )
                or (
                    classifications[-2] == classifications[-1]
                    and classifications[-1]
                    in {
                        "cached-route-pmtu",
                        "interface-mtu-constraint",
                        "local-mtu-constraint-unverified",
                    }
                    and discovered[-1] == discovered[-2]
                )
            ):
                break

        initial_confidence = str(initial.get("discovery_confidence") or "")
        final_two = samples[-2:]
        final_confidences = [
            str(item.get("discovery_confidence") or "") for item in final_two
        ]
        final_mtu = [item.get("discovered_mtu") for item in final_two]
        if final_confidences == ["expected-confirmed", "expected-confirmed"]:
            if initial_confidence == "confirmed-lower-boundary":
                classification = "transient-recovered"
                reason = (
                    "The immediate post-migration sample was below the advertised "
                    "MTU, then two consecutive samples returned to the advertised "
                    "boundary inside the convergence window."
                )
            elif initial_confidence in {
                "cached-route-pmtu",
                "interface-mtu-constraint",
                "local-mtu-constraint-unverified",
            }:
                classification = "local-constraint-cleared"
                reason = (
                    "The immediate post-migration sample was constrained locally, "
                    "then two consecutive samples confirmed the advertised path MTU."
                )
            else:
                classification = "stable-at-advertised-mtu"
                reason = (
                    "Consecutive post-migration samples confirmed the advertised MTU."
                )
            settled = True
        elif (
            final_confidences
            == ["confirmed-lower-boundary", "confirmed-lower-boundary"]
            and final_mtu[0] == final_mtu[1]
        ):
            classification = "persistent-lower-boundary"
            reason = (
                f"Consecutive post-migration samples confirmed the same lower "
                f"boundary ({final_mtu[-1]} bytes)."
            )
            settled = True
        elif (
            final_confidences[0] == final_confidences[1]
            and final_confidences[0]
            in {
                "cached-route-pmtu",
                "interface-mtu-constraint",
                "local-mtu-constraint-unverified",
            }
            and final_mtu[0] == final_mtu[1]
        ):
            local_class = final_confidences[-1]
            classification = f"persistent-{local_class}"
            if local_class == "cached-route-pmtu":
                reason = (
                    f"Two consecutive settlement samples observed the same cached "
                    f"per-destination route PMTU ({final_mtu[-1]} bytes). Packets "
                    "above that value were not transmitted, so the current "
                    "end-to-end path boundary remained unverified."
                )
            elif local_class == "interface-mtu-constraint":
                reason = (
                    f"Two consecutive settlement samples observed the same source "
                    f"interface MTU constraint ({final_mtu[-1]} bytes). The current "
                    "end-to-end path boundary remained unverified."
                )
            else:
                reason = (
                    "Two consecutive settlement samples observed the same local MTU "
                    "constraint, but its source could not be distinguished safely. "
                    "The current end-to-end path boundary remained unverified."
                )
            settled = True
        else:
            classification = "unstable"
            reason = (
                "Post-migration MTU samples did not converge on two consecutive "
                "matching advertised or lower-boundary results."
            )
            settled = False
        selected = dict(samples[-1])
        selected["post_migration_persistence"] = {
            "classification": classification,
            "settled": settled,
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "sample_interval_seconds": interval,
            "samples": [
                self._mtu_settlement_sample(item, index * interval)
                for index, item in enumerate(samples)
            ],
            "reason": reason,
            "initial_observed_mtu": initial.get("discovered_mtu"),
            "settled_observed_mtu": selected.get("discovered_mtu"),
            "initial_boundary_mtu": confirmed_no_fragment_path_mtu(initial),
            "settled_boundary_mtu": confirmed_no_fragment_path_mtu(selected),
            "initial_local_constraint": local_mtu_constraint(initial)[1],
            "settled_local_constraint": local_mtu_constraint(selected)[1],
        }
        return selected

    @staticmethod
    def _mtu_settlement_sample(
        item: dict[str, Any],
        elapsed_seconds: float,
    ) -> dict[str, Any]:
        return {
            "elapsed_seconds": round(float(elapsed_seconds), 3),
            "discovered_mtu": item.get("discovered_mtu"),
            "discovery_confidence": item.get("discovery_confidence"),
            "expected_probe_classification": item.get("expected_probe_classification"),
            "contract_status": item.get("advertised_mtu_contract_status"),
            "pmtud_status": item.get("pmtud_status"),
        }

    @staticmethod
    def _measurement_payload(
        label: str, metrics: dict[str, Any], health: str
    ) -> dict[str, Any]:
        return {"label": label, "health": health, "metrics": metrics}

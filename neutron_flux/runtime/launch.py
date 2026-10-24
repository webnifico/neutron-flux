from __future__ import annotations

import re
from typing import Any

# mypy: disable-error-code="attr-defined"
from ..config import Config
from ..constants import MIN_TEST_RAM_MB
from ..errors import SuiteError
from ..models import Discovery, Plan
from ..openstack import OpenStack
from ..utils import list_value, normalized_map, optional_text, pick, required_text
from .types import LaunchSelection


def _image_admin_user(image: dict[str, Any]) -> str | None:
    direct = pick(image, "os_admin_user", "admin_user")
    if direct:
        return str(direct)
    properties = pick(image, "properties", default={})
    if isinstance(properties, dict):
        normalized = normalized_map(properties)
        property_user = normalized.get("os_admin_user") or normalized.get("admin_user")
        if property_user:
            return str(property_user)
    if isinstance(properties, str):
        match = re.search(
            r"(?:os_admin_user|admin_user)\s*[=:]\s*['\"]?([A-Za-z0-9_.-]+)",
            properties,
        )
        if match:
            return match.group(1)
    name = str(pick(image, "name", default="")).lower()
    mapping = [
        ("debian", "debian"),
        ("ubuntu", "ubuntu"),
        ("rocky", "rocky"),
        ("alma", "almalinux"),
        ("centos", "centos"),
        ("fedora", "fedora"),
        ("cirros", "cirros"),
    ]
    for needle, user in mapping:
        if needle in name:
            return user
    return None


def _image_disk_requirements(image: dict[str, Any]) -> tuple[int, int, int]:
    try:
        min_disk = max(0, int(pick(image, "min_disk", default=0) or 0))
    except (TypeError, ValueError) as exc:
        raise SuiteError(
            f"Image returned an invalid min_disk value: {pick(image, 'min_disk')!r}"
        ) from exc

    virtual_raw = pick(image, "virtual_size", "virtual-size", default=0)
    try:
        virtual_bytes = max(0, int(virtual_raw or 0))
    except (TypeError, ValueError) as exc:
        raise SuiteError(
            f"Image returned an invalid virtual_size value: {virtual_raw!r}"
        ) from exc
    gib = 1024**3
    virtual_gib = (virtual_bytes + gib - 1) // gib if virtual_bytes else 0
    return min_disk, virtual_gib, max(min_disk, virtual_gib)


def _volume_type_availability_zones(detail: dict[str, Any]) -> frozenset[str] | None:
    """Return a volume type's explicit AZ allowlist, when one is declared.

    Cinder exposes volume type extra specs through different OpenStackClient
    payload shapes across releases.  Accept a top-level extra-spec field, a
    properties/extra_specs mapping, or the human-readable properties string.
    ``None`` means the type does not declare an AZ restriction.
    """

    keys = {"reskey_availability_zones", "availability_zones"}
    candidates: list[Any] = []
    normalized = normalized_map(detail)
    for key in keys:
        if key in normalized:
            candidates.append(normalized[key])

    for container_name in ("properties", "extra_specs", "extra specs"):
        container = pick(detail, container_name, default=None)
        if isinstance(container, dict):
            nested = normalized_map(container)
            for key in keys:
                if key in nested:
                    candidates.append(nested[key])
        elif isinstance(container, str):
            match = re.search(
                r"(?:RESKEY:)?availability_zones\s*[=:]\s*['\"]?([^'\";}]+)",
                container,
                flags=re.IGNORECASE,
            )
            if match:
                candidates.append(match.group(1))

    if not candidates:
        return None

    zones: list[str] = []
    for candidate in candidates:
        for item in list_value(candidate):
            text = str(item).strip().strip("'\"")
            if text and text.lower() not in {"none", "null", "*"} and text not in zones:
                zones.append(text)
    if not zones:
        raise SuiteError(
            "The selected Cinder volume type declares RESKEY:availability_zones "
            "but does not contain any usable availability-zone names"
        )
    return frozenset(zones)


def resolve_launch_selection(
    config: Config, osc: OpenStack, logger: Any
) -> LaunchSelection:
    """Resolve and validate launch inputs without creating cloud resources."""
    if not config.image or not config.flavor or not config.storage:
        raise SuiteError("image, flavor and storage are required before VM preparation")

    image = osc.json("image", "show", config.image)
    if not image:
        raise SuiteError(f"Image not found: {config.image}")
    image_selection = config.input_sources.get("image", "operator input")
    image_id = required_text(image, "id", context="Image selection")
    image_name = optional_text(pick(image, "name", default=image_id)) or image_id
    image_min_disk, image_virtual_gib, image_required_gib = _image_disk_requirements(
        image
    )
    if config.storage == "volume" and config.volume_size < image_required_gib:
        reasons: list[str] = []
        if image_min_disk == image_required_gib and image_min_disk:
            reasons.append(f"minimum disk {image_min_disk} GiB")
        if image_virtual_gib == image_required_gib and image_virtual_gib:
            reasons.append(f"virtual size {image_virtual_gib} GiB")
        reason = " and ".join(reasons) or f"required size {image_required_gib} GiB"
        logger.log(
            f"Increasing root volume size from {config.volume_size} to {image_required_gib} GiB "
            f"to contain image {image_name} ({reason})"
        )
        config.volume_size = image_required_gib

    flavor = osc.json("flavor", "show", config.flavor)
    if not flavor:
        raise SuiteError(f"Flavor not found: {config.flavor}")
    volume_type_availability_zones: frozenset[str] | None = None
    if config.storage == "volume" and config.volume_type:
        logger.log(f"Validating requested Cinder volume type {config.volume_type}")
        volume_type = osc.json("volume", "type", "show", config.volume_type)
        if not volume_type:
            raise SuiteError(
                f"Cinder volume type not found or not visible: {config.volume_type}"
            )
        volume_type_availability_zones = _volume_type_availability_zones(volume_type)
        if volume_type_availability_zones is not None:
            logger.log(
                f"Cinder volume type {config.volume_type} is restricted to availability zones: "
                + ", ".join(sorted(volume_type_availability_zones))
            )

    flavor_id = required_text(flavor, "id", context="Flavor selection")
    flavor_name = optional_text(pick(flavor, "name", default=flavor_id)) or flavor_id
    flavor_vcpus = max(1, int(pick(flavor, "vcpus", default=1) or 1))
    flavor_ram_mb = max(
        1, int(pick(flavor, "ram", default=MIN_TEST_RAM_MB) or MIN_TEST_RAM_MB)
    )
    flavor_disk_gib = max(0, int(pick(flavor, "disk", default=0) or 0))
    if config.storage == "volume":
        config.volume_size = max(
            config.volume_size, flavor_disk_gib, image_required_gib
        )
    if (
        config.storage == "host"
        and image_required_gib > 0
        and flavor_disk_gib > 0
        and flavor_disk_gib < image_required_gib
    ):
        raise SuiteError(
            f"Flavor {flavor_name} provides {flavor_disk_gib} GiB of host root disk, "
            f"but image {image_name} requires at least {image_required_gib} GiB "
            f"(min_disk={image_min_disk} GiB, virtual_size={image_virtual_gib} GiB)"
        )

    user = config.ssh_user or _image_admin_user(image)
    if not user:
        raise SuiteError(
            f"Could not infer SSH username for image {image_name}; set the image os_admin_user metadata to its SSH account"
        )

    # Preserve the operator's selectors in execution snapshots and across full
    # suite passes. Replacing a UUID with a display name loses identity when
    # names are duplicated or renamed. LaunchSelection carries display names.
    config.ssh_user = user
    logger.log(
        f"Selected image={image_name} ({image_id}), flavor={flavor_name} ({flavor_id}), "
        f"storage={config.storage}, ssh_user={user}, "
        f"source=image:{image_selection}, flavor:{config.input_sources.get('flavor', 'operator input')}, "
        f"storage:{config.input_sources.get('storage', 'operator input')}"
    )
    return LaunchSelection(
        image_id=image_id,
        image_name=image_name,
        image_min_disk_gib=image_min_disk,
        image_virtual_size_gib=image_virtual_gib,
        image_required_disk_gib=image_required_gib,
        flavor_id=flavor_id,
        flavor_name=flavor_name,
        flavor_vcpus=flavor_vcpus,
        flavor_ram_mb=flavor_ram_mb,
        flavor_disk_gib=flavor_disk_gib,
        ssh_user=user,
        volume_type_availability_zones=volume_type_availability_zones,
    )


def validate_launch_selection_quota(
    config: Config,
    discovery: Discovery,
    plan: Plan,
    selection: LaunchSelection,
) -> None:
    peak = int(plan.estimated.get("peak_instances", 4))
    requirements = {
        "instances": peak,
        "cores": peak * selection.flavor_vcpus,
        "ram": peak * selection.flavor_ram_mb,
    }
    if config.storage == "volume":
        requirements["volumes"] = int(plan.estimated.get("peak_volumes", peak))
        requirements["gigabytes"] = (
            int(plan.estimated.get("peak_volumes", peak)) * config.volume_size
        )
    shortages: list[str] = []
    for resource, required in requirements.items():
        quota = discovery.quota_info.get(resource)
        if quota and quota.available is not None and quota.available < required:
            shortages.append(
                f"{resource}: need {required} for flavor {selection.flavor_name}, "
                f"available {quota.available}"
            )
    if shortages:
        raise SuiteError(
            "Selected flavor does not fit the available compute quota: "
            + "; ".join(shortages)
        )

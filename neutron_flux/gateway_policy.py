from __future__ import annotations

import shlex
from collections.abc import Sequence

from .errors import SuiteError

_GLOBAL_VALUE_OPTIONS = frozenset(
    {
        "--os-compute-api-version",
        "--os-volume-api-version",
        "--os-network-api-version",
        "--os-interface",
        "--os-region-name",
        "--os-cloud",
    }
)


def _starts_with(tokens: tuple[str, ...], phrase: tuple[str, ...]) -> bool:
    return tokens[: len(phrase)] == phrase


def _has_option(tokens: tuple[str, ...], option: str) -> bool:
    return any(token == option or token.startswith(f"{option}=") for token in tokens)


def _command_tokens(tokens: tuple[str, ...]) -> tuple[str, ...]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in _GLOBAL_VALUE_OPTIONS:
            index += 2
        elif any(token.startswith(f"{option}=") for option in _GLOBAL_VALUE_OPTIONS):
            index += 1
        else:
            break
    return tokens[index:]


def assert_router_gateway_defaults(args: Sequence[str]) -> None:
    """Preserve the cloud-default external-gateway behavior.

    Neutron chooses its configured gateway addresses and source-NAT default.
    Flux observes that behavior without overriding it.
    """

    tokens = tuple(str(item).strip().lower() for item in args)
    command = _command_tokens(tokens)
    prohibited = list(
        option
        for option in ("--enable-snat", "--disable-snat")
        if _has_option(tokens, option)
    )
    if _starts_with(command, ("router", "set")) and _has_option(tokens, "--fixed-ip"):
        prohibited.append("--fixed-ip")
    if not prohibited:
        return
    rendered = shlex.join(["openstack", *map(str, args)])
    raise SuiteError(
        "Flux blocked administrative external-gateway control. Test routers must "
        "use Neutron's project-member-visible defaults; prohibited option(s): "
        f"{', '.join(prohibited)}: {rendered}"
    )

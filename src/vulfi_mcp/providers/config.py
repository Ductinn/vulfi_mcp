"""Operator-supplied configuration for the external RE providers.

Everything that decides *what gets launched* and *which bytes get analysed*
lives here, and it comes from one place: a TOML file the operator wrote, found
at ``$VULFI_MCP_PROVIDER_CONFIG`` or at ``providers.toml`` under
:func:`vulfi_mcp.ida_adapter.data_dir`. No MCP argument, rule, finding or
provider response reaches this module. The only thing a caller ever supplies
is the path of the binary it wants analysed, and that path is not trusted to
name anything: it is matched against the operator's binary map and refused
when it is not in it.

This is deliberately the boring half of the provider stack. A string that
looks like an executable cannot become one, because no code path turns a
caller's string into :attr:`ProviderConfig.command`; a string that looks like a
URL cannot become an endpoint for the same reason. The loader is strict rather
than forgiving — an unreadable key, an unknown backend, a relative command, a
non-loopback endpoint or an unauthenticated one is an error at load time, when
an operator can see it, rather than a surprise during a scan.

The whole format, with every optional key shown::

    # radare2-mcp, launched here over stdio
    [r2]
    transport = "stdio"
    command = "/opt/r2mcp/r2mcp"          # absolute, existing, executable
    args = []
    stderr_log = "/var/log/vulfi/r2.log"  # default: the null device

    [r2.env]                              # merged over the SDK's inherited set
    PATH = "/opt/r2/bin:/usr/bin:/bin"
    LD_LIBRARY_PATH = "/opt/r2/lib"

    [[r2.binaries]]                       # the verified binary map; required
    local = "/srv/samples"                # a file, or a directory prefix
    remote = "/srv/samples"

    # GhidraMCP, already running, reached over authenticated loopback
    [ghidra]
    transport = "loopback"
    endpoint = "http://127.0.0.1:8192/mcp"
    token_file = "/etc/vulfi/ghidra.token"   # or token = "..."

    [[ghidra.binaries]]
    local = "/srv/samples"
    remote = "/data/samples"                 # as the provider sees it

    [ghidra.attest]                          # only needed when ``remote`` is
    tool = "get_metadata"                    # not readable on this host
    path_argument = "path"
    sha256_field = "sha256"

    [ghidra.limits]                          # every key optional
    call_timeout_seconds = 120.0             # patience for an answer over the wire
    startup_timeout_seconds = 120.0
    schema_deadline_seconds = 5.0            # local CPU bound; floor of 1.0
    max_response_bytes = 4194304
    max_response_depth = 24
    max_response_items = 256
    max_tool_pages = 16
    max_tools = 512

There is no ``tools`` key, and there never will be: which tools a backend may
be asked for is a constant in that backend's adapter, not something an
installation can widen.

``[r2.env]`` is **not** the child's whole environment. The MCP SDK launches the
child with ``get_default_environment() | (env or {})``, and on POSIX that
default carries ``HOME``, ``LOGNAME``, ``PATH``, ``SHELL``, ``TERM`` and
``USER`` through from this process. An operator can therefore override a
variable by naming it, but cannot unset one by leaving it out.

A configured ``[*.attest]`` tool is called like any other, so **it must also
appear in that backend's adapter allowlist constant**. It is not exempt: an
``attest`` naming a tool the adapter does not allow makes identity
unverifiable, and the session is refused rather than opened unchecked.
"""

from __future__ import annotations

import ipaddress
import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final, Mapping
from urllib.parse import urlsplit

from vulfi_mcp.ida_adapter import data_dir

__all__ = [
    "AttestConfig",
    "MIN_SCHEMA_DEADLINE_SECONDS",
    "CONFIG_FILENAME",
    "FORBIDDEN_TOOLS",
    "PROVIDER_BACKENDS",
    "PROVIDER_CONFIG_ENV",
    "PathMapping",
    "ProviderConfig",
    "ProviderConfigError",
    "ProviderLimits",
    "load_provider_config",
]

#: Where the operator's configuration file is, when it is not in the default
#: place. Read from this process's environment, which only the operator who
#: launched the server controls.
PROVIDER_CONFIG_ENV: Final = "VULFI_MCP_PROVIDER_CONFIG"

#: The default file name, under the already-configured data directory.
CONFIG_FILENAME: Final = "providers.toml"

#: The backends this module may configure. ``ida`` is not among them: it is
#: not reached over MCP, and a configuration that claimed to launch it would be
#: configuring something this server does not do.
PROVIDER_BACKENDS: Final[frozenset[str]] = frozenset({"ghidra", "r2"})

#: Tool names that are never callable, whatever an adapter allowlists, whatever
#: a provider advertises and whatever a provider's own text asks for. These are
#: the raw-command and scripting escapes: reaching one would hand the provider
#: arbitrary execution with this server's arguments, which is precisely the
#: thing the typed tool surface exists to prevent.
#:
#: The radare2-mcp 1.8.8 entries are read from its own tool table
#: (``src/tools.c`` 1542-1596), not guessed at, because the build gates them and
#: this list is what keeps that true for a build that does not: ``run_command``
#: and ``run_javascript`` and ``run_script`` and ``run_frida_script`` are
#: ``TOOL_MODE_EXEC``-gated, enabled by ``r2mcp -r``; ``sql`` — "Runs an SQL
#: query through the r2vsql plugin" — is **not** exec-gated at all
#: (``TOOL_MODE_NORMAL | TOOL_MODE_MINI``) and is absent here only because this
#: build lacks ``r2vsql``. Measured on the installed build: all five are absent
#: from ``tools/list`` and ``run_command`` is refused with "not available in
#: current mode", which is the provider's choice today and not a guarantee.
FORBIDDEN_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "eval",
        "execute_command",
        "execute_script",
        "run_command",
        "run_frida_script",
        "run_javascript",
        "run_script",
        "shell",
        "sql",
    }
)

#: The smallest schema-validation deadline an operator may configure. Measured,
#: not guessed: below roughly this, the bound is dominated by event-loop
#: scheduling latency rather than by validation, and starts refusing legitimate
#: schemas that cost under a millisecond of real work.
MIN_SCHEMA_DEADLINE_SECONDS: Final = 1.0

_TRANSPORTS: Final[frozenset[str]] = frozenset({"stdio", "loopback"})

_BACKEND_KEYS: Final[frozenset[str]] = frozenset(
    {
        "transport",
        "command",
        "args",
        "env",
        "stderr_log",
        "endpoint",
        "token",
        "token_file",
        "binaries",
        "limits",
        "attest",
    }
)

_LIMIT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "call_timeout_seconds",
        "schema_deadline_seconds",
        "startup_timeout_seconds",
        "max_response_bytes",
        "max_response_depth",
        "max_response_items",
        "max_tool_pages",
        "max_tools",
    }
)

_ATTEST_KEYS: Final[frozenset[str]] = frozenset(
    {"tool", "path_argument", "sha256_field"}
)

_MAPPING_KEYS: Final[frozenset[str]] = frozenset({"local", "remote"})


class ProviderConfigError(ValueError):
    """The operator's provider configuration cannot be used as written.

    ``ValueError`` because every instance describes input this module refused
    before it did anything, which is the same contract
    :class:`vulfi_mcp.catalog.CatalogError` keeps.
    """


@dataclass(frozen=True)
class ProviderLimits:
    """Every bound one provider session is held to.

    Defaults are generous enough for a real binary and small enough that a
    provider which stops making sense cannot consume this process: a reply is
    read up to :attr:`max_response_bytes`, parsed no deeper than
    :attr:`max_response_depth`, and waited for no longer than
    :attr:`call_timeout_seconds`.

    :attr:`schema_deadline_seconds` is deliberately **not** derived from
    :attr:`call_timeout_seconds`, and the two must not be coupled again. The
    call timeout is patience for a provider's answer to cross the wire; the
    schema deadline bounds local CPU in this process before anything is sent.
    Coupling them let an operator who tightened network patience silently
    tighten a CPU bound they had never reasoned about.

    It also has a floor, enforced at load, and the reason is measured: the
    deadline is awaited through ``loop.call_soon_threadsafe``, so what it really
    bounds is **validation time plus event-loop scheduling latency**. With a
    legitimate 6,806-byte schema and four busy coroutines, an effective 50 ms
    deadline refused 18 of 30 ordinary validations and 100 ms refused 19 of 30,
    against about 0.9 ms of real work. Tightening this below
    :data:`MIN_SCHEMA_DEADLINE_SECONDS` does not make the server safer, it makes
    it refuse capabilities that work.
    """

    call_timeout_seconds: float = 120.0
    startup_timeout_seconds: float = 120.0
    schema_deadline_seconds: float = 5.0
    max_response_bytes: int = 4 * 1024 * 1024
    max_response_depth: int = 24
    max_response_items: int = 256
    max_tool_pages: int = 16
    max_tools: int = 512


@dataclass(frozen=True)
class PathMapping:
    """One operator-verified pair: bytes here, the same bytes over there.

    ``local`` is a canonical path on this host and ``remote`` is where the
    provider sees the same file. When ``local`` names a directory, every file
    under it maps to the same relative place under ``remote``.
    """

    local: str
    remote: str


@dataclass(frozen=True)
class AttestConfig:
    """How to ask a provider which bytes it actually opened.

    Only needed when the mapped path is not readable on this host — when it is,
    the client hashes it directly and never takes the provider's word for it.

    ``tool`` is called through the ordinary gate, so it **must be in the
    adapter's allowlist constant**. One that is not makes identity
    unverifiable, and the session is refused.
    """

    tool: str
    path_argument: str
    sha256_field: str


@dataclass(frozen=True)
class ProviderConfig:
    """One external provider, exactly as the operator described it.

    Frozen on purpose: nothing downstream of the loader may retarget a
    provider, so a bug that tried to would raise rather than silently launch
    something else.
    """

    backend: str
    transport: str
    binaries: tuple[PathMapping, ...]
    command: str | None = None
    args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    stderr_log: str | None = None
    endpoint: str | None = None
    #: Never in ``repr``: this is a bearer credential, and a refusal message
    #: carrying it would put it wherever that message goes.
    token: str | None = field(default=None, repr=False)
    attest: AttestConfig | None = None
    limits: ProviderLimits = field(default_factory=ProviderLimits)

    def remote_path(self, local_path: str) -> str:
        """Where the provider sees ``local_path``, or :exc:`KeyError`.

        The refusal is the point. A caller names a binary; if the operator
        never mapped it, no provider is asked about it at all.
        """
        wanted = Path(local_path).expanduser().resolve()
        for mapping in self.binaries:
            local = Path(mapping.local)
            if wanted == local:
                return mapping.remote
            if local in wanted.parents:
                return str(Path(mapping.remote) / wanted.relative_to(local))
        raise KeyError(local_path)


def load_provider_config() -> dict[str, ProviderConfig]:
    """Every configured provider, keyed by backend, or an empty mapping.

    No configuration file is not an error: it means no external provider is
    available, which the routing layer reports as unavailable rather than as a
    clean zero. A file that exists and is wrong *is* an error.
    """
    path = _config_path()
    if path is None or not path.is_file():
        return {}
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError) as error:
        raise ProviderConfigError(f"{path}: cannot be read: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise ProviderConfigError(f"{path}: is not valid TOML: {error}") from error
    return {
        backend: _provider(backend, table, path)
        for backend, table in _tables(raw, path).items()
    }


def _config_path() -> Path | None:
    configured = os.environ.get(PROVIDER_CONFIG_ENV)
    if configured:
        return Path(configured).expanduser().resolve()
    return data_dir() / CONFIG_FILENAME


def _tables(raw: object, path: Path) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):  # pragma: no cover - tomllib always gives a dict
        raise ProviderConfigError(f"{path}: the top level must be a table")
    tables: dict[str, dict[str, Any]] = {}
    for name, table in raw.items():
        if name not in PROVIDER_BACKENDS:
            raise ProviderConfigError(
                f"{path}: {name!r} is not an external provider backend;"
                f" expected one of {sorted(PROVIDER_BACKENDS)}"
            )
        if not isinstance(table, dict):
            raise ProviderConfigError(f"{path}: [{name}] must be a table")
        tables[name] = table
    return tables


def _provider(backend: str, table: dict[str, Any], path: Path) -> ProviderConfig:
    where = f"{path}: [{backend}]"
    _reject_unknown(table, _BACKEND_KEYS, where)
    transport = table.get("transport")
    if transport not in _TRANSPORTS:
        raise ProviderConfigError(
            f"{where}: transport must be one of {sorted(_TRANSPORTS)},"
            f" got {transport!r}"
        )
    binaries = _binaries(table.get("binaries"), where)
    limits = _limits(table.get("limits"), where)
    attest = _attest(table.get("attest"), where)
    if transport == "stdio":
        return ProviderConfig(
            backend=backend,
            transport=transport,
            binaries=binaries,
            command=_command(table.get("command"), where),
            args=_args(table.get("args"), where),
            env=MappingProxyType(_env(table.get("env"), where)),
            stderr_log=_optional_path(table.get("stderr_log"), "stderr_log", where),
            attest=attest,
            limits=limits,
        )
    return ProviderConfig(
        backend=backend,
        transport=transport,
        binaries=binaries,
        endpoint=_endpoint(table.get("endpoint"), where),
        token=_token(table, where),
        attest=attest,
        limits=limits,
    )


def _reject_unknown(
    table: Mapping[str, Any], known: frozenset[str], where: str
) -> None:
    unknown = sorted(set(table) - known)
    if unknown:
        raise ProviderConfigError(
            f"{where}: unknown key(s) {unknown}; expected one of {sorted(known)}"
        )


def _command(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProviderConfigError(
            f"{where}: a stdio provider needs command, got {value!r}"
        )
    command = Path(value)
    if not command.is_absolute():
        raise ProviderConfigError(
            f"{where}: command must be an absolute path, got {value!r}"
        )
    # Not resolved: the operator's spelling is launched verbatim. A symlinked
    # interpreter is the usual case — a virtualenv's ``bin/python`` derives
    # its own prefix from the path it was started as, so silently following
    # the link would run a different environment than the one configured.
    # The checks above are what make that spelling safe, not a rewrite of it.
    if not command.is_file():
        raise ProviderConfigError(f"{where}: command {command} is not a file")
    if not os.access(command, os.X_OK):
        raise ProviderConfigError(f"{where}: command {command} is not executable")
    return str(command)


def _args(value: object, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ProviderConfigError(f"{where}: args must be a list of strings")
    return tuple(value)


def _env(value: object, where: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict) or not all(
        isinstance(name, str) and isinstance(item, str) for name, item in value.items()
    ):
        raise ProviderConfigError(f"{where}: env must be a table of strings")
    return dict(value)


def _endpoint(value: object, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProviderConfigError(
            f"{where}: a loopback provider needs endpoint, got {value!r}"
        )
    parts = urlsplit(value)
    if parts.scheme not in ("http", "https"):
        raise ProviderConfigError(
            f"{where}: endpoint must be http or https, got {value!r}"
        )
    host = parts.hostname or ""
    if not _is_loopback(host):
        raise ProviderConfigError(
            f"{where}: endpoint {value!r} is not on loopback; this server only"
            " talks to a provider running on this host"
        )
    return value


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _token(table: Mapping[str, Any], where: str) -> str:
    token = table.get("token")
    token_file = table.get("token_file")
    if token is not None and token_file is not None:
        raise ProviderConfigError(f"{where}: set token or token_file, not both")
    if isinstance(token_file, str) and token_file.strip():
        source = Path(token_file).expanduser()
        if not source.is_absolute():
            raise ProviderConfigError(
                f"{where}: token_file must be an absolute path, got {token_file!r}"
            )
        try:
            token = source.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise ProviderConfigError(
                f"{where}: token_file {source} cannot be read: {error}"
            ) from error
    if not isinstance(token, str) or not token.strip():
        raise ProviderConfigError(
            f"{where}: a loopback provider needs a token (or token_file); an"
            " unauthenticated endpoint is one any local process can answer"
        )
    return token


def _optional_path(value: object, key: str, where: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not Path(value).is_absolute():
        raise ProviderConfigError(
            f"{where}: {key} must be an absolute path, got {value!r}"
        )
    return value


def _binaries(value: object, where: str) -> tuple[PathMapping, ...]:
    if not isinstance(value, list) or not value:
        raise ProviderConfigError(
            f"{where}: binaries must be a non-empty array of {{local, remote}}"
            " tables; a provider with no verified binary map may not be asked"
            " about any binary at all"
        )
    mappings: list[PathMapping] = []
    for index, item in enumerate(value):
        place = f"{where}: binaries[{index}]"
        if not isinstance(item, dict):
            raise ProviderConfigError(f"{place} must be a table")
        _reject_unknown(item, _MAPPING_KEYS, place)
        local = item.get("local")
        remote = item.get("remote")
        for name, entry in (("local", local), ("remote", remote)):
            if not isinstance(entry, str) or not Path(entry).is_absolute():
                raise ProviderConfigError(
                    f"{place}: {name} must be an absolute path, got {entry!r}"
                )
        assert isinstance(local, str) and isinstance(remote, str)
        mappings.append(
            PathMapping(
                local=str(Path(local).expanduser().resolve()),
                remote=str(Path(remote)),
            )
        )
    return tuple(mappings)


def _limits(value: object, where: str) -> ProviderLimits:
    if value is None:
        return ProviderLimits()
    if not isinstance(value, dict):
        raise ProviderConfigError(f"{where}: limits must be a table")
    place = f"{where}: limits"
    _reject_unknown(value, _LIMIT_KEYS, place)
    defaults = ProviderLimits()
    numbers: dict[str, Any] = {}
    for key in ("call_timeout_seconds", "startup_timeout_seconds"):
        numbers[key] = _positive_float(
            value.get(key), key, place, getattr(defaults, key)
        )
    numbers["schema_deadline_seconds"] = _schema_deadline(
        value.get("schema_deadline_seconds"), place, defaults.schema_deadline_seconds
    )
    for key in (
        "max_response_bytes",
        "max_response_depth",
        "max_response_items",
        "max_tool_pages",
        "max_tools",
    ):
        numbers[key] = _positive_int(
            value.get(key), key, place, getattr(defaults, key)
        )
    return ProviderLimits(**numbers)


def _positive_float(value: object, key: str, where: str, fallback: float) -> float:
    if value is None:
        return fallback
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ProviderConfigError(f"{where}: {key} must be a number > 0, got {value!r}")
    return float(value)


def _schema_deadline(value: object, where: str, fallback: float) -> float:
    """The local-CPU bound, refused below its floor rather than quietly honoured.

    See :class:`ProviderLimits`: this deadline is awaited across the event loop,
    so a small value measures scheduling latency rather than validation cost and
    turns working capabilities into refusals.
    """
    seconds = _positive_float(value, "schema_deadline_seconds", where, fallback)
    if seconds < MIN_SCHEMA_DEADLINE_SECONDS:
        raise ProviderConfigError(
            f"{where}: schema_deadline_seconds must be at least"
            f" {MIN_SCHEMA_DEADLINE_SECONDS} seconds, got {seconds}; this bound is"
            " awaited across the event loop, so a smaller one measures scheduling"
            " latency rather than schema cost and refuses validations that work"
        )
    return seconds


def _positive_int(value: object, key: str, where: str, fallback: int) -> int:
    if value is None:
        return fallback
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ProviderConfigError(
            f"{where}: {key} must be an integer > 0, got {value!r}"
        )
    return value


def _attest(value: object, where: str) -> AttestConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ProviderConfigError(f"{where}: attest must be a table")
    place = f"{where}: attest"
    _reject_unknown(value, _ATTEST_KEYS, place)
    fields: dict[str, str] = {}
    for key in sorted(_ATTEST_KEYS):
        entry = value.get(key)
        if not isinstance(entry, str) or not entry.strip():
            raise ProviderConfigError(
                f"{place}: {key} must be a non-empty string, got {entry!r}"
            )
        fields[key] = entry
    if fields["tool"] in FORBIDDEN_TOOLS:
        raise ProviderConfigError(
            f"{place}: {fields['tool']!r} is never callable from this server"
        )
    return AttestConfig(**fields)

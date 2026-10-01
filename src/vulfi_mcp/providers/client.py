"""Constrained MCP sessions against an external reverse-engineering provider.

The whole of this module is one idea: a provider is a *source of facts under
suspicion*. It is launched only from operator configuration, it is asked only
for tools an adapter wrote down in advance, its answers are checked against the
schema those tools had when the adapter was written, and everything it says is
data. None of its text is ever an instruction, and none of it reaches a caller
as one.

Four gates, in the order they fire:

``identity``
    The caller's binary is hashed here, from local bytes, before a provider
    process exists. The operator's map says where that file is from the
    provider's side; if the mapped path is readable here it is hashed too, and
    a same-name different-bytes file ends the session with nothing analysed and
    nothing written. If it is not readable here, the provider must attest the
    digest itself, or the session is refused.

``allowlist``
    :func:`checked_call` will only call a tool the adapter named when it opened
    the session, and never one of :data:`~vulfi_mcp.providers.config.
    FORBIDDEN_TOOLS` — the raw-command and scripting escapes — whatever the
    adapter passed and whatever the provider advertises.

``schema``
    Each allowlisted tool is fingerprinted from the input and output schema it
    advertised. A call carries the fingerprint it was written against; when the
    two differ, or the tool is gone, *that capability* is unavailable with a
    reason, and the rest of the session keeps working. This is per capability
    on purpose: one changed tool must not take a provider's other evidence down
    with it, and must not quietly produce evidence of a different shape.

``envelope``
    A reply is text blocks and an optional structured object, nothing else,
    inside the operator's byte, item and depth budgets. Control characters are
    stripped, so a provider cannot even repaint a terminal through a reason
    string.

The session itself is an async context manager, and it releases the provider on
the way out of the ``with`` — on success, on error and on cancellation alike.
Nothing here writes to stdout or stderr: this process speaks MCP on its own
stdio, so a stray print would corrupt the protocol this server answers on. The
provider's own stderr goes to the operator's ``stderr_log`` or to the null
device, never to ours.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import threading
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from pathlib import Path
from typing import Any, Final

import jsonschema
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from vulfi_mcp.contracts import RuleEvidence
from vulfi_mcp.ida_runtime import (
    UNAVAILABLE,
    FunctionCall,
    Param,
    RuleContext,
    Unavailable,
)
from vulfi_mcp.providers.config import (
    FORBIDDEN_TOOLS,
    PROVIDER_BACKENDS,
    AttestConfig,
    ProviderConfig,
    ProviderLimits,
)

__all__ = [
    "CapabilityUnavailableError",
    "ForbiddenToolError",
    "ProviderArgumentError",
    "ProviderCallError",
    "ProviderError",
    "ProviderEvidenceError",
    "ProviderIdentityError",
    "ProviderResponseError",
    "ProviderSession",
    "ProviderUnavailableError",
    "UNCLASSIFIED_KEYWORDS",
    "checked_call",
    "provider_session",
    "rule_contexts",
    "tool_fingerprint",
]

_HEX64: Final = re.compile(r"\A[0-9a-f]{64}\Z")

#: Characters a provider may not put in anything this server keeps or reports.
#: Newline and tab survive; every other C0 control, the escape that drives a
#: terminal, and DEL do not.
_CONTROL: Final = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

_READ_CHUNK: Final = 1 << 20


class ProviderError(RuntimeError):
    """Base class for every refusal this module makes."""


class ProviderUnavailableError(ProviderError):
    """The provider could not be reached, started, or spoken to."""


class ProviderIdentityError(ProviderError):
    """The bytes the provider would analyse are not the caller's bytes.

    Raised before any analysis is requested, so a refusal leaves the provider
    untouched and the stored findings exactly as they were.
    """


class ForbiddenToolError(ProviderError):
    """A tool this server never calls, whatever asked for it."""


class CapabilityUnavailableError(ProviderError):
    """One tool is missing or no longer matches the schema it was pinned at.

    One capability, not one provider: a caller catches this, records the rule
    or pass as ``unsupported`` with :attr:`reason`, and goes on using the rest
    of the session.
    """

    def __init__(self, tool: str, reason: str) -> None:
        super().__init__(reason)
        self.tool = tool
        self.reason = reason


class ProviderArgumentError(ProviderError):
    """Arguments that do not match the tool's pinned input schema."""


class ProviderResponseError(ProviderError):
    """A reply that is too large, too deep, or not a shape this reads."""


class ProviderCallError(ProviderError):
    """The provider ran the tool and reported that it failed."""


class ProviderEvidenceError(ProviderError):
    """Provider evidence that does not consist of facts this can verify.

    This is what stops decompiled text from becoming a structural claim: a
    context may only name facts :class:`vulfi_mcp.ida_runtime.Param` and
    :class:`vulfi_mcp.ida_runtime.FunctionCall` define, with the types they
    define, and anything else — a pseudocode string, an invented predicate, a
    boolean spelled as a word — is refused rather than guessed at.
    """


def tool_fingerprint(tool: types.Tool) -> str:
    """A stable digest of one tool's *contract*, not of its prose.

    Name and schemas only. A provider that rewords a description has not
    changed what it promises; a provider that renames a required argument has,
    and that is exactly the change this must catch.
    """
    canonical = json.dumps(
        {
            "name": tool.name,
            "input_schema": tool.input_schema,
            "output_schema": tool.output_schema,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


#: JSON Schema keywords a provider's **input schema** may not contain. There
#: are two different reasons in this one set, and the second is the important
#: one:
#:
#: ``pattern``, ``patternProperties``
#:     Regular expressions, compiled and run by ``jsonschema``
#:     **synchronously, inside this process's event loop, before any call is
#:     sent** — so no ``call_timeout_seconds`` applies. A provider-supplied
#:     ``(a+)+$`` against a 29-character argument measures around twenty
#:     seconds here, and a slightly longer argument does not finish.
#:
#: ``$ref``, ``$defs``, ``definitions``, ``$dynamicRef``, ``$recursiveRef``
#:     **This half is not a blocklist and must not be read as one.** Reference
#:     resolution makes a schema's *cost* independent of its text: a flat
#:     1,620-byte schema whose ``$defs`` chain doubles at each level — using no
#:     refused keyword at all, inside every size, depth and ``check_schema``
#:     bound — did not finish validating in 300 seconds. Enumerating the
#:     expensive shapes is impossible, because the expense comes from what a
#:     pointer can *reach*, not from which words appear: a ``$ref`` into an
#:     ``enum`` member resurrects a ``pattern`` that no keyword scan would see,
#:     measured at 39.8 seconds. So the reachability itself is removed. Do not
#:     "improve" this by narrowing it back to a list of bad constructs.
#:
#: Nothing is lost by refusing any of them: the arguments this module sends are
#: adapter-authored constants, never agent input, so a provider's own schema
#: was never the thing keeping them honest; and neither installed backend emits
#: a reference — radare2-mcp 1.8.8 uses none across its 32 tools, GhidraMCP
#: 6.0.0 none across its 222. ``format`` is not here because no format checker
#: is installed, which is what makes it inert rather than a second
#: regular-expression engine.
_REFUSED_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "$defs",
        "$dynamicRef",
        "$recursiveRef",
        "$ref",
        "definitions",
        "pattern",
        "patternProperties",
    }
)


class _Capability:
    """One allowlisted tool, as this session found it.

    ``unusable`` is set at pin time, from the provider's own advertisement, and
    is the reason this tool may never be called. Keeping it here rather than
    dropping the tool means the refusal names what was wrong with it instead of
    looking like a tool the provider never offered.
    """

    __slots__ = ("fingerprint", "input_schema", "name", "unusable")

    def __init__(
        self,
        name: str,
        input_schema: dict[str, Any],
        fingerprint: str,
        unusable: str | None = None,
    ) -> None:
        self.name = name
        self.input_schema = input_schema
        self.fingerprint = fingerprint
        self.unusable = unusable


class ProviderSession:
    """One open, identity-checked conversation with one provider.

    Instances are made by :func:`provider_session` and are only valid inside
    it. Nothing here carries a provider's descriptions or instructions: an
    adapter sees tool *names* it already knew and the facts it asked for.
    """

    __slots__ = (
        "_allowlist",
        "_capabilities",
        "_client",
        "_limits",
        "backend",
        "binary_sha256",
        "capability_fingerprint",
        "remote_path",
    )

    def __init__(
        self,
        *,
        backend: str,
        binary_sha256: str,
        remote_path: str,
        capability_fingerprint: str,
        capabilities: Mapping[str, _Capability],
        allowlist: frozenset[str],
        client: ClientSession,
        limits: ProviderLimits,
    ) -> None:
        #: Which provider answered.
        self.backend = backend
        #: SHA-256 of the original binary, as read here from local bytes.
        self.binary_sha256 = binary_sha256
        #: Where the provider sees that same file.
        self.remote_path = remote_path
        #: Digest of provider identity plus every allowlisted tool's contract.
        #: A stored result produced under a different fingerprint describes a
        #: provider that no longer exists, and is not reusable.
        self.capability_fingerprint = capability_fingerprint
        self._capabilities = dict(capabilities)
        self._allowlist = allowlist
        self._client = client
        self._limits = limits

    @property
    def available_tools(self) -> frozenset[str]:
        """The allowlisted tools this provider actually offers, by name."""
        return frozenset(self._capabilities)

    def fingerprint(self, tool: str) -> str:
        """This provider's current fingerprint for ``tool``.

        Used once, by an adapter author, to write down the constant that every
        later call is checked against.
        """
        return self._capability(tool).fingerprint

    def _capability(self, tool: str) -> _Capability:
        if tool in FORBIDDEN_TOOLS:
            raise ForbiddenToolError(
                f"{tool!r} is never callable from this server, whatever the"
                f" {self.backend} provider advertises or asks for"
            )
        if tool not in self._allowlist:
            raise ForbiddenToolError(
                f"{tool!r} is not in the {self.backend} adapter's allowlist"
            )
        capability = self._capabilities.get(tool)
        if capability is None:
            raise CapabilityUnavailableError(
                tool,
                f"the {self.backend} provider no longer offers the {tool!r}"
                " tool, so everything that depends on it is unavailable",
            )
        return capability

    def __repr__(self) -> str:
        return (
            f"ProviderSession(backend={self.backend!r},"
            f" binary_sha256={self.binary_sha256!r},"
            f" remote_path={self.remote_path!r},"
            f" tools={sorted(self._capabilities)!r})"
        )


@asynccontextmanager
async def provider_session(
    config: ProviderConfig,
    original_path: str,
    *,
    allowlist: Iterable[str] = (),
) -> AsyncIterator[ProviderSession]:
    """Open one checked session against ``config`` for ``original_path``.

    ``allowlist`` is the adapter's constant set of tools; it is a keyword
    argument rather than global state so two adapters, and a test, can never
    widen each other's surface. Omitting it opens a session that may call
    nothing, which is the right default for a mistake.

    The provider is released on the way out — including when the caller is
    cancelled — and every refusal below happens before a single analysis
    request is sent.
    """
    allowed = _allowlist(allowlist)
    source = _canonical_source(original_path)
    binary_sha256 = _digest(source)
    remote = _mapped_path(config, source)
    locally_readable = _verify_local_bytes(config, source, binary_sha256, remote)
    if not locally_readable and config.attest is None:
        raise ProviderIdentityError(
            f"the {config.backend} provider's path for {source} is {remote},"
            " which cannot be read here, and this provider is not configured"
            " to attest the bytes it opens: its identity is unverifiable"
        )

    try:
        async with AsyncExitStack() as stack:
            try:
                client = await _connect(stack, config)
                initialized = await client.initialize()
                tools = await _list_tools(client, config.limits)
            except asyncio.CancelledError:
                raise
            except BaseException as error:  # noqa: BLE001 - re-raised as one type
                raise ProviderUnavailableError(
                    f"the {config.backend} provider did not open a usable"
                    f" session: {_flatten(error)}"
                ) from error
            capabilities = {
                tool.name: _pin(tool, config.limits)
                for tool in tools
                if tool.name in allowed
            }
            session = ProviderSession(
                backend=config.backend,
                binary_sha256=binary_sha256,
                remote_path=remote,
                capability_fingerprint=_capability_fingerprint(
                    config.backend, initialized, capabilities
                ),
                capabilities=capabilities,
                allowlist=allowed,
                client=client,
                limits=config.limits,
            )
            if config.attest is not None:
                await _verify_attested_bytes(session, config.attest, source)
            yield session
    except BaseExceptionGroup as group:
        # The transports below run in anyio task groups, so a single failure
        # reaches a caller wrapped in one ``ExceptionGroup`` per nested group.
        # A caller asked for one session and deserves one exception; the
        # original object is re-raised, not a copy of its message.
        raise _single(group) from None


async def checked_call(
    session: ProviderSession,
    tool: str,
    arguments: dict[str, object],
    schema_fingerprint: str,
) -> dict[str, object]:
    """Call one allowlisted tool, or say why that capability is unavailable.

    ``schema_fingerprint`` is what the adapter was written against. The result
    is a plain JSON mapping with exactly ``tool``, ``structured`` and ``text``:
    the provider's own words arrive under ``text``, as data, with control
    characters removed and the operator's budgets applied.
    """
    capability = session._capability(tool)
    if capability.fingerprint != schema_fingerprint:
        raise CapabilityUnavailableError(
            tool,
            f"the {session.backend} provider's {tool!r} tool no longer matches"
            f" the schema it was pinned at ({schema_fingerprint}); it now"
            f" fingerprints as {capability.fingerprint}, so this capability is"
            " unavailable rather than answered from a contract that changed",
        )
    if capability.unusable is not None:
        raise CapabilityUnavailableError(
            tool,
            f"the {session.backend} provider's {tool!r} tool cannot be used:"
            f" {capability.unusable}",
        )
    await _check_arguments(
        session.backend,
        capability,
        arguments,
        min(SCHEMA_DEADLINE_SECONDS, session._limits.call_timeout_seconds),
    )
    try:
        result = await session._client.call_tool(
            tool,
            arguments,
            read_timeout_seconds=session._limits.call_timeout_seconds,
        )
    except asyncio.CancelledError:
        raise
    except BaseException as error:  # noqa: BLE001 - re-raised as one type
        raise ProviderCallError(
            f"the {session.backend} provider failed to answer {tool!r}:"
            f" {_flatten(error)}"
        ) from error
    return _envelope(session, tool, result)


def rule_contexts(evidence: RuleEvidence) -> tuple[RuleContext, ...]:
    """Convert provider evidence into the contexts the shared evaluator takes.

    Every fact must be named, and named with the type
    :class:`vulfi_mcp.ida_runtime.Param` gives it. A fact that is not there
    stays :data:`~vulfi_mcp.ida_runtime.UNAVAILABLE`, so a rule that needs it
    refuses to answer instead of answering ``False`` — which is the whole
    reason a provider cannot turn "the pseudocode says ``strcpy``" into a
    finding. Anything else in the payload is a refusal, not a hint.
    """
    _check_evidence_shape(evidence)
    raw = evidence["contexts"]
    if not isinstance(raw, list):
        raise ProviderEvidenceError(
            f"contexts must be a list, got {type(raw).__name__}"
        )
    return tuple(_context(item, index) for index, item in enumerate(raw))


# -- identity ---------------------------------------------------------------


def _canonical_source(original_path: str) -> Path:
    if not isinstance(original_path, str) or not original_path.strip():
        raise ProviderIdentityError(
            f"the original binary path must be a non-empty string,"
            f" got {original_path!r}"
        )
    source = Path(original_path).expanduser().resolve()
    if not source.is_file():
        raise ProviderIdentityError(
            f"{source} is not a file, so there are no bytes to identify"
        )
    return source


def _mapped_path(config: ProviderConfig, source: Path) -> str:
    try:
        return config.remote_path(str(source))
    except KeyError:
        raise ProviderIdentityError(
            f"{source} is not in the operator-configured binary map for the"
            f" {config.backend} provider, so it is not a file this server will"
            " ask that provider about"
        ) from None


def _verify_local_bytes(
    config: ProviderConfig, source: Path, binary_sha256: str, remote: str
) -> bool:
    """Hash the mapped path here when it is readable; refuse a mismatch."""
    mapped = Path(remote)
    if not mapped.is_file():
        return False
    mapped_digest = _digest(mapped)
    if mapped_digest != binary_sha256:
        raise ProviderIdentityError(
            f"the {config.backend} provider's path for {source} is {remote},"
            f" which does not hash to the same bytes: the original is"
            f" {binary_sha256} and the mapped file is {mapped_digest}. Nothing"
            " was analysed and nothing was written."
        )
    return True


async def _verify_attested_bytes(
    session: ProviderSession, attest: AttestConfig, source: Path
) -> None:
    try:
        fingerprint = session.fingerprint(attest.tool)
    except (ForbiddenToolError, CapabilityUnavailableError) as error:
        raise ProviderIdentityError(
            f"the {session.backend} provider cannot attest {session.remote_path}:"
            f" {error}"
        ) from error
    answer = await checked_call(
        session, attest.tool, {attest.path_argument: session.remote_path}, fingerprint
    )
    structured = answer["structured"]
    claimed = (
        structured.get(attest.sha256_field) if isinstance(structured, dict) else None
    )
    if not isinstance(claimed, str) or not _HEX64.match(claimed.strip().lower()):
        raise ProviderIdentityError(
            f"the {session.backend} provider did not attest a SHA-256 for"
            f" {session.remote_path} under {attest.sha256_field!r}, so the bytes"
            " it would analyse are unverified"
        )
    if claimed.strip().lower() != session.binary_sha256:
        raise ProviderIdentityError(
            f"the {session.backend} provider attests {claimed.strip().lower()}"
            f" for {session.remote_path}, not the {session.binary_sha256} of"
            f" {source}. Nothing was analysed and nothing was written."
        )


def _digest(source: Path) -> str:
    """SHA-256 of a file, read in bounded blocks rather than all at once.

    A file that cannot be read is an identity failure, not an I/O accident:
    bytes nobody could hash are bytes nobody verified.
    """
    digest = hashlib.sha256()
    try:
        with source.open("rb") as stream:
            for block in iter(lambda: stream.read(_READ_CHUNK), b""):
                digest.update(block)
    except OSError as error:
        raise ProviderIdentityError(
            f"{source} could not be read, so its bytes are unverified: {error}"
        ) from error
    return digest.hexdigest()


# -- transport --------------------------------------------------------------


async def _connect(stack: AsyncExitStack, config: ProviderConfig) -> ClientSession:
    if config.backend not in PROVIDER_BACKENDS:  # pragma: no cover - loader checks
        raise ProviderUnavailableError(f"{config.backend!r} is not a provider backend")
    if config.transport == "stdio":
        assert config.command is not None
        errlog = stack.enter_context(
            open(config.stderr_log or os.devnull, "a", encoding="utf-8")
        )
        read, write = await stack.enter_async_context(
            stdio_client(
                StdioServerParameters(
                    command=config.command,
                    args=list(config.args),
                    env=dict(config.env),
                ),
                errlog=errlog,
            )
        )
    else:
        assert config.endpoint is not None and config.token is not None
        # Imported here, not at module scope: an installation that only runs a
        # stdio provider never pays for the HTTP and TLS stack, and the
        # credential below never exists in a process that has no endpoint.
        import httpx2

        http = await stack.enter_async_context(
            httpx2.AsyncClient(
                headers={"Authorization": f"Bearer {config.token}"},
                timeout=config.limits.call_timeout_seconds,
            )
        )
        streams = await stack.enter_async_context(
            streamable_http_client(config.endpoint, http_client=http)
        )
        read, write = streams[0], streams[1]
    return await stack.enter_async_context(
        ClientSession(
            read, write, read_timeout_seconds=config.limits.startup_timeout_seconds
        )
    )


async def _list_tools(
    client: ClientSession, limits: ProviderLimits
) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    for _ in range(limits.max_tool_pages):
        params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
        page = await client.list_tools(params=params)
        tools.extend(page.tools)
        if len(tools) > limits.max_tools:
            raise ProviderResponseError(
                f"the provider advertises more than {limits.max_tools} tools"
            )
        cursor = page.next_cursor
        if not cursor:
            return tools
    raise ProviderResponseError(
        f"the provider's tool list did not end within {limits.max_tool_pages} pages"
    )


def _pin(tool: types.Tool, limits: ProviderLimits) -> _Capability:
    """One advertised tool, with its schema vetted before anything uses it.

    The input schema is the one provider-controlled value this module *runs*
    rather than merely reads, so it is checked here, once, while the session is
    being built — not at call time, where a refusal would already have cost
    whatever the schema asked it to cost.
    """
    schema = dict(tool.input_schema) if isinstance(tool.input_schema, dict) else {}
    return _Capability(
        tool.name, schema, tool_fingerprint(tool), _unusable_schema(schema, limits)
    )


def _unusable_schema(schema: dict[str, Any], limits: ProviderLimits) -> str | None:
    """Why this tool's input schema may not be evaluated, or ``None``."""
    try:
        encoded = json.dumps(schema, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        return _quote(f"its input schema is not JSON ({error})")
    if len(encoded) > limits.max_response_bytes:
        return (
            f"its input schema is {len(encoded)} bytes, over the"
            f" {limits.max_response_bytes} byte response budget"
        )
    if _too_deep(schema, limits.max_response_depth):
        return (
            "its input schema nests deeper than the"
            f" {limits.max_response_depth} level depth budget"
        )
    found = _refused_keywords(schema)
    unclassified = [name for name in found if name in UNCLASSIFIED_KEYWORDS]
    if unclassified:
        return (
            f"its input schema uses {unclassified}, which the installed"
            " JSON Schema library evaluates but this server has not classified"
            " as a schema position; a keyword whose shape is unknown is refused"
            " rather than walked past, because what it can reach is unknown too"
        )
    if found:
        return (
            f"its input schema uses {found}, which this server will not"
            " evaluate: a provider's regular expression, and anything a"
            " provider's reference can reach, runs here, in this process,"
            " before any call is sent"
        )
    if not isinstance(schema.get("properties"), dict):
        # An empty ``properties`` table is a real answer — "this tool takes no
        # arguments" — and stays callable. No table at all means nothing says
        # which arguments exist, so the undeclared-key filter would pass
        # anything; failing closed is the only honest reading.
        return (
            "its input schema declares no properties table, so nothing says"
            " which arguments it accepts"
        )
    validator = jsonschema.validators.validator_for(schema)
    try:
        validator.check_schema(schema)
    except Exception as error:  # noqa: BLE001 - any refusal is a refusal
        return _quote(f"its input schema is not a valid JSON Schema ({error})")
    return None


#: Keywords whose value is one subschema.
_ONE_SUBSCHEMA: Final[frozenset[str]] = frozenset(
    {
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)

#: Keywords whose value is a list of subschemas. ``items`` also appears above:
#: older drafts spell a tuple of schemas that way, so both forms are walked.
_SUBSCHEMA_LIST: Final[frozenset[str]] = frozenset(
    {"allOf", "anyOf", "items", "oneOf", "prefixItems"}
)

#: Keywords whose value is a table *keyed by names the author chose*, so those
#: names are data and only the values below them are schemas. Without this, a
#: tool with an argument honestly called ``pattern`` would be refused for using
#: the ``pattern`` keyword it never used.
#:
#: ``dependencies`` is the draft-07 spelling, and its values are *either* a
#: subschema or a list of property names; the walk descends into the first and
#: steps over the second, because a list of names holds no keywords. Leaving it
#: out is how the first version of these tables reopened the very class they
#: exist to close — ``Draft4/6/7Validator`` evaluates those subschemas in full,
#: so a 200-byte draft-07 schema hid a catastrophic ``pattern`` where nothing
#: looked.
_NAMED_SUBSCHEMAS: Final[frozenset[str]] = frozenset(
    {
        "$defs",
        "definitions",
        "dependencies",
        "dependentSchemas",
        "patternProperties",
        "properties",
    }
)

#: Keywords whose value contains no subschema anywhere: assertions about the
#: instance itself. Listed so the completeness check below can tell "this
#: keyword needs no walking" from "nobody has decided what this keyword is".
_INSTANCE_KEYWORDS: Final[frozenset[str]] = frozenset(
    {
        "const",
        "dependentRequired",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "required",
        "type",
        "uniqueItems",
    }
)

#: Every keyword any installed draft actually evaluates, read from the library
#: rather than typed out here. The four tables above are a *second* blocklist,
#: and the first one failed precisely because a hand-written list went stale;
#: this is what stops that happening twice.
_SCHEMA_KEYWORDS: Final[frozenset[str]] = frozenset().union(
    *(
        frozenset(validator.VALIDATORS)
        for validator in (
            getattr(jsonschema, name, None)
            for name in (
                "Draft4Validator",
                "Draft6Validator",
                "Draft7Validator",
                "Draft201909Validator",
                "Draft202012Validator",
            )
        )
        if validator is not None
    )
)

#: Keywords a validator evaluates that this module has not placed in any of the
#: tables above — empty for the pinned ``jsonschema``, and asserted empty by the
#: suite so a library upgrade that adds one is a test failure rather than a
#: silent hole. If one ever appears at run time, a schema using it is refused:
#: not knowing a keyword's shape means not knowing what it can reach.
UNCLASSIFIED_KEYWORDS: Final[frozenset[str]] = _SCHEMA_KEYWORDS - (
    _ONE_SUBSCHEMA
    | _SUBSCHEMA_LIST
    | _NAMED_SUBSCHEMAS
    | _INSTANCE_KEYWORDS
    | _REFUSED_KEYWORDS
)


def _too_deep(value: object, limit: int) -> bool:
    """Whether ``value`` nests past ``limit``, walked without recursion.

    Iterative because the thing being measured is hostile input: a recursive
    walk would answer a deeply nested schema with ``RecursionError``, which is
    not one of this module's refusals.
    """
    stack: list[tuple[object, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        if depth > limit:
            return True
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return False


def _refused_keywords(schema: object) -> list[str]:
    """Which refused or unclassified keywords this schema actually uses.

    Only true schema positions are walked — the three tables above are the
    whole vocabulary this descends through. A dict under an unrecognised key is
    an annotation, not a subschema: a provider that tags its tools with
    ``"x-meta": {"pattern": ...}`` has not used the ``pattern`` keyword, and
    refusing it would cost a legitimate tool for nothing. A keyword a validator
    *does* evaluate but this module has not classified is reported too, because
    a position nobody has placed is a position nobody has checked.

    Iterative, for the reason :func:`_too_deep` is.
    """
    found: set[str] = set()
    wanted = _REFUSED_KEYWORDS | UNCLASSIFIED_KEYWORDS
    stack: list[object] = [schema]
    while stack:
        item = stack.pop()
        if not isinstance(item, dict):
            continue
        found |= set(item) & wanted
        for key, value in item.items():
            if key in _NAMED_SUBSCHEMAS and isinstance(value, dict):
                stack.extend(value.values())
            elif key in _SUBSCHEMA_LIST and isinstance(value, list):
                stack.extend(value)
            elif key in _ONE_SUBSCHEMA or key in _SUBSCHEMA_LIST:
                stack.append(value)
    return sorted(found)


def _capability_fingerprint(
    backend: str,
    initialized: types.InitializeResult,
    capabilities: Mapping[str, _Capability],
) -> str:
    """Identity and contract of exactly what this session may use.

    Only allowlisted tools go in, so a provider that gains an unrelated tool
    does not invalidate stored results that never depended on it, while a
    changed version, protocol or pinned schema does.
    """
    canonical = json.dumps(
        {
            "backend": backend,
            "protocol": initialized.protocol_version,
            "server": {
                "name": initialized.server_info.name,
                "version": initialized.server_info.version,
            },
            "tools": {name: item.fingerprint for name, item in capabilities.items()},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _allowlist(allowlist: Iterable[str]) -> frozenset[str]:
    if isinstance(allowlist, str):
        raise ProviderError("allowlist must be a set of tool names, not one string")
    names = frozenset(allowlist)
    if not all(isinstance(name, str) and name for name in names):
        raise ProviderError("allowlist must contain non-empty tool names")
    forbidden = sorted(names & FORBIDDEN_TOOLS)
    if forbidden:
        raise ForbiddenToolError(
            f"{forbidden} may never be allowlisted: they hand a provider"
            " arbitrary execution with this server's arguments"
        )
    return names


def _leaves(error: BaseException) -> list[BaseException]:
    """Every non-group failure inside ``error``, in order."""
    if isinstance(error, BaseExceptionGroup):
        found: list[BaseException] = []
        for child in error.exceptions:
            found.extend(_leaves(child))
        return found
    return [error]


def _single(group: BaseExceptionGroup) -> BaseException:
    """The one failure a group describes, or one that names them all."""
    leaves = _leaves(group)
    if len(leaves) == 1:
        return leaves[0]
    return ProviderUnavailableError(_flatten(group))


def _flatten(error: BaseException) -> str:
    """One line naming every leaf of a (possibly grouped) failure.

    Truncated, because the text below is the provider's: a JSON-RPC error
    ``message`` and ``data`` are whatever the provider chose to send, and these
    strings become the ``reason`` an agent is shown. Without a cap the
    operator's ``max_response_bytes`` would close the success path while the
    failure path stayed an unbounded channel.
    """
    described: list[str] = []
    for leaf in _leaves(error):
        detail = getattr(leaf, "data", None)
        described.append(
            f"{type(leaf).__name__}: {leaf}"
            + (f" ({detail})" if isinstance(detail, (str, dict, list)) else "")
        )
    return _quote(_sanitize("; ".join(described) or repr(error)))


#: How much provider-authored text any one refusal may carry. The same bound
#: the tool-failure envelope already used, applied everywhere prose from the
#: other side becomes a message this server hands onward.
MAX_REASON_CHARS: Final = 512


def _quote(text: str) -> str:
    """Provider text, bounded, with the elision made visible."""
    if len(text) <= MAX_REASON_CHARS:
        return text
    return f"{text[:MAX_REASON_CHARS]}… ({len(text)} characters, truncated)"


# -- arguments and responses ------------------------------------------------


#: Wall-clock ceiling on validating one call's arguments. Checking a handful
#: of adapter-authored scalars against a pinned schema is a matter of
#: microseconds, so anything near this bound is already pathological; it exists
#: only as the second layer behind the pin-time refusal above, for a cost shape
#: nobody has thought of yet.
SCHEMA_DEADLINE_SECONDS: Final = 5.0


async def _check_arguments(
    backend: str, capability: _Capability, arguments: dict[str, object], seconds: float
) -> None:
    """Refuse arguments the pinned schema does not accept, within a deadline.

    The cheap structural checks run here. The schema evaluation itself runs on
    a thread, because ``jsonschema`` is synchronous and a pathological schema
    would otherwise stall every other task in this process — including the
    cancellation that is supposed to rescue it.

    Two limits on that, both real and both measured:

    **A Python thread cannot be killed.** When the deadline expires this
    returns a refusal and the worker is left running. It is a daemon thread, so
    it holds up neither session teardown nor interpreter exit, and it dies with
    the process — the cost is bounded by the process, not reclaimed.

    **A thread does not bound work that holds the GIL.** ``re`` does not
    release it, so a catastrophic ``pattern`` freezes the interpreter outright
    and this deadline never gets to fire; running the suite with one proved it
    by hanging. That is exactly why ``pattern`` and reference resolution are
    refused at pin time instead of being left for a timeout to catch, and why
    this layer is a backstop rather than the defence. What it does bound is
    Python-level cost — ``uniqueItems`` over a large argument is the measured
    example — where the interpreter still switches threads.
    """
    if not isinstance(arguments, dict) or not all(
        isinstance(name, str) for name in arguments
    ):
        raise ProviderArgumentError(
            f"{capability.name}: arguments must be a mapping of string keys,"
            f" got {type(arguments).__name__}"
        )
    declared = capability.input_schema["properties"]
    undeclared = sorted(set(arguments) - set(declared))
    if undeclared:
        raise ProviderArgumentError(
            f"{capability.name}: {undeclared} is not declared by the pinned"
            f" input schema, so the {backend} provider is never sent it"
        )
    failure = await _validated(backend, capability, arguments, seconds)
    if failure is not None:
        raise failure


async def _validated(
    backend: str, capability: _Capability, arguments: dict[str, object], seconds: float
) -> ProviderError | None:
    """The refusal this schema produces, or ``None``; never raises by itself."""
    loop = asyncio.get_running_loop()
    answered: asyncio.Future[ProviderError | None] = loop.create_future()

    def settle(outcome: ProviderError | None) -> None:
        if not answered.done():
            answered.set_result(outcome)

    def work() -> None:
        outcome = _validation_failure(backend, capability, arguments)
        try:
            loop.call_soon_threadsafe(settle, outcome)
        except RuntimeError:
            # The deadline already fired, the caller already has its refusal,
            # and the loop has since closed. There is nobody left to tell, and
            # a worker that outlives its loop must not raise into the void.
            pass

    threading.Thread(
        target=work, name=f"vulfi-schema-{capability.name}", daemon=True
    ).start()
    try:
        return await asyncio.wait_for(asyncio.shield(answered), seconds)
    except (asyncio.TimeoutError, TimeoutError):
        return CapabilityUnavailableError(
            capability.name,
            f"the {backend} provider's {capability.name!r} input schema did not"
            f" finish validating one call's arguments within {seconds} seconds,"
            " so this capability is unavailable",
        )


def _validation_failure(
    backend: str, capability: _Capability, arguments: dict[str, object]
) -> ProviderError | None:
    """Run the pinned schema. Called on a worker thread; returns, never raises."""
    try:
        jsonschema.validate(instance=arguments, schema=capability.input_schema)
    except jsonschema.ValidationError as error:
        where = "/".join(str(part) for part in error.absolute_path) or capability.name
        return ProviderArgumentError(
            f"{capability.name}: argument {where!r} does not match the pinned"
            f" input schema: {_quote(error.message)}"
        )
    except BaseException as error:  # noqa: BLE001 - see below
        # Anything that is not "these arguments are wrong" is "this schema
        # cannot be evaluated", and that is the provider's defect, not ours:
        # an unresolvable ``$ref`` raises ``_WrappedReferencingError``, which
        # is not even a ``jsonschema`` public type. Letting it out would hand a
        # caller a foreign exception where the contract promises a reasoned
        # refusal it can record as unsupported.
        return CapabilityUnavailableError(
            capability.name,
            f"the {backend} provider's {capability.name!r} input schema could"
            f" not be evaluated: {_quote(f'{type(error).__name__}: {error}')}",
        )
    return None


def _envelope(
    session: ProviderSession, tool: str, result: object
) -> dict[str, object]:
    limits = session._limits
    if not isinstance(result, types.CallToolResult):
        raise ProviderResponseError(
            f"{tool}: the {session.backend} provider answered with"
            f" {type(result).__name__}, not a tool result"
        )
    budget = _Budget(limits.max_response_bytes)
    text = _text_blocks(session.backend, tool, result.content, limits, budget)
    if result.is_error:
        raise ProviderCallError(
            f"the {session.backend} provider reported {tool!r} failed:"
            f" {_quote(' '.join(text))}"
        )
    structured = result.structured_content
    if structured is not None and not isinstance(structured, dict):
        raise ProviderResponseError(
            f"{tool}: structured content must be an object,"
            f" got {type(structured).__name__}"
        )
    checked = (
        _bounded(structured, limits.max_response_depth, 0, budget, tool)
        if structured is not None
        else None
    )
    return {"tool": tool, "structured": checked, "text": text}


def _text_blocks(
    backend: str,
    tool: str,
    content: Sequence[object],
    limits: ProviderLimits,
    budget: _Budget,
) -> list[str]:
    if len(content) > limits.max_response_items:
        raise ProviderResponseError(
            f"{tool}: the {backend} provider returned {len(content)} content"
            f" blocks, over the {limits.max_response_items} block budget"
        )
    blocks: list[str] = []
    for block in content:
        if not isinstance(block, types.TextContent):
            raise ProviderResponseError(
                f"{tool}: the {backend} provider returned a"
                f" {getattr(block, 'type', type(block).__name__)!r} content"
                " block; only text is read here"
            )
        value = _sanitize(block.text)
        budget.spend(len(value.encode("utf-8", "replace")), tool)
        blocks.append(value)
    return blocks


class _Budget:
    """One response's byte allowance, spent across text and structure."""

    __slots__ = ("limit", "spent")

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.spent = 0

    def spend(self, amount: int, tool: str) -> None:
        self.spent += amount
        if self.spent > self.limit:
            raise ProviderResponseError(
                f"{tool}: the provider's answer is over the"
                f" {self.limit} byte response budget"
            )


def _bounded(
    value: object, max_depth: int, depth: int, budget: _Budget, tool: str
) -> object:
    """A JSON-native copy of ``value``, inside the depth and byte budgets."""
    if depth > max_depth:
        raise ProviderResponseError(
            f"{tool}: the provider's structured answer nests deeper than the"
            f" {max_depth} level depth budget"
        )
    if value is None or isinstance(value, (bool, int, float)):
        budget.spend(8, tool)
        return value
    if isinstance(value, str):
        cleaned = _sanitize(value)
        budget.spend(len(cleaned.encode("utf-8", "replace")), tool)
        return cleaned
    if isinstance(value, list):
        return [_bounded(item, max_depth, depth + 1, budget, tool) for item in value]
    if isinstance(value, dict):
        bounded: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProviderResponseError(
                    f"{tool}: the provider's structured answer has a"
                    f" {type(key).__name__} key; JSON objects are keyed by string"
                )
            name = _sanitize(key)
            budget.spend(len(name.encode("utf-8", "replace")), tool)
            bounded[name] = _bounded(item, max_depth, depth + 1, budget, tool)
        return bounded
    raise ProviderResponseError(
        f"{tool}: the provider's structured answer contains a"
        f" {type(value).__name__}, which is not JSON"
    )


def _sanitize(text: str) -> str:
    """Provider text, with everything that is not text taken out."""
    return _CONTROL.sub("", text)


# -- evidence ---------------------------------------------------------------

#: Every fact a provider may state about one argument, and the check that
#: decides whether what it stated is that fact. Nothing outside this table can
#: become a ``Param`` field, which is what keeps an adapter from inventing one.
_PARAM_FACTS: Final[dict[str, str]] = {
    "constant": "bool",
    "string": "str",
    "number": "number_or_none",
    "const_number": "bool",
    "size_bytes": "size",
    "indexed": "bool",
    "sign_compared": "bool",
    "nulled_after_call": "bool",
    "calls_before": "names",
    "calls_after": "names",
}

_CALL_FACTS: Final[dict[str, str]] = {
    "return_checked": "bool",
    "return_check_values": "values",
    "reachable_from_names": "names",
}

_CONTEXT_KEYS: Final[frozenset[str]] = frozenset({"params", "call"})

_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset(
    {"backend", "rule_index", "contexts", "ranges", "state", "reason"}
)

_EVIDENCE_STATES: Final[frozenset[str]] = frozenset(
    {"evaluated", "unsupported", "failed"}
)


def _check_evidence_shape(evidence: object) -> None:
    if not isinstance(evidence, dict):
        raise ProviderEvidenceError(
            f"evidence must be an object, got {type(evidence).__name__}"
        )
    missing = sorted(_EVIDENCE_KEYS - set(evidence))
    unknown = sorted(set(evidence) - _EVIDENCE_KEYS)
    if missing or unknown:
        raise ProviderEvidenceError(
            f"evidence must have exactly {sorted(_EVIDENCE_KEYS)};"
            f" missing {missing}, unknown {_quote(repr(unknown))}"
        )
    backend = evidence["backend"]
    if backend not in PROVIDER_BACKENDS and backend != "ida":
        raise ProviderEvidenceError(
            f"backend must name a backend this server knows, got"
            f" {_quote(repr(backend))}"
        )
    state = evidence["state"]
    if state not in _EVIDENCE_STATES:
        raise ProviderEvidenceError(
            f"state must be one of {sorted(_EVIDENCE_STATES)}, got"
            f" {_quote(repr(state))}"
        )
    index = evidence["rule_index"]
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ProviderEvidenceError(
            f"rule_index must be an integer >= 0, got {_quote(repr(index))}"
        )
    if not isinstance(evidence["ranges"], list):
        raise ProviderEvidenceError(
            "ranges must be a list of address ranges; a rule evaluated over an"
            " unstated part of an image is not evidence about the whole of it"
        )
    if state != "evaluated":
        reason = evidence["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise ProviderEvidenceError(
                f"a {state!r} rule must carry a reason saying what was missing"
            )
        if evidence["contexts"]:
            raise ProviderEvidenceError(
                f"a {state!r} rule has no evaluated call sites, so it may not"
                " carry contexts"
            )


def _context(raw: object, index: int) -> RuleContext:
    where = f"contexts[{index}]"
    if not isinstance(raw, dict):
        raise ProviderEvidenceError(
            f"{where} must be an object, got {type(raw).__name__}"
        )
    unknown = sorted(set(raw) - _CONTEXT_KEYS)
    if unknown:
        raise ProviderEvidenceError(
            f"{where}: {_quote(repr(unknown))} is not a verified fact; a"
            f" context carries"
            f" {sorted(_CONTEXT_KEYS)} and nothing else, so decompiled text"
            " cannot travel as evidence"
        )
    return RuleContext(
        params=_params(raw.get("params"), where),
        call=_call(raw.get("call"), where),
    )


def _params(raw: object, where: str) -> tuple[Param, ...] | Unavailable:
    if raw is None:
        return UNAVAILABLE
    if not isinstance(raw, list):
        raise ProviderEvidenceError(
            f"{where}.params must be a list of per-argument fact objects or"
            f" null, got {type(raw).__name__}; a provider that only has text"
            " has no argument facts"
        )
    return tuple(
        _param(item, f"{where}.params[{index}]") for index, item in enumerate(raw)
    )


def _param(raw: object, where: str) -> Param:
    if raw is None:
        return Param()
    if not isinstance(raw, dict):
        raise ProviderEvidenceError(
            f"{where} must be an object or null, got {type(raw).__name__}"
        )
    return Param(**_facts(raw, _PARAM_FACTS, where))


def _call(raw: object, where: str) -> FunctionCall:
    if raw is None:
        return FunctionCall()
    if not isinstance(raw, dict):
        raise ProviderEvidenceError(
            f"{where}.call must be an object or null, got {type(raw).__name__}"
        )
    return FunctionCall(**_facts(raw, _CALL_FACTS, f"{where}.call"))


def _facts(
    raw: Mapping[str, object], known: Mapping[str, str], where: str
) -> dict[str, Any]:
    unknown = sorted(set(raw) - set(known))
    if unknown:
        raise ProviderEvidenceError(
            f"{where}: {_quote(repr(unknown))} is not a fact this server can"
            " verify;"
            f" the facts a backend may state are {sorted(known)}"
        )
    return {name: _fact(name, value, known[name], where) for name, value in raw.items()}


def _fact(name: str, value: object, kind: str, where: str) -> Any:
    place = f"{where}.{name}"
    if kind == "bool":
        if not isinstance(value, bool):
            raise ProviderEvidenceError(
                f"{place} must be a boolean, got {_quote(repr(value))}; a fact a"
                " backend did not establish is left out, never guessed"
            )
        return value
    if kind == "str":
        if not isinstance(value, str):
            raise ProviderEvidenceError(
                f"{place} must be a string, got {_quote(repr(value))}"
            )
        return _sanitize(value)
    if kind == "number_or_none":
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ProviderEvidenceError(
                f"{place} must be a number or null, got {_quote(repr(value))}"
            )
        return value
    if kind == "size":
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ProviderEvidenceError(
                f"{place} must be an integer >= 0, got {_quote(repr(value))}"
            )
        return value
    if kind == "names":
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise ProviderEvidenceError(
                f"{place} must be a list of strings, got {_quote(repr(value))}"
            )
        return tuple(_sanitize(item) for item in value)
    if kind == "values":
        if not isinstance(value, list) or not all(
            not isinstance(item, bool) and isinstance(item, (int, float))
            for item in value
        ):
            raise ProviderEvidenceError(
                f"{place} must be a list of numbers, got {_quote(repr(value))}"
            )
        return tuple(value)
    raise ProviderEvidenceError(  # pragma: no cover - the tables above are closed
        f"{place}: {kind!r} is not a fact kind"
    )

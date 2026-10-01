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

The two schema gates are **not** backed by the same safety net, and the
difference decides how much the pin-time refusal has to carry:

* an **input** schema is evaluated by this module, on a worker thread, under
  ``schema_deadline_seconds``. A cost that slips past the pin becomes a
  :class:`CapabilityUnavailableError` on the deadline — unless it holds the
  GIL, which is why regular expressions are refused outright rather than timed;
* an **output** schema is evaluated by the SDK, inside
  ``ClientSession.call_tool``'s ``validate_tool_result``, on this event loop,
  **after** ``send_request`` has returned. ``read_timeout_seconds`` bounds the
  wait for the answer and not what is done with it; the operator's response
  budgets are applied by :func:`_envelope`, which runs later still. There is no
  thread, no deadline and no budget on that path, so **the pin-time refusal is
  the entire defence there** — which is why :data:`_COSTLY_KEYWORDS` exists and
  why both schemas are vetted, not just the one this module runs itself.

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
from dataclasses import dataclass
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

    How much this attests depends on the provider. GhidraMCP 6.0.0 declares an
    ``outputSchema`` on every tool, so a pin there covers the reply's declared
    shape as well. radare2-mcp 1.8.8 declares one on **none** of its 42 tools,
    measured, so a pin there attests the call and nothing about the answer —
    which is the other half of why text from that backend may not become a
    structural fact.
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


#: The schema's **own** size budget, in two dimensions, and deliberately not
#: ``max_response_bytes`` — that is a bound on one answer, and using a response
#: budget as a schema budget is what let the ninth instance of this bug through.
#:
#: The cost of a provider's schema is not a property of the schema. It is the
#: **product** of the schema's size and the size of every answer it is later run
#: against, paid once by the provider at ``tools/list`` and collected on every
#: call afterwards. A 1.06 MB schema — depth 4, no reference, no refused or
#: costly keyword, inside the old 4 MiB response budget — took 9.0 s merely to
#: *vet*, with this event loop blocked for ~99% of it, and then 20.1 s to answer
#: one call carrying **398 bytes**: about 50 ms of blocked loop per byte of
#: answer, against ~1 µs/byte for an honest schema. No word added to either
#: keyword set reaches that, because the cost belongs to no keyword.
#:
#: Both numbers are derived from the providers rather than chosen, so that a
#: later reader can see what they protect instead of rounding them. Measured
#: across every schema both installed backends advertise — radare2-mcp 1.8.8's
#: 42 input schemas and GhidraMCP 6.0.0's 222 input plus 222 output schemas,
#: 486 in all — the largest is **953 bytes** (``search_functions_enhanced``)
#: and **52 nodes** (the same one); radare2-mcp's largest is 896 bytes and 20
#: nodes. The limits below are roughly **8.6×** and **9.8×** those observed
#: maxima. If a real provider ever needs more, raise them against a fresh
#: measurement and re-measure the worst case below — do not relax them because
#: a number looks small.
#:
#: What the budget admits is the actual security property, and it is measured
#: rather than inferred. The most expensive shape these two limits allow is 245
#: ``allOf`` branches in 8,166 bytes: **67.5 ms to vet**, and **~290 µs per byte
#: of answer** at call time (115 ms for the same 398-byte answer that cost
#: 20.1 s before). That is an amplification of ~290× over an honest schema's
#: ~1 µs/byte, down from ~5×10⁴ — bounded, not eliminated. The answer dimension
#: still has no ceiling, because bounding it would mean not calling
#: ``ClientSession.call_tool``; a very large answer against a legal-but-hostile
#: schema is the residue, and it is in the report rather than hidden here.
MAX_SCHEMA_BYTES: Final = 8 * 1024

#: Nodes the schema walk may visit before it stops. Counted during the walk it
#: already performs, so it costs nothing, and checked *before* each node rather
#: than after the walk completes.
MAX_SCHEMA_NODES: Final = 512

#: Keywords refused for what they **cost**, which is a different question from
#: the one :data:`_SHARED_KINDS` answers and must stay one.
#:
#: The position classification asks *"does this keyword hold a subschema?"*.
#: This set asks *"can this keyword's evaluation cost more than the bytes it is
#: given?"*. For seven rounds this module treated the second as a consequence
#: of the first, and ``uniqueItems`` is where they part company: it holds no
#: subschema — ``instance`` is the *correct* position class for it — and
#: ``jsonschema``'s ``uniq`` still falls back to an O(n²) deep comparison
#: whenever the array's items are unorderable, which the provider chooses.
#: A 72-byte output schema measured 0.74 s on an 11 KB answer, 12.2 s on 50 KB
#: and 52.5 s on 103 KB, every call succeeding, after every budget this server
#: applies.
#:
#: Populated by measurement, not by guesswork: every keyword classified
#: ``instance``, in every dialect, swept against the worst instance a provider
#: could choose. ``uniqueItems`` was the only one whose cost is both
#: super-linear and unbounded by anything else. ``maximum`` and
#: ``exclusiveMaximum`` are super-linear in an integer's digits — 36 ms at
#: 64,000 digits, quadratic — but CPython's own ``sys.get_int_max_str_digits``
#: of 4,300 means ``json`` refuses to parse a longer one at all, capping them
#: at 0.18 ms; ``enum``, ``const``, ``required`` and the rest measured linear.
#: The sweep and those ceilings are pinned in ``tests/test_provider_security.py``
#: so the set keeps its evidence and a change of ceiling is visible.
_COSTLY_KEYWORDS: Final[frozenset[str]] = frozenset({"uniqueItems"})

#: JSON Schema keywords a provider's schema may not contain, input or output
#: alike. There are two different reasons in this one set, and the second is
#: the important one:
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
#: Nothing measurable is lost by refusing any of them, and that is an
#: availability claim, so it is measured rather than argued: **GhidraMCP 6.0.0
#: declares an output schema on all 222 of its tools and none is refused by
#: this set; radare2-mcp 1.8.8 declares none at all across its 42, and its
#: input schemas use none of these keywords either.** (The older justification
#: here — that the arguments this module sends are adapter-authored constants —
#: was about input schemas only, and stopped being the whole reason when this
#: set started governing output schemas, which are run against a provider's own
#: answer.) ``format`` is not here because no format checker is installed,
#: which is what makes it inert rather than a second regular-expression engine.
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
        session._limits.schema_deadline_seconds,
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
    """Every tool the provider advertises, following the cursor to the end.

    Paging is not optional here. radare2-mcp 1.8.8 hardcodes a page size of 32
    (``handle_list_tools``, ``src/r2mcp.c``) and advertises **42** tools over
    two pages, so a reader that takes the first page sees a different, smaller
    provider than the one it is talking to — ``hexdump`` and ``lookup_address``
    are page-two tools. Anywhere this project says "32 tools" about r2mcp, that
    is a page count.
    """
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
    """One advertised tool, with **both** its schemas vetted before anything runs.

    A tool schema is the provider-controlled value this module *runs* rather
    than merely reads, so it is checked here, once, while the session is being
    built — not at call time, where a refusal would already have cost whatever
    the schema asked it to cost.

    Both, because both are run. The input schema is evaluated by
    :func:`_check_arguments` before a call goes out; the **output** schema is
    evaluated by the SDK itself — ``ClientSession.call_tool`` calls
    ``validate_tool_result``, which compiles the provider's ``outputSchema``
    and runs it against the provider's own structured content, in this
    process's event loop, on the way back. A ``^(a+)+$`` there cost 10.5
    seconds against a five-second call timeout, needing no input schema at all.
    Vetting one and not the other was the same hole through a field nobody had
    looked at.

    ``outputSchema`` is optional, and absent is not unusable: radare2-mcp
    cannot declare one at all, so a missing field means nothing is compiled and
    nothing is refused. The two cases get different branches on purpose.
    """
    schema = dict(tool.input_schema) if isinstance(tool.input_schema, dict) else {}
    unusable = _unusable_schema(schema, limits, require_properties=True)
    if unusable is None:
        unusable = _unusable_output_schema(tool.output_schema, limits)
    return _Capability(tool.name, schema, tool_fingerprint(tool), unusable)


def _unusable_output_schema(
    schema: object, limits: ProviderLimits
) -> str | None:
    """Why this tool's declared output schema may not be run, or ``None``.

    ``None`` means *no output schema was declared*, which is the common case
    and costs nothing: the SDK compiles nothing and validates nothing. A
    declared one that is not a JSON object is a defect rather than an absence,
    and is refused rather than ignored — the SDK's own parse makes that
    unreachable over the wire today, which is a reason to keep the branch, not
    to drop it.
    """
    if schema is None:
        return None
    if not isinstance(schema, dict):
        return (
            f"it declares a {type(schema).__name__} output schema, which is not"
            " a schema at all"
        )
    return _unusable_schema(
        schema, limits, require_properties=False, what="output"
    )


def _unusable_schema(
    schema: dict[str, Any],
    limits: ProviderLimits,
    *,
    require_properties: bool,
    what: str = "input",
) -> str | None:
    """Why one of this tool's schemas may not be evaluated, or ``None``.

    ``require_properties`` is the one asymmetry: an input schema with no
    ``properties`` table says nothing about which arguments exist, and this
    module fails closed on that. An output schema makes no such promise — the
    SDK runs it against whatever the provider returned either way — so the same
    requirement there would refuse honest tools for nothing.
    """
    try:
        encoded = json.dumps(schema, ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as error:
        return _quote(f"its {what} schema is not JSON ({error})")
    if len(encoded) > MAX_SCHEMA_BYTES:
        # Checked before the walk, not after: the walk is itself linear in
        # schema size, and the version that measured a schema with a response
        # budget blocked this loop for nine seconds before deciding anything.
        return (
            f"its {what} schema is {len(encoded)} bytes, over the"
            f" {MAX_SCHEMA_BYTES} byte schema budget"
        )
    if _too_deep(schema, limits.max_response_depth):
        return (
            f"its {what} schema nests deeper than the"
            f" {limits.max_response_depth} level depth budget"
        )
    finding = _inspect_schema(schema, what)
    if finding.reason is not None:
        return finding.reason
    if finding.unclassified:
        return (
            f"its {what} schema uses {finding.unclassified}, which the"
            " installed"
            " JSON Schema library evaluates but this server has not classified"
            " as a schema position; a keyword whose shape is unknown is refused"
            " rather than walked past, because what it can reach is unknown too"
        )
    if finding.costly:
        return (
            f"its {what} schema uses {finding.costly}, whose evaluation cost"
            " this server cannot bound: measured at 12.2 s on a 50 KB answer"
            " and 52.5 s on a 103 KB one, growing with the square of what the"
            " provider sends, inside this process and after every budget this"
            " server applies"
        )
    if finding.refused:
        return (
            f"its {what} schema uses {finding.refused}, which this server will"
            " not evaluate: a provider's regular expression, and anything a"
            " provider's reference can reach, runs here, in this process,"
            " before any call is sent"
        )
    if require_properties and not isinstance(schema.get("properties"), dict):
        # An empty ``properties`` table is a real answer — "this tool takes no
        # arguments" — and stays callable. No table at all means nothing says
        # which arguments exist, so the undeclared-key filter would pass
        # anything; failing closed is the only honest reading.
        return (
            "its input schema declares no properties table, so nothing says"
            " which arguments it accepts"
        )
    try:
        validator = _validator_for(
            schema, default=jsonschema.validators._LATEST_VERSION
        )
        validator.check_schema(schema)
    except Exception as error:  # noqa: BLE001 - any refusal is a refusal
        return _quote(f"its {what} schema is not a valid JSON Schema ({error})")
    return None


class _UnusableDialect(Exception):
    """A ``$schema`` that is not a dialect name. Never leaves this module."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class _Finding:
    """What one walk of a provider's schema turned up."""

    refused: list[str]
    unclassified: list[str]
    costly: list[str]
    reason: str | None


def _validator_for(schema: object, default: type[Any]) -> type[Any]:
    """The validator class the library itself would use for ``schema``.

    Called instead of comparing ``$schema`` strings, and that is the whole
    point of this round. The previous version normalised with ``rstrip("#")``
    while :data:`_META_SCHEMAS` is a ``URIDict`` normalising with
    ``urlsplit(uri).geturl()`` — ``rstrip`` removes every trailing ``#`` and
    ``urlsplit`` only an empty fragment, so ``…/draft-04/schema##`` was
    draft-04 to the pin and 2020-12 to the evaluator, and every keyword in the
    gap between those vocabularies became a position the walk stepped over and
    the validator evaluated in full. There is no second normalisation here to
    drift, because there is no second normalisation.

    The one thing checked before handing the schema over is that a declared
    ``$schema`` is a string. The library assumes it is one and reaches for
    ``.decode`` or hashes it, so a provider-supplied ``7`` or ``[]`` comes back
    as ``AttributeError``/``TypeError`` — a raw builtin exception out of
    :func:`provider_session`, past every ``except ProviderError`` an adapter
    writes, because :func:`_pin` runs outside the guarded block. It fails
    closed, but "fails closed" is not the contract; the contract is that every
    provider defect arrives as a :class:`ProviderError` naming what was wrong.
    The guard lives here, not at the four call sites, because they all share
    this helper.
    """
    if isinstance(schema, Mapping):
        declared = schema.get("$schema", "")
        if not isinstance(declared, str):
            raise _UnusableDialect(
                f"it declares a {type(declared).__name__} $schema, which names"
                " no dialect at all"
            )
    return jsonschema.validators.validator_for(schema, default=default)


def _inspect_schema(schema: Mapping[str, Any], what: str) -> _Finding:
    """Walk a provider's schema the way the library will evaluate it.

    Two things happen per node, not once at the root, and both were bypasses
    before they did:

    * **the dialect is re-selected.** ``Validator.evolve`` calls
      ``validator_for(subschema, default=self.__class__)`` and ``descend`` goes
      through ``evolve``, so a subschema carrying its own ``$schema`` switches
      vocabulary *for that subtree*. A 153-byte schema with no root ``$schema``
      at all — the shape radare2-mcp emits — reached draft-03 that way, through
      a pin that had only ever looked at the root;
    * **the pin is applied** to whatever class that selection returns. Membership
      is tested on the class, never on a URI string.

    A nested ``$schema`` is then refused outright, as the outer belt: no tool
    schema either installed provider ships declares one anywhere — zero across
    radare2-mcp's 52 table entries and GhidraMCP's 222 tools — so the legitimate
    surface being given up is empty, while the surface being closed is every
    dialect switch anyone thinks of next.
    """
    try:
        return _walk_schema(schema, what)
    except _UnusableDialect as error:
        return _Finding([], [], [], f"its {what} schema: {error.reason}")


def _walk_schema(schema: Mapping[str, Any], what: str) -> _Finding:
    refused: set[str] = set()
    unclassified: set[str] = set()
    costly: set[str] = set()
    visited = 0
    root = _validator_for(schema, default=jsonschema.validators._LATEST_VERSION)
    if root not in SUPPORTED_DIALECTS:
        return _Finding([], [], [], _unsupported(root, schema.get("$schema"), what))
    stack: list[tuple[object, type[Any]]] = [(schema, root)]
    first = True
    while stack:
        visited += 1
        if visited > MAX_SCHEMA_NODES:
            # Stopping here rather than after the walk completes is the point:
            # the counter costs nothing because the walk visits these nodes
            # anyway, and it is what keeps a schema that is small in bytes but
            # vast in evaluated positions from being measured by running it.
            return _Finding(
                [],
                [],
                [],
                f"its {what} schema has more than {MAX_SCHEMA_NODES} nodes,"
                " over the schema budget; the cost of evaluating a schema is"
                " the product of its size and the size of every answer it is"
                " later run against, so size is bounded here rather than"
                " discovered at call time",
            )
        item, validator = stack.pop()
        if isinstance(item, list):
            stack.extend((child, validator) for child in item)
            continue
        if not isinstance(item, dict):
            continue
        # Re-selection and the pin come first, deliberately: they are the layer
        # that has to work on its own, and putting the belt in front of them
        # would hide whether it does.
        validator = _validator_for(item, default=validator)
        if validator not in SUPPORTED_DIALECTS:
            return _Finding(
                [], [], [], _unsupported(validator, item.get("$schema"), what)
            )
        if not first and "$schema" in item:
            return _Finding(
                [],
                [],
                [],
                f"a subschema of its {what} schema declares its own $schema,"
                " which switches the dialect the library evaluates that subtree"
                " with; no tool schema this server talks to has one, and one"
                " here would mean the vocabulary changes underneath the check",
            )
        first = False
        dialect = DIALECTS[validator.__name__]
        for key, value in item.items():
            if key in dialect.kinds and key in _COSTLY_KEYWORDS:
                # Asked separately from the position question below, and of
                # every keyword the dialect evaluates whatever its shape.
                costly.add(key)
                continue
            if key in _REFUSED_KEYWORDS:
                refused.add(key)
                continue
            if key in dialect.unclassified:
                unclassified.add(key)
                continue
            kind = dialect.kinds.get(key)
            if kind == "named":
                if isinstance(value, dict):
                    stack.extend((child, validator) for child in value.values())
            elif kind == "schema":
                stack.append((value, validator))
    return _Finding(sorted(refused), sorted(unclassified), sorted(costly), None)


def _unsupported(validator: type[Any], declared: object, what: str) -> str:
    """Why one dialect is refused, naming what the library resolved it to."""
    named = f" declared as {declared!r}" if declared is not None else ""
    return _quote(
        f"its {what} schema would be evaluated as {validator.__name__}{named},"
        " a dialect this server has not classified and tested; only"
        f" {sorted(item.__name__ for item in SUPPORTED_DIALECTS)} are accepted"
    )


def _refused_keywords(schema: object, dialect: _Dialect) -> list[str]:
    """The refused or unclassified keywords one dialect's vocabulary finds.

    The classification on its own, with no dialect re-selection and no pin, so
    a test can hold each layer to its own promise. :func:`_inspect_schema` is
    what production uses.
    """
    found: set[str] = set()
    stack: list[object] = [schema]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
            continue
        if not isinstance(item, dict):
            continue
        for key, value in item.items():
            if key in _REFUSED_KEYWORDS or key in dialect.unclassified:
                found.add(key)
                continue
            kind = dialect.kinds.get(key)
            if kind == "named":
                if isinstance(value, dict):
                    stack.extend(value.values())
            elif kind == "schema":
                stack.append(value)
    return sorted(found)


#: How one keyword's value is shaped, and therefore what the walk must do with
#: it. Three answers only:
#:
#: ``"schema"``
#:     the value is a subschema, or a list of them — both are descended into,
#:     and a boolean or a string there is simply skipped;
#: ``"named"``
#:     the value is a table keyed by *names the schema's author chose*, so those
#:     names are data and only the values below them are schemas. Without this,
#:     a tool with an argument honestly called ``pattern`` would be refused for
#:     a keyword it never used;
#: ``"instance"``
#:     the value is an assertion about the instance and holds no subschema.
#:
#: Shapes shared by every dialect that has the keyword. Per-dialect differences
#: go in :data:`_DIALECT_KINDS` below, and that split is the whole point of this
#: round: a keyword's shape is a property of **(dialect, keyword)**, not of the
#: name. ``type`` is the proof — an instance assertion from draft-04 onward, and
#: in draft-03 a union that may contain subschemas.
_SHARED_KINDS: Final[dict[str, str]] = {
    "$dynamicRef": "refused",
    "$recursiveRef": "refused",
    "$ref": "refused",
    "additionalItems": "schema",
    "additionalProperties": "schema",
    "allOf": "schema",
    "anyOf": "schema",
    "const": "instance",
    "contains": "schema",
    "dependencies": "named",
    "dependentRequired": "instance",
    "dependentSchemas": "named",
    "divisibleBy": "instance",
    "enum": "instance",
    "exclusiveMaximum": "instance",
    "exclusiveMinimum": "instance",
    "format": "instance",
    "if": "schema",
    "items": "schema",
    "maxItems": "instance",
    "maxLength": "instance",
    "maxProperties": "instance",
    "maximum": "instance",
    "minItems": "instance",
    "minLength": "instance",
    "minProperties": "instance",
    "minimum": "instance",
    "multipleOf": "instance",
    "not": "schema",
    "oneOf": "schema",
    "pattern": "refused",
    "patternProperties": "refused",
    "prefixItems": "schema",
    "properties": "named",
    "propertyNames": "schema",
    "required": "instance",
    "type": "instance",
    "unevaluatedItems": "schema",
    "unevaluatedProperties": "schema",
    "uniqueItems": "instance",
}

#: Keywords that are not entries in any validator's ``VALIDATORS`` table, but
#: that another keyword's implementation descends into — ``if_`` evaluates the
#: ``then`` and ``else`` siblings itself. They are added to a dialect only when
#: the keyword that reaches them is present, so the completeness check can
#: assert the tables in **both** directions: nothing missing, and nothing
#: surplus. ``contentSchema`` used to sit in the shared table and was exactly
#: that surplus-and-wrong entry nothing checked — no installed validator
#: evaluates it, so it is now an annotation, like any other key the library
#: ignores.
_COMPANION_KINDS: Final[dict[str, tuple[str, str]]] = {
    "else": ("if", "schema"),
    "then": ("if", "schema"),
}

#: Where one dialect disagrees with :data:`_SHARED_KINDS`.
#:
#: Draft-03 is the dialect that proved this table has to exist. ``extends`` and
#: ``disallow`` descend into subschemas and have no counterpart in later drafts;
#: ``type`` may be ``["null", {<subschema>}]``. A 182-byte draft-03 schema hid a
#: catastrophic ``pattern`` under ``extends`` and froze this process's event
#: loop for 5.12 seconds, because the vocabulary was keyed by name and read from
#: five hand-typed classes that did not include it.
_DIALECT_KINDS: Final[dict[str, dict[str, str]]] = {
    "Draft3Validator": {
        "disallow": "schema",
        "extends": "schema",
        "type": "schema",
    }
}


@dataclass(frozen=True)
class _Dialect:
    """One JSON Schema draft, as this module understands it.

    ``kinds`` maps each keyword the draft's validator evaluates to the shape
    this module knows it has; ``unclassified`` is the rest — the keywords the
    library will act on that nothing here has placed.
    """

    name: str
    uri: str | None
    kinds: Mapping[str, str]
    unclassified: frozenset[str]


#: Every dialect :func:`jsonschema.validators.validator_for` can hand back,
#: read from the registry **that function itself consults**. The previous
#: version derived from five hand-typed class names and so could not notice the
#: sixth, draft-03; the test re-typed the same five and could not notice it
#: either. Nothing here is typed out, so nothing here can disagree with the
#: selector.
_META_SCHEMAS: Final[Mapping[str, Any]] = jsonschema.validators._META_SCHEMAS


def _dialect(validator: Any, uri: str | None) -> _Dialect:
    """Classify one validator's whole vocabulary, keyword by keyword."""
    overrides = _DIALECT_KINDS.get(validator.__name__, {})
    kinds: dict[str, str] = {}
    unclassified: set[str] = set()
    for keyword in validator.VALIDATORS:
        kind = overrides.get(keyword, _SHARED_KINDS.get(keyword))
        if kind is None:
            unclassified.add(keyword)
        else:
            kinds[keyword] = kind
    for companion, (reached_by, kind) in _COMPANION_KINDS.items():
        if reached_by in validator.VALIDATORS:
            kinds[companion] = kind
    return _Dialect(
        name=validator.__name__,
        uri=uri,
        kinds=kinds,
        unclassified=frozenset(unclassified),
    )


#: Every dialect, by validator class name, built from the registry above. The
#: selector's fallback for a schema that names no ``$schema`` is
#: ``_LATEST_VERSION``, which the registry already carries; it is added here
#: only if some future library stops listing it.
DIALECTS: Final[dict[str, _Dialect]] = {
    validator.__name__: _dialect(validator, uri)
    for uri, validator in sorted(_META_SCHEMAS.items())
}

if jsonschema.validators._LATEST_VERSION.__name__ not in DIALECTS:  # pragma: no cover
    _latest = jsonschema.validators._LATEST_VERSION
    DIALECTS[_latest.__name__] = _dialect(_latest, None)

#: ``validator class name -> keywords it evaluates that nothing here classifies``.
#: Empty for the pinned ``jsonschema``, asserted empty by the suite, and refused
#: at run time if one ever appears: not knowing a keyword's shape means not
#: knowing what it can reach.
UNCLASSIFIED_KEYWORDS: Final[dict[str, frozenset[str]]] = {
    name: dialect.unclassified for name, dialect in DIALECTS.items()
}

#: The dialects this server has classified **and tested**, as **validator
#: classes**, resolved once through the same :data:`_META_SCHEMAS` mapping the
#: library's own selector consults. Deliberately not a set of URI strings: a
#: string comparison needs a normalisation of its own, and the one written here
#: drifted from ``urlsplit`` badly enough that ``…/draft-04/schema##`` was
#: draft-04 to the pin and 2020-12 to the evaluator. Membership is tested on
#: the class the library resolved, so there is nothing left that can disagree.
#:
#: Draft-03 is deliberately absent. It is classified correctly now, and it is
#: still refused, because this server has no reason to evaluate a dialect
#: nobody ships and every round of this review has shown that the classification
#: is the thing most likely to be wrong. Belt and braces, in that order — the
#: derivation first, so a refusal is not the only thing standing between a
#: provider and this process's event loop.
#:
#: Both installed backends emit modern schemas: measured live, none of
#: radare2-mcp 1.8.8's 42 tools declares a ``$schema`` at all, and GhidraMCP
#: 6.0.0 was cross-checked across its 222. The cost of being wrong here is a
#: provider refused with a reason naming the dialect the library resolved.
SUPPORTED_DIALECTS: Final[frozenset[type[Any]]] = frozenset(
    _META_SCHEMAS[uri]
    for uri in (
        "http://json-schema.org/draft-04/schema",
        "http://json-schema.org/draft-06/schema",
        "http://json-schema.org/draft-07/schema",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema",
    )
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
        # Selected explicitly, through the same helper the pin-time walk used,
        # rather than letting ``jsonschema.validate`` select again: a second
        # implicit selection is how this module and the evaluator came to
        # disagree about which dialect a schema was in.
        validator = _validator_for(
            capability.input_schema, default=jsonschema.validators._LATEST_VERSION
        )
        validator(capability.input_schema).validate(arguments)
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

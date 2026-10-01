"""End-to-end coverage of the public MCP entry point, over a real transport.

Every assertion here is made against a ``vulfi-mcp`` child process spoken to
the way an MCP client speaks to it: newline-delimited JSON-RPC on its stdin and
stdout. Importing the server in this process would prove nothing about the
packaged console script, the registered schemas, or a stdout that a stray log
line would corrupt, so nothing here imports :mod:`vulfi_mcp.server`.

The official MCP client SDK is not part of this environment — ``ida-mcp``
serves the protocol through ``zeromcp``, which ships a server and no client —
so the small client below speaks the stdio transport itself rather than adding
a dependency this milestone does not otherwise need.
"""

from __future__ import annotations

import itertools
import json
import os
import queue
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

import pytest

# Not the server module — nothing here imports that, on purpose. These two
# are the shared bad-pack tolerance's own predicate and the error type it
# recognises, needed because the transport flattens that error into text.
from conftest import names_the_rollback
from vulfi_mcp.ida_adapter import ManagedDatabaseError

pytestmark = pytest.mark.requires_ida

#: The transport version this client negotiates; ZeroMCP's own default.
PROTOCOL_VERSION = "2025-06-18"

#: Seconds allowed for the handshake, which only imports and answers.
HANDSHAKE_TIMEOUT = 180.0

#: Seconds allowed for one tool call. A first scan analyzes the binary into a
#: managed IDB before it evaluates a single rule, so this is minutes, not
#: seconds.
CALL_TIMEOUT = 900.0

#: Seconds allowed for the child to exit once its input is closed.
SHUTDOWN_TIMEOUT = 180.0

#: How often a call waiting for an answer checks that the child is still
#: alive. The answer almost always arrives first; what this bounds is how
#: long a child that died mid-call keeps the suite waiting.
LIVENESS_POLL = 0.5

#: The six tools the official IDA MCP registers; this entry point extends that
#: server rather than replacing it, so all six stay callable.
STOCK_TOOLS = frozenset(
    {
        "open_database",
        "execute_python",
        "reference",
        "list_databases",
        "save_database",
        "close_database",
    }
)

#: The seven tools this milestone adds.
VULFI_TOOLS = frozenset(
    {
        "vulfi_rule_template",
        "vulfi_scan",
        "vulfi_prepare",
        "vulfi_preparation",
        "vulfi_propose_recovery",
        "vulfi_findings",
        "vulfi_triage",
    }
)

#: One agent-authored rule, nested the way an agent would send it: a rule
#: object carrying a `mark_if` object whose High branch is a comprehension
#: inside `any()` with its own filter. It matches the fixture's two
#: variable-source `strcpy` calls and leaves the constant-source one alone.
NESTED_RULE: dict[str, Any] = {
    "name": "Copy From Untrusted Source",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {
        "High": "any([not param[i].is_constant() for i in range(param_count) if i > 0])",
        "Medium": "False",
        "Low": "False",
    },
}

#: An expression that would run a command if anything ever evaluated it with
#: Python. It must be refused while it is still JSON.
MALICIOUS_RULE: dict[str, Any] = {
    "name": "Escape Attempt",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {
        "High": "__import__('os').system('touch vulfi-escaped')",
        "Medium": "False",
        "Low": "False",
    },
}

SCAN_NAME = "e2e"
SCOPE = f"custom:{SCAN_NAME}"
RATIONALE = "危険: the copied bytes come from argv — assessed over MCP ✅"


def _executable() -> str:
    """The packaged ``vulfi-mcp`` console script this environment installed."""
    candidate = Path(sys.executable).parent / "vulfi-mcp"
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    found = shutil.which("vulfi-mcp")
    if found is not None:
        return found
    raise AssertionError(
        "the vulfi-mcp console script is not installed in this environment;"
        " the package declares no entry point to run"
    )


class _Server:
    """One real ``vulfi-mcp`` child, and the MCP conversation held with it."""

    def __init__(self, log_path: Path) -> None:
        self._log_path = log_path
        self._log = log_path.open("wb")
        self._process = subprocess.Popen(
            [_executable()],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self._log,
            text=True,
            encoding="utf-8",
            bufsize=1,
        )
        #: Anything the child wrote to stdout that is not a JSON-RPC message.
        #: stdout *is* the transport, so a single log line here is a defect.
        self.noise: list[str] = []
        self._messages: queue.Queue[dict[str, Any]] = queue.Queue()
        self._ids = itertools.count(1)
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()
        self._handshake()

    # -- transport ---------------------------------------------------------

    def _read(self) -> None:
        assert self._process.stdout is not None
        for line in self._process.stdout:
            text = line.strip()
            if not text:
                continue
            try:
                self._messages.put(json.loads(text))
            except json.JSONDecodeError:
                self.noise.append(text)

    def _send(self, payload: dict[str, Any]) -> None:
        assert self._process.stdin is not None
        self._process.stdin.write(json.dumps(payload) + "\n")
        self._process.stdin.flush()

    def _await(self, request_id: int, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    f"no answer to request {request_id} within {timeout}s;"
                    f" stderr:\n{self._stderr()}"
                )
            try:
                message = self._messages.get(timeout=min(remaining, LIVENESS_POLL))
            except queue.Empty:
                # A dead child never answers, and the reader thread ends at
                # EOF rather than raising, so waiting out CALL_TIMEOUT would
                # only delay the same failure by a quarter of an hour. This
                # is the one place that can notice, so it checks.
                if self._process.poll() is None:
                    continue
                answer = self._drain_after_exit(request_id)
                if answer is not None:
                    return answer
                raise AssertionError(
                    f"vulfi-mcp exited with code {self._process.returncode}"
                    f" before answering request {request_id};"
                    f" stderr:\n{self._stderr()}"
                ) from None
            # Notifications carry no id, and a concurrent answer is not ours.
            if message.get("id") == request_id:
                return message

    def _drain_after_exit(self, request_id: int) -> dict[str, Any] | None:
        """Take the answer the child managed to send before it died, if any.

        Exiting right after writing a reply is not a defect, and the reply may
        still be in flight when ``poll()`` first reports the exit, so the
        reader is joined (its loop ends at EOF) and everything it queued is
        examined before this call is declared unanswered.
        """
        self._reader.join(timeout=SHUTDOWN_TIMEOUT)
        answer: dict[str, Any] | None = None
        while True:
            try:
                message = self._messages.get_nowait()
            except queue.Empty:
                return answer
            if message.get("id") == request_id:
                answer = message

    def _stderr(self) -> str:
        self._log.flush()
        return self._log_path.read_text("utf-8", errors="replace")[-4000:]

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = HANDSHAKE_TIMEOUT,
    ) -> dict[str, Any]:
        request_id = next(self._ids)
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params
        self._send(payload)
        return self._await(request_id, timeout)

    def _handshake(self) -> None:
        answer = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "vulfi-mcp-tests", "version": "0"},
            },
        )
        assert "result" in answer, answer
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    # -- MCP -------------------------------------------------------------

    def tools(self) -> dict[str, dict[str, Any]]:
        answer = self.request("tools/list")
        assert "result" in answer, answer
        return {tool["name"]: tool for tool in answer["result"]["tools"]}

    def call(
        self,
        name: str,
        arguments: dict[str, Any],
        timeout: float = CALL_TIMEOUT,
    ) -> dict[str, Any]:
        """Call one tool and return its structured result, or fail loudly."""
        result = self._result(name, arguments, timeout)
        assert result.get("isError") is False, _text(result)
        structured = result.get("structuredContent")
        assert isinstance(structured, dict), result
        return structured

    def failure(
        self,
        name: str,
        arguments: dict[str, Any],
        timeout: float = CALL_TIMEOUT,
    ) -> str:
        """Call one tool that must be refused, and return what it said."""
        result = self._result(name, arguments, timeout)
        assert result.get("isError") is True, result
        assert "structuredContent" not in result, result
        return _text(result)

    def _result(
        self, name: str, arguments: dict[str, Any], timeout: float
    ) -> dict[str, Any]:
        answer = self.request(
            "tools/call", {"name": name, "arguments": arguments}, timeout
        )
        assert "error" not in answer, answer
        result = answer.get("result")
        assert isinstance(result, dict), answer
        return result

    def close(self) -> None:
        """Close the peer's input, which is how this server is asked to stop."""
        try:
            if self._process.stdin is not None:
                self._process.stdin.close()
            try:
                self._process.wait(timeout=SHUTDOWN_TIMEOUT)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait(timeout=SHUTDOWN_TIMEOUT)
                raise AssertionError(
                    f"vulfi-mcp did not exit on EOF; stderr:\n{self._stderr()}"
                ) from None
            self._reader.join(timeout=SHUTDOWN_TIMEOUT)
        finally:
            if self._process.stdout is not None:
                self._process.stdout.close()
            self._log.close()


def _text(result: dict[str, Any]) -> str:
    """Every text block of one tool result, joined."""
    return "\n".join(
        block.get("text", "")
        for block in result.get("content", [])
        if isinstance(block, dict)
    )


@pytest.fixture
def mcp_server(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Callable[[], _Server]]:
    """Start ``vulfi-mcp`` children that share one isolated managed workspace."""
    monkeypatch.setenv("IDA_MCP_STATE_DIR", str(tmp_path / "ida-mcp-state"))
    started: list[_Server] = []
    logs = itertools.count(1)

    def start() -> _Server:
        server = _Server(tmp_path / f"vulfi-mcp-{next(logs)}.stderr.log")
        started.append(server)
        return server

    try:
        yield start
    finally:
        for server in started:
            server.close()


def _managed_databases(data_dir: Path) -> list[Path]:
    """Every managed IDB under the workspace; a netnode can only live in one."""
    return [
        path
        for suffix in ("*.i64", "*.idb")
        for path in data_dir.rglob(suffix)
    ]


@contextmanager
def _rollback_survives_the_transport() -> Iterator[None]:
    """Give the shared bad-pack tolerance back the error MCP flattened.

    ``durable_or_reported`` tolerates a ``ManagedDatabaseError`` naming this
    server's rollback and nothing else, deliberately, so that an ordinary
    failed assertion always propagates. Over MCP that error never arrives as
    an exception: the server answers ``isError: true`` with the message as
    text, and :meth:`_Server.call` turns that into an ``AssertionError``. This
    is the one place that knows the transport did that, so it is the one place
    that undoes it — and only for an assertion whose message *is* the rollback
    report, checked with the tolerance's own predicate rather than a second
    copy of the wording. A wrong status, a lost row or a missing key raises
    the plain ``AssertionError`` it always did.
    """
    try:
        yield
    except AssertionError as flattened:
        reported = ManagedDatabaseError(str(flattened))
        if not names_the_rollback(reported):
            raise
        raise reported from flattened


def _violations(schema: dict[str, Any], value: Any, where: str = "$") -> list[str]:
    """Every way ``value`` fails ``schema``, in the subset ZeroMCP publishes.

    The MCP client SDK is not in this environment and neither is a JSON Schema
    library, so this checks exactly the keywords the server's generator can
    emit — ``type``, ``properties``, ``required``, ``additionalProperties``,
    ``items``, ``anyOf`` and the empty schema — and refuses to guess at any
    other, so a keyword it has never seen fails loudly instead of passing.
    """
    if "anyOf" in schema:
        if any(not _violations(option, value, where) for option in schema["anyOf"]):
            return []
        return [f"{where}: {value!r} matches no branch of {schema['anyOf']}"]
    unknown = set(schema) - {
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "description",
        "default",
        "title",
    }
    assert not unknown, f"{where}: unhandled JSON Schema keywords {sorted(unknown)}"
    expected = schema.get("type")
    if expected is None:
        return []
    if not _has_type(expected, value):
        return [f"{where}: schema says {expected}, payload has {value!r}"]
    problems: list[str] = []
    if expected == "object":
        properties = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for key in schema.get("required", []):
            if key not in value:
                problems.append(f"{where}: required property {key!r} is missing")
        for key, item in value.items():
            if key in properties:
                problems += _violations(properties[key], item, f"{where}.{key}")
            elif extra is False:
                problems.append(f"{where}: property {key!r} is not allowed")
            elif isinstance(extra, dict):
                problems += _violations(extra, item, f"{where}.{key}")
    elif expected == "array" and "items" in schema:
        for index, item in enumerate(value):
            problems += _violations(schema["items"], item, f"{where}[{index}]")
    return problems


def _has_type(expected: str, value: Any) -> bool:
    """JSON Schema type test, with JSON's own booleans-are-not-integers rule."""
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "string":
        return isinstance(value, str)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    if expected == "null":
        return value is None
    raise AssertionError(f"unhandled JSON Schema type {expected!r}")


def test_stdio_scan_then_triage_survives_restart(
    compiled_calls: Path,
    managed_data_dir: Path,
    mcp_server: Callable[[], _Server],
    durable_or_reported: Callable[[], AbstractContextManager[list[str]]],
) -> None:
    # Two spare-backed packs and two reopens, one of them across a restart:
    # the exposure to IDA 9.4's bad-pack defect that `durable_or_reported`
    # exists for. Every assertion below is unchanged by the tolerance — it
    # accepts only this server reporting its own rollback, and then only
    # after re-reading the managed database to prove no row came back half
    # written.
    with durable_or_reported() as produced, _rollback_survives_the_transport():
        try:
            _scan_triage_and_restart(compiled_calls, mcp_server)
        finally:
            produced.extend(str(path) for path in _managed_databases(managed_data_dir))


def _scan_triage_and_restart(
    compiled_calls: Path, mcp_server: Callable[[], _Server]
) -> None:
    server = mcp_server()

    # Throwaway discovery check: this entry point extends the official server,
    # so its six tools answer beside the seven added here.
    listed = server.tools()
    assert STOCK_TOOLS | VULFI_TOOLS <= set(listed)
    assert len(listed) == 13, sorted(listed)

    template = server.call("vulfi_rule_template", {}, timeout=HANDSHAKE_TIMEOUT)
    assert "rule_schema" in template
    assert template["expression_language"]["builtins"] == ["any", "len", "range"]

    scan = server.call(
        "vulfi_scan",
        {
            "path": str(compiled_calls),
            "rules": [NESTED_RULE],
            "scan_name": SCAN_NAME,
        },
    )
    assert scan["scope"] == SCOPE
    assert scan["backend"] == "ida"
    assert scan["coverage"] == "complete"
    assert scan["rule_coverage"] == [
        {"rule_index": 0, "backend": "ida", "state": "evaluated", "reason": None}
    ]

    findings = scan["findings"]
    assert [row["found_in"] for row in findings] == [
        "copy_from_argument",
        "copy_from_environment",
    ], findings
    assert len({row["id"] for row in findings}) == 2
    assert len({row["address"] for row in findings}) == 2
    assert [row["priority"] for row in findings] == ["High", "High"]
    assert [row["status"] for row in findings] == ["Not Checked", "Not Checked"]
    assert scan["scope_total"] == 2
    assert scan["status_counts"]["aggregate"]["Not Checked"] == 2

    assessed, untouched = findings
    triage = server.call(
        "vulfi_triage",
        {
            "path": str(compiled_calls),
            "finding_id": assessed["id"],
            "status": "Vulnerable",
            "rationale": RATIONALE,
        },
    )
    assert triage["finding"]["id"] == assessed["id"]
    assert triage["finding"]["status"] == "Vulnerable"
    assert triage["finding"]["rationale"] == RATIONALE
    assert triage["finding"]["assessed_at"]
    assert triage["triage_revision"] == 1
    assert triage["status_counts"]["aggregate"]["Vulnerable"] == 1

    assert server.noise == [], "stdout is the MCP transport and carries no logs"
    server.close()

    # A second process, sharing only what the first one wrote to disk.
    restarted = mcp_server()
    page = restarted.call(
        "vulfi_findings", {"path": str(compiled_calls)}, timeout=HANDSHAKE_TIMEOUT
    )
    assert page["target_total"] == 2
    assert page["offset"] == 0
    assert page["limit"] == 100
    stored = {row["id"]: row for row in page["findings"]}
    assert set(stored) == {assessed["id"], untouched["id"]}
    assert stored[assessed["id"]]["status"] == "Vulnerable"
    assert stored[assessed["id"]]["rationale"] == RATIONALE
    assert stored[assessed["id"]]["triage_revision"] == 1
    assert stored[untouched["id"]]["status"] == "Not Checked"
    assert stored[untouched["id"]]["rationale"] == ""
    assert page["status_counts"]["aggregate"] == {
        "Not Checked": 1,
        "False Positive": 0,
        "Suspicious": 0,
        "Vulnerable": 1,
    }
    assert restarted.noise == []


def test_invalid_custom_rule_or_scan_name_leaves_no_idb(
    compiled_calls: Path, managed_data_dir: Path, mcp_server: Callable[[], _Server]
) -> None:
    server = mcp_server()
    escaped = Path.cwd() / "vulfi-escaped"

    malicious = server.failure(
        "vulfi_scan",
        {
            "path": str(compiled_calls),
            "rules": [NESTED_RULE, MALICIOUS_RULE],
            "scan_name": SCAN_NAME,
        },
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "rules[1]" in malicious
    assert "mark_if['High']" in malicious
    assert not escaped.exists(), "a rejected rule ran its own expression"

    named = server.failure(
        "vulfi_scan",
        {
            "path": str(compiled_calls),
            "rules": [NESTED_RULE],
            "scan_name": "e2e: drop",
        },
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "scan_name" in named
    assert "'e2e: drop'" in named

    empty = server.failure(
        "vulfi_scan",
        {"path": str(compiled_calls), "rules": [], "scan_name": SCAN_NAME},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "rules" in empty

    assert _managed_databases(managed_data_dir) == []
    assert server.noise == []


def test_unimplemented_capabilities_are_refused_not_answered_empty(
    compiled_calls: Path, managed_data_dir: Path, mcp_server: Callable[[], _Server]
) -> None:
    server = mcp_server()

    for tool_name in ("vulfi_scan", "vulfi_prepare"):
        for name in ("ghidra", "r2"):
            refused = server.failure(
                tool_name,
                {"path": str(compiled_calls), "backend": name},
                timeout=HANDSHAKE_TIMEOUT,
            )
            assert name in refused
            assert "'ida'" in refused and "'auto'" in refused
            # The claim that matters: nothing quietly answered for it.
            assert "fell back" in refused

    unprepared = server.failure(
        "vulfi_scan",
        {"path": str(compiled_calls), "analysis_id": "prep-1"},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "analysis_id" in unprepared
    assert "'prep-1'" in unprepared
    assert "nothing was scanned" in unprepared

    unknown_pass = server.failure(
        "vulfi_prepare",
        {"path": str(compiled_calls), "passes": ["decompile_everything"]},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "decompile_everything" in unknown_pass

    aggregated = server.failure(
        "vulfi_findings",
        {"path": str(compiled_calls), "binary_path": str(compiled_calls)},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "binary_path" in aggregated

    assert _managed_databases(managed_data_dir) == []
    assert server.noise == []


def test_every_successful_result_validates_against_its_advertised_schema(
    compiled_calls: Path,
    managed_data_dir: Path,
    mcp_server: Callable[[], _Server],
    durable_or_reported: Callable[[], AbstractContextManager[list[str]]],
) -> None:
    """A client that validates structured output accepts all seven tools.

    MCP 2025-06-18 says a client SHOULD validate a tool result's
    ``structuredContent`` against the ``outputSchema`` that tool advertises, so
    a schema the tool's own payload violates makes every successful call a
    failed one. This takes the schemas the running server publishes — not a
    copy written here — and checks a real successful payload from each of the
    seven VulFi tools against its own.
    """
    with durable_or_reported() as produced, _rollback_survives_the_transport():
        try:
            _validate_every_vulfi_payload(compiled_calls, mcp_server)
        finally:
            produced.extend(str(path) for path in _managed_databases(managed_data_dir))


def _validate_every_vulfi_payload(
    compiled_calls: Path, mcp_server: Callable[[], _Server]
) -> None:
    server = mcp_server()
    advertised = {
        name: listing.get("outputSchema")
        for name, listing in server.tools().items()
    }
    target = {"path": str(compiled_calls)}

    payloads: dict[str, dict[str, Any]] = {}
    payloads["vulfi_rule_template"] = server.call(
        "vulfi_rule_template", {}, timeout=HANDSHAKE_TIMEOUT
    )
    prepared = server.call("vulfi_prepare", target)
    # A payload with no candidates and no passes would not exercise the
    # nested `Candidate` and `PassResult` schemas, which is where this
    # result's flattened value types live.
    assert prepared["candidates"], prepared
    assert prepared["passes"], prepared
    payloads["vulfi_prepare"] = prepared
    scan = server.call(
        "vulfi_scan", {**target, "rules": [NESTED_RULE], "scan_name": SCAN_NAME}
    )
    payloads["vulfi_scan"] = scan
    # A payload with no rows would not exercise the nested `Finding` schema at
    # all, and `Finding` is where the flattened value types live.
    assert scan["findings"], scan
    payloads["vulfi_triage"] = server.call(
        "vulfi_triage",
        {
            **target,
            "finding_id": scan["findings"][0]["id"],
            "status": "Suspicious",
            "rationale": RATIONALE,
        },
    )
    page = server.call("vulfi_findings", target, timeout=HANDSHAKE_TIMEOUT)
    assert page["findings"], page
    payloads["vulfi_findings"] = page
    recovered = server.call("vulfi_preparation", target, timeout=HANDSHAKE_TIMEOUT)
    assert recovered["candidates"], recovered
    payloads["vulfi_preparation"] = recovered
    # One proposal against a candidate this preparation really recorded, so
    # the nested submission schema is exercised by a row and not by an empty
    # list. Whether the proposal is *accepted* is the proposal tests' subject;
    # what this file checks is that the payload matches the published schema
    # either way.
    about = next(
        row
        for row in prepared["candidates"]
        if row["state"] == "candidate" and row["address"] is not None
    )
    proposed = server.call(
        "vulfi_propose_recovery",
        {
            **target,
            "analysis_id": prepared["analysis_id"],
            "proposals": [
                {
                    "candidate_id": about["candidate_id"],
                    "kind": "name",
                    "address_space": about["address_space"],
                    "address": about["address"],
                    "value": {"name": "vulfi_schema_probe"},
                    "evidence": {"segment": about["evidence"]["segment"]},
                    "rationale": "a name for the candidate this schema check uses",
                }
            ],
        },
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert len(proposed["proposals"]) == 1, proposed
    assert proposed["applied"] is False
    payloads["vulfi_propose_recovery"] = proposed

    for name in sorted(VULFI_TOOLS):
        schema = advertised[name]
        assert isinstance(schema, dict), f"{name} advertises no outputSchema"
        broken = "\n".join(_violations(schema, payloads[name]))
        assert not broken, f"{name} result violates its own outputSchema:\n{broken}"

    assert server.noise == []

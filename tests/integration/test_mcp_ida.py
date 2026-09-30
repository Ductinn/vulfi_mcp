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
from pathlib import Path
from typing import Any

import pytest

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

#: The four tools this milestone adds.
VULFI_TOOLS = frozenset(
    {
        "vulfi_rule_template",
        "vulfi_scan",
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
                message = self._messages.get(timeout=remaining)
            except queue.Empty:
                continue
            # Notifications carry no id, and a concurrent answer is not ours.
            if message.get("id") == request_id:
                return message

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


def test_stdio_scan_then_triage_survives_restart(
    compiled_calls: Path, managed_data_dir: Path, mcp_server: Callable[[], _Server]
) -> None:
    server = mcp_server()

    # Throwaway discovery check: this entry point extends the official server,
    # so its six tools answer beside the four added here.
    listed = server.tools()
    assert STOCK_TOOLS | VULFI_TOOLS <= set(listed)
    assert len(listed) == 10, sorted(listed)

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

    backend = server.failure(
        "vulfi_scan",
        {"path": str(compiled_calls), "backend": "ghidra"},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "ghidra" in backend
    assert "'ida'" in backend and "'auto'" in backend

    prepared = server.failure(
        "vulfi_scan",
        {"path": str(compiled_calls), "analysis_id": "prep-1"},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "analysis_id" in prepared
    assert "preparation" in prepared

    aggregated = server.failure(
        "vulfi_findings",
        {"path": str(compiled_calls), "binary_path": str(compiled_calls)},
        timeout=HANDSHAKE_TIMEOUT,
    )
    assert "binary_path" in aggregated

    assert _managed_databases(managed_data_dir) == []
    assert server.noise == []


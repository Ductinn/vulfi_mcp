"""The TUI already collected the decision. The CLI must not ask stdin again.

``pi.exec`` ignores stdin. A flag carries the token the operator confirmed.
Without that flag, a closed or disagreeing stdin still aborts and writes
nothing. The flag is not an MCP tool.
"""

from __future__ import annotations

import io

import pytest

from vulfi_mcp import operator


def _briefing() -> dict:
    return {
        "path": "/tmp/target",
        "idb_path": "/tmp/target.i64",
        "backend": "ida",
        "artifact_revision": 3,
        "proposal": {
            "proposal_id": "prop-1",
            "kind": "name",
            "state": "pending",
            "analysis_id": "an",
            "candidate_id": "cand-1",
            "address": 0x1000,
            "value": {"name": "checked"},
            "rationale": "rename",
            "evidence": {"bytes": "90"},
        },
        "candidate": None,
        "site": {},
        "conflicts": [],
        "effect": "set the name",
        "reviewable": True,
        "reason": None,
    }


def _link_briefing() -> dict:
    return {
        "ida": {"id": "ida-1", "address_space": "image", "address": "0x401000"},
        "external": {"id": "ext-1", "address_space": "image", "address": "0x401000"},
        "proof": {
            "ida_image_base": "0x400000",
            "external_image_base": "0x400000",
            "rva": "0x1000",
            "bytes": "90",
            "xrefs": {},
        },
    }


class _Catalog:
    def link(self, link_id: str) -> dict:
        return {
            "link_id": link_id,
            "ida_finding_id": "ida-1",
            "external_finding_id": "ext-1",
            "sync_state": "conflict",
        }

    def close(self) -> None:
        return None


def test_review_confirmed_flag_does_not_also_read_stdin(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    applied: list[str] = []

    monkeypatch.setattr(operator, "proposal_briefing", lambda *_args: _briefing())
    monkeypatch.setattr(
        operator,
        "review_proposal",
        lambda *_args, **_kwargs: applied.append("approve")
        or {
            "confirmed": True,
            "decision": "approve",
            "proposal_id": "prop-1",
            "state": "approved",
            "applied": True,
            "expected_revision": 3,
            "artifact_revision": 4,
            "approved_revision": 4,
            "decided_by": "tester",
            "reason": None,
            "reconciliation": None,
        },
    )
    monkeypatch.setattr(sys_stdin(), "stdin", io.StringIO(""))
    assert (
        operator.main(
            [
                "approve",
                "--path",
                "/tmp/target",
                "--proposal-id",
                "prop-1",
                "--expected-revision",
                "3",
            ]
        )
        == 1
    )
    assert applied == []


    monkeypatch.setattr(sys_stdin(), "stdin", io.StringIO("nope\n"))
    assert (
        operator.main(
            [
                "approve",
                "--path",
                "/tmp/target",
                "--proposal-id",
                "prop-1",
                "--expected-revision",
                "3",
                "--confirmed",
                "approve",
            ]
        )
        == 0
    )
    assert applied == ["approve"]
    assert "Proposal prop-1" in capsys.readouterr().out


def test_link_and_resolve_confirmed_flag_skips_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    applied: list[str] = []
    monkeypatch.setattr(operator, "link_briefing", lambda *_args: _link_briefing())
    monkeypatch.setattr(
        operator,
        "review_link",
        lambda *_args: applied.append("link") or {"confirmed": True, "link_id": "L1"},
    )
    monkeypatch.setattr(
        operator,
        "resolve_link",
        lambda *_args: applied.append("resolve") or {"confirmed": True, "link_id": "L1"},
    )
    monkeypatch.setattr(operator, "open_catalog", lambda *_args, **_kwargs: _Catalog())

    monkeypatch.setattr(sys_stdin(), "stdin", io.StringIO(""))
    assert (
        operator.link_main(
            [
                "--path",
                "/tmp/target",
                "--ida-id",
                "ida-1",
                "--external-id",
                "ext-1",
                "--binary",
                "/tmp/target",
                "--source",
                "ida",
                "--status",
                "Vulnerable",
                "--rationale",
                "kept",
            ]
        )
        == 1
    )
    assert applied == []

    monkeypatch.setattr(sys_stdin(), "stdin", io.StringIO("nope\n"))
    assert (
        operator.link_main(
            [
                "--path",
                "/tmp/target",
                "--ida-id",
                "ida-1",
                "--external-id",
                "ext-1",
                "--binary",
                "/tmp/target",
                "--source",
                "ida",
                "--status",
                "Vulnerable",
                "--rationale",
                "kept",
                "--confirmed",
                "ida",
            ]
        )
        == 0
    )
    assert applied == ["link"]

    monkeypatch.setattr(sys_stdin(), "stdin", io.StringIO("nope\n"))
    assert (
        operator.resolve_main(
            [
                "--path",
                "/tmp/target",
                "--link-id",
                "L1",
                "--source",
                "external",
                "--status",
                "Suspicious",
                "--rationale",
                "conflict",
                "--confirmed",
                "external",
            ]
        )
        == 0
    )
    assert applied == ["link", "resolve"]


def test_briefing_flag_prints_mapping_evidence_and_does_not_write(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--briefing`` is the read-only path. It must not confirm a link.

    The production change that must fail this test is treating ``--briefing``
    as an unknown flag, or printing the evidence only after ``review_link``.
    """
    applied: list[str] = []
    monkeypatch.setattr(operator, "link_briefing", lambda *_args: _link_briefing())
    monkeypatch.setattr(
        operator,
        "review_link",
        lambda *_args: applied.append("link") or {"confirmed": True, "link_id": "L1"},
    )
    monkeypatch.setattr(
        operator,
        "resolve_link",
        lambda *_args: applied.append("resolve") or {"confirmed": True, "link_id": "L1"},
    )
    monkeypatch.setattr(operator, "open_catalog", lambda *_args, **_kwargs: _Catalog())
    assert (
        operator.link_main(
            [
                "--path",
                "/tmp/target",
                "--ida-id",
                "ida-1",
                "--external-id",
                "ext-1",
                "--binary",
                "/tmp/target",
                "--source",
                "ida",
                "--status",
                "Vulnerable",
                "--rationale",
                "kept",
                "--briefing",
                "--confirmed",
                "ida",
            ]
        )
        == 0
    )
    shown = capsys.readouterr().out.lower()
    assert "image base" in shown
    assert "rva" in shown
    assert "bytes" in shown
    assert "xref" in shown
    assert applied == []

    refused = _link_briefing()
    refused["reason"] = "the machine already rejected this pair"
    monkeypatch.setattr(operator, "link_briefing", lambda *_args: refused)
    assert (
        operator.resolve_main(
            [
                "--path",
                "/tmp/target",
                "--link-id",
                "L1",
                "--source",
                "external",
                "--status",
                "Suspicious",
                "--rationale",
                "conflict",
                "--briefing",
            ]
        )
        == 1
    )
    assert "rejected" in capsys.readouterr().out.lower()
    assert applied == []



def sys_stdin():
    import sys

    return sys

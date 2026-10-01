"""Reading a target nothing has scanned, without analyzing it into existence.

The rows a read answers from live in the target's managed IDA database, and
only ``vulfi_scan`` makes one. These tests run on an ordinary contributor
machine precisely because a read that needs IDA is the defect: every call below
would, if a read still created its database, either analyze a file in full or
fail for want of a licensed IDA. What they assert instead is that nothing is
created, nothing is opened, and the absent store is reported as absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from vulfi_mcp.ida_adapter import NO_DATABASE_REASON, existing_managed_idb
from vulfi_mcp.ida_runtime import UnknownFindingError
from vulfi_mcp.server import vulfi_findings, vulfi_triage

#: An id of exactly the shape `vulfi_scan` issues. Nothing stores it, and with
#: no database nothing could.
FINDING_ID = "ida:default:0:0123456789abcdef:file:0x401000:0"


@pytest.fixture
def never_scanned(tmp_path: Path) -> Path:
    """A real file this suite has never pointed a scan at."""
    target = tmp_path / "never-scanned.bin"
    target.write_bytes(b"\x7fELF" + b"not an analysis" * 16)
    return target


def _workspace_contents(data_dir: Path) -> list[str]:
    return sorted(str(entry.relative_to(data_dir)) for entry in data_dir.rglob("*"))


def test_paging_a_target_that_was_never_scanned_creates_nothing(
    never_scanned: Path, managed_data_dir: Path
) -> None:
    assert existing_managed_idb(str(never_scanned)) is None

    page = vulfi_findings(str(never_scanned))

    # The invariant the whole contract exists for: unavailable, with a reason,
    # never an empty store.
    health = page["store_health"]["ida"]
    assert health["available"] is False
    assert health["reason"] == NO_DATABASE_REASON
    # No counts at all: a store that is not there has no zero to report.
    assert "record_digest" not in health
    assert "scopes" not in health

    assert page["findings"] == []
    assert page["page_total"] == 0
    assert page["target_total"] == 0
    assert page["target_total_complete"] is False
    assert page["stale_total"] == 0
    assert page["status_counts"] == {}
    assert page["path"] == str(never_scanned)
    assert page["idb_path"] == ""
    assert NO_DATABASE_REASON in page["warnings"]

    assert _workspace_contents(managed_data_dir) == []


def test_assessing_a_target_that_was_never_scanned_creates_nothing(
    never_scanned: Path, managed_data_dir: Path
) -> None:
    with pytest.raises(Exception) as refusal:
        vulfi_triage(
            str(never_scanned),
            FINDING_ID,
            "Vulnerable",
            "an assessment of a finding no store holds",
        )

    # The transport flattens the refusal into its own error type; what the
    # server raised is still the ordinary unknown-id refusal.
    reported = refusal.value
    cause = reported.__cause__
    assert isinstance(cause, UnknownFindingError), reported
    assert FINDING_ID in str(cause)
    assert NO_DATABASE_REASON in str(cause)

    assert _workspace_contents(managed_data_dir) == []


def test_a_page_window_is_still_refused_before_the_workspace_is_consulted(
    never_scanned: Path, managed_data_dir: Path
) -> None:
    with pytest.raises(Exception, match="limit"):
        vulfi_findings(str(never_scanned), limit=0)
    with pytest.raises(Exception, match="offset"):
        vulfi_findings(str(never_scanned), offset=-1)

    assert _workspace_contents(managed_data_dir) == []


def test_a_target_that_is_not_a_file_is_refused_not_answered_empty(
    tmp_path: Path, managed_data_dir: Path
) -> None:
    # An absent store and an absent target are different answers: the first is
    # a page, the second is an error.
    with pytest.raises(Exception, match="no such binary or IDA database"):
        vulfi_findings(str(tmp_path / "not-here.bin"))

    assert _workspace_contents(managed_data_dir) == []

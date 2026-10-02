"""The public preparation tools, and the scan that prepares before it reads.

Five behaviours are pinned here, each against a real compiled ELF and a real
managed IDA database.

**Preparation changes what a scan can see.** The fixture below hides a
``strcpy`` call inside an unreferenced stretch of executable bytes. IDA
decodes those bytes and creates no function over them, and the scanner skips
a call site that belongs to no function — so before preparation that call is
not a finding at all. Once the ``functions`` pass proves the stretch is an
entry point and defines it, the same scan reports the same call. That is the
only honest way to show "recovered evidence affects a finding": not a count
that went up, but a specific row that exists because of a specific recovery.

**A revision is reused only when everything about it still matches.** Source
identity, managed artifact, backend capability fingerprint and the requested
pass coverage, all four. A second preparation of an unchanged target applies
nothing and keeps the revision where it was.

**Refusals happen before anything exists.** An empty pass list, a pass this
build does not run, an unsafe rule expression and an external backend are all
refused while the request is still data, with no managed database and no
catalog on disk afterwards.

**A failure is never dressed as a result.** A save the adapter could not
complete leaves the earlier recorded passes exactly as they were, claims no
new coverage, and fails the scan that needed it rather than returning a clean
one.

**A shorter run never replaces a longer one.** A pass re-run under a budget
it cannot finish comes back ``partial`` with the addresses it never reached
named — this design's ordinary cancellation. The complete result an earlier
run recorded keeps its place, keeps its candidates, and is what a later
request reuses.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from typing import Any

import pytest
from conftest import missing_prerequisite, names_the_rollback
from vulfi_mcp.catalog import CATALOG_NAME, CATALOG_UNAVAILABLE_REASON
from vulfi_mcp.ida_adapter import ManagedDatabaseError, ensure_managed_idb, scan_ida
from vulfi_mcp.prepare import PreparationError, prepare_target, run_ida_passes
from vulfi_mcp.rules import validate_rules
from vulfi_mcp.server import vulfi_prepare, vulfi_preparation, vulfi_scan

pytestmark = pytest.mark.requires_ida

#: `tests/conftest.py`'s tolerance for IDA 9.4's bad-pack defect: hold a body
#: to "the state is intact, or the loss was reported". Register every managed
#: database a body produces with the list it yields.
Tolerance = Callable[[], AbstractContextManager[list[str]]]


@contextmanager
def _rollback_survives_the_tool_wrapper() -> Iterator[None]:
    """Give the shared bad-pack tolerance back the error the server raised.

    The tools below are the registered MCP ones, and the decorator that
    registers them re-raises every failure as its own transport error with
    the original underneath. ``durable_or_reported`` tolerates a
    ``ManagedDatabaseError`` naming this server's rollback and nothing else,
    deliberately, so that wrapper has to be undone for exactly that error and
    for no other. The tolerance's own predicate decides, rather than a second
    copy of the wording; anything else propagates as it arrived.
    """
    try:
        yield
    except Exception as wrapped:
        cause = wrapped.__cause__
        if not isinstance(cause, BaseException) or not names_the_rollback(cause):
            raise
        raise cause from wrapped


#: Exactly the flags the preparation fixtures are pinned to, so the hidden
#: stretch below really is assembled as written and `strcpy` is really called.
CC_FLAGS = ("-O0", "-fno-builtin", "-fno-inline", "-fPIE", "-pie")

#: The local symbol on the hidden stretch. Local, not global: a global symbol
#: is an entry point IDA recognises on its own, which would make the whole
#: fixture vacuous.
HIDDEN = "vulfi_hidden_copy"

#: A target whose only interesting property is where its `strcpy` calls are.
#: One is reached from `main` and IDA owns it; the other lives in bytes
#: nothing references, which IDA decodes and leaves outside every function.
FIXTURE_SOURCE = f"""\
#include <stdio.h>
#include <string.h>

char vulfi_flow_destination[64];

/* An executable section nothing references, holding a stretch IDA's own
 * auto-analysis declines to make a function of: no stack adjustment, so the
 * heuristic that recognises a frame never fires. (Measured, not assumed —
 * add `sub $8,%rsp` here and IDA creates the function itself, which is why
 * this shape is the one that pins anything.) The `strcpy` call inside is
 * therefore attributed to no function and the scanner skips it entirely,
 * because a call site with no holder is not a finding. The local ELF symbol
 * is the evidence the `functions` pass needs to call this an entry point
 * and define it. */
__asm__(
    ".section .vulfi_flow,\\"ax\\",@progbits\\n"
    ".balign 16\\n"
    "{HIDDEN}:\\n"
    "  endbr64\\n"
    "  call strcpy@PLT\\n"
    "  ret\\n"
    ".previous\\n");

int vulfi_visible_copy(char *source)
{{
    strcpy(vulfi_flow_destination, source);
    return (int)strlen(vulfi_flow_destination);
}}

int main(int argc, char **argv)
{{
    if (argc > 1)
        return vulfi_visible_copy(argv[1]);
    puts(vulfi_flow_destination);
    return 0;
}}
"""

#: A rule that matches every `strcpy` call site and needs no recovered
#: argument to decide: the question this file asks is which call sites exist
#: at all, not what the scanner could prove about their arguments.
COPY_RULE: dict[str, Any] = {
    "name": "Any Copy",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {"High": "True", "Medium": "False", "Low": "False"},
}

#: An expression that would run a command if anything ever evaluated it with
#: Python. It must be refused while it is still JSON.
MALICIOUS_RULE: dict[str, Any] = {
    "name": "Escape Attempt",
    "function_names": ["strcpy"],
    "wrappers": False,
    "mark_if": {
        "High": "__import__('os').system('touch vulfi-prepare-escaped')",
        "Medium": "False",
        "Low": "False",
    },
}

SCAN_NAME = "prepflow"
SCOPE = f"custom:{SCAN_NAME}"


@pytest.fixture
def compiled_flow(tmp_path: Path) -> Path:
    """Compile the inline fixture above into ``tmp_path``."""
    compiler = shutil.which("gcc")
    if compiler is None:
        missing_prerequisite(
            "gcc is not installed, so the flow fixture cannot be built"
        )
    source = tmp_path / "vulfi_flow.c"
    source.write_text(FIXTURE_SOURCE, encoding="utf-8")
    binary = tmp_path / "vulfi_flow"
    completed = subprocess.run(
        [str(compiler), *CC_FLAGS, "-o", str(binary), str(source)],
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"compiling the flow fixture failed ({completed.returncode}):\n"
            f"{completed.stderr.strip()}"
        )
    return binary


def _workspace_contents(data_dir: Path) -> list[str]:
    if not data_dir.exists():
        return []
    return sorted(str(entry.relative_to(data_dir)) for entry in data_dir.rglob("*"))


def _managed_databases(data_dir: Path) -> list[Path]:
    if not data_dir.exists():
        return []
    return [path for suffix in ("*.i64", "*.idb") for path in data_dir.rglob(suffix)]


def _hidden_candidate(result: dict[str, Any]) -> dict[str, Any]:
    """The function candidate the ``functions`` pass proved from the symbol."""
    matches = [
        row
        for row in result["candidates"]
        if row["kind"] == "function"
        and row["evidence"]["entry_evidence"].get("symbol") == HIDDEN
    ]
    assert len(matches) == 1, [
        (row["kind"], row["evidence"].get("entry_evidence")) for row in matches
    ] or result["candidates"]
    return matches[0]


def test_scan_prepares_once_and_reuses_revision(
    compiled_flow: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _prepare_scan_and_reuse(compiled_flow)
        finally:
            produced.extend(str(path) for path in _managed_databases(managed_data_dir))


def _prepare_scan_and_reuse(binary: Path) -> None:
    target = str(binary)

    # Baseline, asserted rather than assumed: the managed database IDA built
    # on its own attributes the hidden call to no function, so the scanner
    # never reports it. A future IDA that recovers the stretch unaided fails
    # here instead of making the rest of this test vacuous.
    idb_path = ensure_managed_idb(target)
    before = scan_ida(idb_path, validate_rules([COPY_RULE]), SCOPE, path=target)
    assert [row["found_in"] for row in before["findings"]] == ["vulfi_visible_copy"]

    prepared = vulfi_prepare(target)
    assert prepared["backend"] == "ida"
    assert prepared["reused"] is False
    assert prepared["requested_passes"] == [
        "functions",
        "strings",
        "structures",
        "pointer_tables",
    ]
    assert prepared["idb_path"] == idb_path
    assert prepared["source_sha256"]
    assert prepared["analysis_id"]
    assert prepared["preparation_revision"] >= 1
    assert prepared["catalog_available"] is True
    assert Path(prepared["artifact_paths"]["catalog"]).is_file()

    recovered = _hidden_candidate(prepared)
    assert recovered["state"] == "applied", recovered["reason"]
    assert recovered["candidate_id"] in prepared["applied_ids"]
    entry = recovered["address"]
    end = recovered["evidence"]["defined_end"]
    assert end is not None and end > entry

    # The scan reuses the revision it did not have to make, and reports it.
    after = vulfi_scan(target, rules=[COPY_RULE], scan_name=SCAN_NAME)
    assert after["analysis_id"] == prepared["analysis_id"]
    assert after["preparation_revision"] == prepared["preparation_revision"]

    found = {row["found_in"]: row for row in after["findings"]}
    assert set(found) == {"vulfi_visible_copy", HIDDEN}, after["findings"]
    hidden = found[HIDDEN]
    assert entry <= int(hidden["address"], 16) < end
    assert hidden["priority"] == "High"

    # An identical request reuses the recorded revision. The artifact's
    # revision is the proof that nothing was applied a second time: it moves
    # in the same write as the change that earned it, so an unchanged
    # revision is an unchanged artifact. The reused report describes that
    # same revision — the same passes, the same candidates, the same applied
    # rows — rather than a second, emptier run.
    again = vulfi_prepare(target)
    assert again["reused"] is True
    assert again["analysis_id"] == prepared["analysis_id"]
    assert again["preparation_revision"] == prepared["preparation_revision"]
    assert again["applied_ids"] == prepared["applied_ids"]
    assert again["applied_total"] == prepared["applied_total"]
    assert again["candidate_total"] == prepared["candidate_total"]
    assert again["skipped_prerequisites"] == []
    assert {row["pass"] for row in again["passes"]} == {
        row["pass"] for row in prepared["passes"]
    }

    # And the catalog pages the same candidates without re-running anything.
    page = vulfi_preparation(target, limit=5)
    assert page["available"] is True
    assert page["analysis_id"] == prepared["analysis_id"]
    assert page["total"] == prepared["candidate_total"]
    assert page["loaded"] == len(page["candidates"]) <= 5
    assert page["preparation_revision"] == prepared["preparation_revision"]


def test_invalid_passes_and_rules_do_not_mutate(
    compiled_flow: Path, managed_data_dir: Path
) -> None:
    target = str(compiled_flow)
    escaped = Path.cwd() / "vulfi-prepare-escaped"

    with pytest.raises(Exception, match="passes"):
        vulfi_prepare(target, passes=[])
    with pytest.raises(Exception, match="nonesuch"):
        vulfi_prepare(target, passes=["nonesuch"])
    with pytest.raises(Exception, match="binaryninja"):
        vulfi_prepare(target, backend="binaryninja")
    with pytest.raises(Exception, match=r"rules\[0\]"):
        vulfi_scan(target, rules=[MALICIOUS_RULE], scan_name=SCAN_NAME)
    with pytest.raises(Exception, match="analysis_id"):
        vulfi_scan(target, analysis_id="prep-nothing-prepared")

    assert not escaped.exists(), "a rejected rule ran its own expression"
    # The whole point: every refusal above happened while the request was
    # still data, so no database and no catalog were ever created.
    assert _workspace_contents(managed_data_dir) == []

    # ghidra and r2 are backends. A configured one may prepare. An
    # unconfigured one refuses with a reason. Neither is an invalid name.
    named = vulfi_prepare(target, backend="ghidra")
    assert named["requested_backend"] == "ghidra"
    if named.get("coverage") == "unavailable":
        assert named.get("warnings")
        assert _workspace_contents(managed_data_dir) == []


def test_catalog_unavailable_is_not_empty(
    compiled_flow: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _page_with_the_catalog_offline(compiled_flow, managed_data_dir)
        finally:
            produced.extend(str(path) for path in _managed_databases(managed_data_dir))


def _page_with_the_catalog_offline(binary: Path, data_dir: Path) -> None:
    target = str(binary)

    # A target nothing has prepared has no managed database, and a read does
    # not make one: unavailable, with a reason, never an empty page.
    nothing = vulfi_preparation(target)
    assert nothing["available"] is False
    assert nothing["reason"]
    assert nothing["candidates"] == []
    assert nothing["total"] == 0
    assert nothing["analysis_id"] is None
    assert _workspace_contents(data_dir) == []

    prepared = vulfi_prepare(target, passes=["strings"])
    assert prepared["candidate_total"] > 0

    catalog = data_dir / CATALOG_NAME
    assert catalog.is_file()
    catalog.unlink()

    offline = vulfi_preparation(target)
    assert offline["available"] is False
    assert offline["reason"] == CATALOG_UNAVAILABLE_REASON
    assert offline["candidates"] == []
    assert offline["total"] == 0
    # The managed database is still there and still carries the revision; it
    # is the candidate store that is gone, and the two are reported apart.
    assert offline["idb_path"]
    assert offline["preparation_revision"] == prepared["preparation_revision"]
    # Nothing re-created the store to answer the question.
    assert not catalog.exists()


def test_failed_save_retains_partial(
    compiled_flow: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _failed_save_claims_nothing(compiled_flow)
        finally:
            produced.extend(str(path) for path in _managed_databases(managed_data_dir))


def test_an_unreadable_spare_is_re_raised_not_substituted(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A spare that cannot be opened is the operator's failure, not an absent backend."""
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(tmp_path / "absent.toml"))
    binary = tmp_path / "firmware"
    binary.write_bytes(b"not a database")
    dead = tmp_path / "dead.i64"
    phrase = (
        f"IDA could not open {dead}, and neither can the copy taken before"
        " its last save; nothing in this workspace is usable and it has to"
        " be built again from its source"
    )

    def _dead(path: str) -> str:
        raise ManagedDatabaseError(phrase)

    monkeypatch.setattr("vulfi_mcp.prepare.ensure_managed_idb", _dead)
    with pytest.raises(ManagedDatabaseError) as refused:
        prepare_target(str(binary), backend="auto")
    assert "neither can the copy taken before its last save" in str(refused.value)
    assert "no backend in the chain" not in str(refused.value)


def test_a_missing_database_still_advances_the_chain(
    tmp_path: Path, managed_data_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No database was produced, so the chain may ask the next backend."""
    monkeypatch.setenv("VULFI_MCP_PROVIDER_CONFIG", str(tmp_path / "absent.toml"))
    binary = tmp_path / "firmware"
    binary.write_bytes(b"not a database")
    produced = tmp_path / "missing.i64"
    phrases = (
        f"IDA did not leave a database at {produced}",
        (
            f"IDA could not open the copy it made of {binary}: those bytes"
            " are a database IDA 9.4 packed and can no longer load. Nothing"
            f" was written to {binary}, and no managed database was produced"
            " from it — it has to be built again from its source binary."
        ),
    )
    for phrase in phrases:
        def _missing(path: str, message: str = phrase) -> str:
            raise ManagedDatabaseError(message)

        monkeypatch.setattr("vulfi_mcp.prepare.ensure_managed_idb", _missing)
        with pytest.raises(PreparationError) as advanced:
            prepare_target(str(binary), backend="auto")
        assert "no backend in the" in str(advanced.value) and "chain prepared" in str(
            advanced.value
        )
        assert phrase in str(advanced.value)
        assert not isinstance(advanced.value, ManagedDatabaseError)


def _refuse_to_save(handle: object, database: object) -> None:
    """Stand in for the adapter's save and fail the way a bad one does."""
    raise ManagedDatabaseError(f"IDA reported no save for {database}: injected")


def _refused(call: Callable[[], object]) -> None:
    """``call`` must fail, and fail with the save failure underneath it."""
    with pytest.raises(Exception) as reported:
        call()
    # The tool decorator re-raises as its own transport error; what the server
    # raised is still the adapter's unsaved-database failure.
    cause = reported.value.__cause__
    assert isinstance(cause, ManagedDatabaseError), reported
    # Unless the save never got the chance to fail. IDA 9.4's bad-pack defect
    # refuses the *open*, so the call fails before `_refuse_to_save` is ever
    # reached and the reason names the rollback instead of the injection —
    # observed in a whole-suite run. That is the one outcome this file's
    # tolerance owns, so it is handed back to it rather than asserted on;
    # every other failure still has to be the injected one.
    if names_the_rollback(cause):
        raise cause from reported.value
    assert "injected" in str(reported.value)


def _failed_save_claims_nothing(binary: Path) -> None:
    target = str(binary)

    # A page window is refused before the workspace is even consulted.
    for bad in ({"offset": -1}, {"limit": 0}, {"limit": 201}):
        with pytest.raises(Exception, match="offset|limit"):
            vulfi_preparation(target, **bad)

    partial = vulfi_prepare(target, passes=["strings"])
    assert [row["pass"] for row in partial["passes"]] == ["strings"]
    assert partial["skipped_prerequisites"], (
        "a strings-only run cannot do its instruction stage and must say so"
    )

    # Scoped, not the test's own `monkeypatch`: undoing that one would also
    # undo the managed-workspace environment the fixtures set up, and the
    # reads below would then look for this target somewhere it never was.
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("vulfi_mcp.ida_adapter._save_session", _refuse_to_save)
        # The requested coverage is wider than what is recorded, so this
        # re-runs — and its save fails. That is reported, never returned.
        _refused(lambda: vulfi_prepare(target))

    # Nothing was claimed: the earlier `strings` result is exactly as it was,
    # and no `functions` coverage was recorded for a run that never landed.
    page = vulfi_preparation(target)
    assert page["available"] is True, page["reason"]
    assert page["analysis_id"] == partial["analysis_id"]
    assert [row["pass"] for row in page["passes"]] == ["strings"]
    assert page["preparation_revision"] == partial["preparation_revision"]
    assert page["total"] == partial["candidate_total"]

    # And a scan that needs the preparation it cannot save reports the failure
    # rather than a clean complete scan of an unprepared analysis.
    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("vulfi_mcp.ida_adapter._save_session", _refuse_to_save)
        _refused(lambda: vulfi_scan(target, rules=[COPY_RULE], scan_name=SCAN_NAME))


#: One byte of reading, which is less than the first range of any image
#: costs. Budget exhaustion is this design's cancellation: the run returns,
#: reports `partial`, and names the addresses it never reached. The ceiling
#: is this absurd on purpose — a ceiling chosen to be "small" would be a
#: ceiling whose effect depends on how big the fixture happens to compile.
TIGHT_BUDGET: dict[str, int] = {"bytes": 1}


def _pass_entry(result: dict[str, Any], name: str) -> dict[str, Any]:
    """The one record this result carries for ``name``."""
    matches = [row for row in result["passes"] if row["pass"] == name]
    assert len(matches) == 1, result["passes"]
    return matches[0]


def test_a_shortened_rerun_keeps_the_longer_result(
    compiled_flow: Path,
    managed_data_dir: Path,
    durable_or_reported: Tolerance,
) -> None:
    with durable_or_reported() as produced, _rollback_survives_the_tool_wrapper():
        try:
            _shortened_rerun_keeps_what_it_could_not_beat(compiled_flow)
        finally:
            produced.extend(str(path) for path in _managed_databases(managed_data_dir))


def _shortened_rerun_keeps_what_it_could_not_beat(binary: Path) -> None:
    target = str(binary)

    whole = vulfi_prepare(target, passes=["functions"])
    complete = _pass_entry(whole, "functions")
    assert complete["coverage"] == "complete", complete
    assert complete["candidate_ids"], "the fixture must give `functions` work to do"
    recovered = _hidden_candidate(whole)
    assert recovered["state"] == "applied", recovered["reason"]
    assert recovered["candidate_id"] in complete["candidate_ids"]

    # The second request asks for one pass more, so there is nothing to reuse
    # and `functions` runs again — this time under a budget it cannot finish.
    ran: list[dict[str, Any]] = []

    def _on_a_tight_budget(idb_path: str, passes: tuple[str, ...]) -> dict[str, Any]:
        result = run_ida_passes(idb_path, passes, limits=TIGHT_BUDGET)
        ran.append(result)
        return result

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr("vulfi_mcp.prepare.run_ida_passes", _on_a_tight_budget)
        shortened = vulfi_prepare(target, passes=["functions", "strings"])

    # The re-run really was cut short, and really did cover less: without that
    # the rest of this test would pass against anything.
    assert len(ran) == 1, "the wider request had nothing to reuse and must re-run"
    cut = _pass_entry(ran[0], "functions")
    assert cut["coverage"] == "partial", cut
    assert [span for row in cut["ranges"] for span in row["unvisited"]], cut["ranges"]
    assert set(cut["candidate_ids"]) <= set(complete["candidate_ids"]), cut
    assert cut["candidate_ids"] != complete["candidate_ids"], (
        "recording this result would really have dropped candidates"
    )

    # And it was not written down: the stored record is still the complete
    # one, with the candidates only it describes, and the skip is reported.
    kept = _pass_entry(shortened, "functions")
    assert kept["coverage"] == "complete", kept
    assert kept["ranges"] == complete["ranges"]
    assert kept["candidate_ids"] == complete["candidate_ids"]
    assert recovered["candidate_id"] in kept["candidate_ids"]
    assert any("kept rather than replaced" in said for said in shortened["warnings"]), (
        shortened["warnings"]
    )

    # The catalog agrees, read back without running anything.
    page = vulfi_preparation(target)
    assert page["available"] is True, page["reason"]
    assert page["analysis_id"] == whole["analysis_id"]
    assert _pass_entry(page, "functions") == kept

    # And the revision a later request reuses is the complete one, not the
    # degraded one the shortened run would have left behind.
    again = vulfi_prepare(target, passes=["functions"])
    assert again["reused"] is True
    assert again["analysis_id"] == whole["analysis_id"]
    assert _pass_entry(again, "functions") == kept
    assert set(whole["applied_ids"]) <= set(again["applied_ids"])
    assert again["candidate_total"] >= whole["candidate_total"]

"""Preparation passes over a managed IDA analysis.

Before a scan can say anything trustworthy about a target, the analysis it
reads has to contain the functions, the strings, the object layouts and the
pointer tables that are really there. This module is the host side of that
work: it checks a request, hands it to the one worker operation that does
it, and returns what came back.

Three things are deliberately *not* here.

**No second IDA path.** Every byte this module causes to be written reaches
disk through :func:`vulfi_mcp.ida_adapter.invoke_ida`, which is the one lease
that keeps a rescue copy of the bytes a save replaces and reports a failed
save as a failure. There is no save route in this file.

**No duplicated vocabulary.** The pass names, the ceilings and the rules for
tightening them live in :mod:`vulfi_mcp.ida_runtime`, next to the code that
spends them, and are validated here by calling that module's validators and
re-raising what they say. A caller gets the refusal before a database is
opened, and gets exactly one wording for it.

**No analysis this module invented.** Everything in the result is the
worker's own report of what it read out of the database: candidates carry the
bytes or the instructions they were recovered from, and a pass that was cut
short names the addresses it never reached.
"""

from __future__ import annotations

from typing import Final

from vulfi_mcp.ida_adapter import BACKEND, invoke_ida
from vulfi_mcp.ida_runtime import (
    PREPARE_LIMITS,
    PREPARE_PASSES,
    OperationError,
    validate_prepare_limits,
    validate_prepare_passes,
)

__all__ = [
    "LIMITS",
    "PASSES",
    "PreparationError",
    "run_ida_passes",
]

#: The passes this build runs, in the order dependencies require. ``strings``
#: recovers raw mapped bytes on its own, but the buffers that exist only in
#: instructions need ``functions`` to have run first, and a request that
#: leaves ``functions`` out is told which stage that cost it. ``structures``
#: and ``pointer_tables`` read the analysis as they find it, and run last
#: because a function the first pass recovers is one whose operands and
#: whose entry they can then see.
PASSES: Final[tuple[str, ...]] = PREPARE_PASSES

#: The ceilings one run may spend. A request may lower any of these and
#: cannot raise one.
LIMITS: Final[dict[str, int]] = dict(PREPARE_LIMITS)

#: The one operation name this module sends.
_OPERATION: Final = "prepare"


class PreparationError(ValueError):
    """A preparation request was refused before any database was opened."""


def run_ida_passes(
    idb_path: str,
    passes: tuple[str, ...] = PASSES,
    limits: dict[str, int] | None = None,
) -> dict[str, object]:
    """Run ``passes`` over one managed IDB and return what they recovered.

    ``idb_path`` must already be a managed database —
    :func:`vulfi_mcp.ida_adapter.ensure_managed_idb` produces one, and the
    operator's own binary or supplied IDB is never opened here. ``passes`` is
    reordered into dependency order and de-duplicated; a name this build does
    not run is refused rather than quietly replaced with one that it does.
    ``limits`` may only tighten :data:`LIMITS`.

    The returned dictionary is the worker's, with these keys:

    ``passes``
        One :class:`vulfi_mcp.contracts.PassResult` per pass that ran, each
        carrying its per-range coverage. A range the run stopped inside names
        what is left of it in ``unvisited``; a range it never started names
        all of itself. ``coverage`` is ``complete`` only when every range is.
    ``candidates``
        Every :class:`vulfi_mcp.contracts.Candidate` the run produced, with
        the bytes or the instructions it rests on. ``state`` is ``applied``
        only for the ones the managed database now carries.
    ``applied_ids``, ``artifact_revision``
        What changed, and the revision of the managed artifact that now
        describes it. The revision moves only when something was applied, in
        the same write that carries the change.
    ``skipped_prerequisites``
        One entry per stage that did not run because the pass it depends on
        was not requested. A subset never reports a coverage it did not
        produce.
    ``warnings``, ``bounded``
        Everything the run wants said out loud, and whether any budget ran
        out at all.
    ``idb_path``, ``requested_idb_path``, ``input_file``, ``input_sha256``,
    ``image_base``, ``processor``, ``managed_idb_id``
        Which database answered and what it was built from. ``idb_path`` is
        the one IDA reports it has open and ``requested_idb_path`` is the one
        this call named, so a mismatch is visible rather than papered over.

    Raises :class:`PreparationError` for a request that is wrong on its face,
    before anything is opened, and lets
    :class:`vulfi_mcp.ida_adapter.ManagedDatabaseError`,
    :class:`FileNotFoundError` and :class:`ValueError` from the lease through
    unchanged: a database that cannot be opened or saved is not a
    preparation that found nothing.
    """
    payload = _request(passes, limits)
    result = invoke_ida(idb_path, _OPERATION, payload)
    return _checked(result, idb_path)


def _request(
    passes: tuple[str, ...], limits: dict[str, int] | None
) -> dict[str, object]:
    """One validated payload, or exactly what is wrong with the request."""
    try:
        chosen = validate_prepare_passes(passes)
        bounds = validate_prepare_limits({} if limits is None else limits)
    except OperationError as refused:
        raise PreparationError(str(refused)) from refused
    return {"passes": list(chosen), "limits": bounds}


def _checked(result: dict[str, object], idb_path: str) -> dict[str, object]:
    """The worker's report, with the database it describes named in it.

    The worker reports the path IDA has open, which is the same file; this
    adds the path the caller asked about so a result can be matched to a
    request without comparing two spellings of one database.
    """
    reported = result.get("backend")
    if reported != BACKEND:
        raise PreparationError(
            f"the IDA worker reported backend {reported!r}, not {BACKEND!r}"
        )
    for key in ("passes", "candidates"):
        if not isinstance(result.get(key), list):
            raise PreparationError(
                f"the IDA worker returned no {key} list: {result.get(key)!r}"
            )
    result["requested_idb_path"] = idb_path
    return result

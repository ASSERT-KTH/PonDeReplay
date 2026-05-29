#!/usr/bin/env python3
"""
Run a full PonDeReplay experiment over the dfhl-invariants dataset.

For each eligible case (the ones with both ``bytecode/original.hex`` and
``bytecode/patch.hex`` and a non-empty ``txs/`` folder):

1. Aggregate transaction hashes from ``src/<case>/txs/*.json`` (and from
   ``src/<case>/tx_hashes.json`` when present), keeping their on-chain
   ``reverted`` flag.
2. Make sure the malicious tx from ``dataset-info.json`` is in the list.
3. Replay every tx twice with ``BatchReplayer``:
   - once with ``original.hex`` (faithfulness baseline)
   - once with ``patch.hex`` (patch behaviour)
4. Save the full ``BatchReplayer`` report (including per-tx diagnostics) under
   ``<results-dir>/<case>/{original,patch}/replay-result.json``.
5. Classify each tx and produce a per-case soundness verdict.
6. Write an overall ``summary.json`` and ``summary.md``.

Soundness rules (``on_original`` first)
---------------------------------------
Each tx is replayed on **original** bytecode first. That replay must reproduce
on-chain behaviour (success/revert) before the patch verdict is trusted.

Per-tx ``on_original`` block:

- ``ok`` — original replay matches chain (``reason: matches_chain``)
- ``ok: false`` — replay issue: ``oog``, ``timestamp_risk``, ``status_mismatch``,
  ``replay_error`` (with ``remediation`` hint)

If ``on_original.ok`` is false, the tx is ``on_original_unreliable_<reason>`` and
the patch is **not** blamed.

When ``on_original.ok`` is true, patch categories are:

- ``patch_blocked_attack`` — malicious; patch reverts, original passes
- ``malicious_not_blocked`` — malicious; patch still succeeds
- ``patch_no_effect`` — benign; orig and patch agree (both pass)
- ``expected_revert`` — benign; both revert (chain also reverted)
- ``patch_breaks_benign`` — benign; patch reverts but original passed
- ``patch_relaxed`` — benign; patch passes but original reverted
- ``patch_oog_replay_artifact`` — patch-side OOG only (not a real patch revert)

Case verdict: ``sound`` when malicious is ``patch_blocked_attack`` and no benign
tx is ``patch_breaks_benign`` (with ``on_original.ok`` on those txs).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from dotenv import load_dotenv  # noqa: E402

from pondereplay.batch import BatchReplayer  # noqa: E402
from pondereplay.utils import read_bytecode  # noqa: E402


DEFAULT_DATASET_INFO = Path(
    "/home/sofia/Documents/Deffensive/dfhl-invariants/resources/dataset/dataset-info.json"
)
DEFAULT_DFHL_ROOT = Path("/home/sofia/Documents/Deffensive/dfhl-invariants")
DEFAULT_RESULTS_DIR = DEFAULT_DFHL_ROOT / "results" / "pondereplay"


# ---------------------------------------------------------------------------
# Dataset / tx discovery
# ---------------------------------------------------------------------------


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _is_tx_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) == 66
    )


def _eligible_cases(
    dataset_info: Dict[str, Any],
    dfhl_src: Path,
    only_ids: Optional[List[str]],
    skip_ids: List[str],
) -> List[Dict[str, Any]]:
    """Pick cases that have original.hex + patch.hex + non-empty txs."""
    eligible: List[Dict[str, Any]] = []
    for cid, info in dataset_info.items():
        if only_ids and cid not in only_ids:
            continue
        if cid in skip_ids:
            continue
        if not isinstance(info, dict):
            continue

        case_dir = dfhl_src / cid
        orig_hex = case_dir / "bytecode" / "original.hex"
        patch_hex = case_dir / "bytecode" / "patch.hex"
        if not orig_hex.exists() or not patch_hex.exists():
            continue

        tx_records = _collect_case_tx_records(case_dir, info)
        if not tx_records:
            continue

        contract_addr = info.get("vulnerable_contract_address")
        if not (isinstance(contract_addr, str) and contract_addr.startswith("0x")):
            continue

        malicious_tx = info.get("malicious_tx_address")
        proxy_addr = None
        compilation = info.get("compilation_metadata")
        if isinstance(compilation, dict) and compilation.get("is_proxy"):
            proxy_addr = compilation.get("proxy_address")

        eligible.append(
            {
                "id": cid,
                "case_dir": case_dir,
                "contract_address": contract_addr,
                "proxy_address": proxy_addr,
                "malicious_tx": (
                    malicious_tx if _is_tx_hash(malicious_tx) else None
                ),
                "original_hex": orig_hex,
                "patch_hex": patch_hex,
                "tx_records": tx_records,
                "modified_functions": info.get("modified_functions") or [],
            }
        )
    return eligible


def _collect_case_tx_records(
    case_dir: Path, info: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate tx hashes from ``txs/*.json`` and (if present)
    ``tx_hashes.json``. Returns a dict keyed by lower-cased tx hash.
    """
    records: Dict[str, Dict[str, Any]] = {}

    txs_dir = case_dir / "txs"
    if txs_dir.is_dir():
        for path in sorted(txs_dir.glob("*.json")):
            try:
                data = _load_json(path)
            except Exception:
                continue
            if not isinstance(data, list):
                continue
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                tx_hash = entry.get("tx_hash")
                if not _is_tx_hash(tx_hash):
                    continue
                key = tx_hash.lower()
                if key in records:
                    continue
                records[key] = {
                    "tx_hash": tx_hash,
                    "reverted": bool(entry.get("reverted", False)),
                    "block_number": entry.get("block_number"),
                    "tx_index": entry.get("tx_index"),
                    "selector": entry.get("selector"),
                    "canonical_sig": entry.get("canonical_sig"),
                    "contract_name": entry.get("contract_name"),
                    "from_addr": entry.get("from_addr"),
                    "to_addr": entry.get("to_addr"),
                    "source_file": path.name,
                }

    tx_hashes_file = case_dir / "tx_hashes.json"
    if tx_hashes_file.exists():
        try:
            payload = _load_json(tx_hashes_file)
        except Exception:
            payload = None
        candidate_list: List[str] = []
        if isinstance(payload, dict):
            for key in ("tx_hashes", "txs", "hashes"):
                value = payload.get(key)
                if isinstance(value, list):
                    candidate_list = value
                    break
        elif isinstance(payload, list):
            candidate_list = payload
        for tx_hash in candidate_list:
            if not _is_tx_hash(tx_hash):
                continue
            key = tx_hash.lower()
            if key in records:
                continue
            records[key] = {
                "tx_hash": tx_hash,
                "reverted": False,
                "block_number": None,
                "tx_index": None,
                "selector": None,
                "canonical_sig": None,
                "contract_name": None,
                "from_addr": None,
                "to_addr": None,
                "source_file": tx_hashes_file.name,
            }

    malicious = info.get("malicious_tx_address")
    if _is_tx_hash(malicious):
        key = malicious.lower()
        if key not in records:
            records[key] = {
                "tx_hash": malicious,
                "reverted": False,
                "block_number": None,
                "tx_index": None,
                "selector": None,
                "canonical_sig": None,
                "contract_name": None,
                "from_addr": None,
                "to_addr": None,
                "source_file": "dataset-info.json",
            }

    return records


# ---------------------------------------------------------------------------
# Replay execution
# ---------------------------------------------------------------------------


def _flatten_results(report: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Return ``tx_hash_lower -> result_dict`` from a batch report."""
    flat: Dict[str, Dict[str, Any]] = {}
    for tx_hash, value in (report.get("results") or {}).items():
        if isinstance(value, dict):
            flat[tx_hash.lower()] = value
    return flat


def _run_variant(
    *,
    variant: str,
    batch: BatchReplayer,
    tx_hashes: List[str],
    contract_address: str,
    bytecode_path: Path,
    output_dir: Path,
    attack_tx: Optional[str],
    verbose: bool,
    bump_gas_for_original: bool = False,
) -> Dict[str, Any]:
    """Replay ``tx_hashes`` against one bytecode variant and persist the report."""
    bytecode = read_bytecode(str(bytecode_path))

    # Patch variant always re-estimates gas on Anvil (patched bytecode is larger).
    # Original uses source tx gas unless --bump-gas-for-original is set.
    use_bump = variant == "patch" or bump_gas_for_original

    if verbose:
        print(
            f"   [{variant}] bytecode={bytecode_path} "
            f"({len(bytecode) // 2} bytes), txs={len(tx_hashes)}, "
            f"bump_gas={use_bump}",
            file=sys.stderr,
        )

    prev_flag = batch.replayer.bump_gas_for_patch
    batch.replayer.bump_gas_for_patch = use_bump
    try:
        started = time.time()
        results = batch.replay_batch(
            tx_hashes=tx_hashes,
            contract_address=contract_address,
            new_bytecode=bytecode,
            verbose=verbose,
        )
        elapsed = time.time() - started
    finally:
        batch.replayer.bump_gas_for_patch = prev_flag

    report = batch.generate_report(results, attack_tx=attack_tx, verbose=False)
    report["variant"] = variant
    report["bytecode_path"] = str(bytecode_path)
    report["bytecode_size_bytes"] = len(bytecode) // 2
    report["elapsed_seconds"] = round(elapsed, 2)

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(output_dir / "replay-result.json", report)

    if verbose:
        print(
            f"   [{variant}] done in {elapsed:.1f}s — passed={report['passed']} "
            f"failed={report['failed']} unfaithful={len(report.get('unfaithful_replay_txs', []))}",
            file=sys.stderr,
        )
    return report


# ---------------------------------------------------------------------------
# Soundness classification
# ---------------------------------------------------------------------------


def _local_reverted(result: Dict[str, Any]) -> Optional[bool]:
    """
    Decide whether the local replay (re)verted. Returns ``None`` when we cannot
    tell (e.g. the replayer itself errored before producing a status).
    """
    if not isinstance(result, dict):
        return None
    execution = result.get("execution") if isinstance(result.get("execution"), dict) else {}
    local_reverted = result.get("local_reverted")
    if isinstance(local_reverted, bool):
        return local_reverted
    if isinstance(execution.get("local_reverted"), bool):
        return execution["local_reverted"]
    local_status = execution.get("local_status")
    if local_status is None:
        local_status = (result.get("diagnostics") or {}).get("local_status")
    if local_status is None:
        return None
    return int(local_status) == 0


def _local_failure_reason(result: Dict[str, Any]) -> Optional[str]:
    if not isinstance(result, dict):
        return None
    reason = result.get("local_failure_reason")
    if isinstance(reason, str) and reason:
        return reason
    execution = result.get("execution") or {}
    reason = execution.get("local_failure_reason")
    if isinstance(reason, str) and reason:
        return reason
    diag = result.get("diagnostics") or {}
    reason = diag.get("local_failure_reason")
    if isinstance(reason, str) and reason:
        return reason
    return None


def _replay_failed(result: Dict[str, Any]) -> bool:
    """Replay machinery itself errored (not a clean EVM revert)."""
    if not isinstance(result, dict):
        return True
    error = result.get("error") or ""
    if not error:
        return False
    lowered = error.lower()
    if "out of gas" in lowered:
        return False
    if "revert" in lowered:
        return False
    return True


def _has_time_risk_warning(result: Dict[str, Any]) -> bool:
    """Preflight emitted a 'time/context mismatch risk' warning."""
    if not isinstance(result, dict):
        return False
    diag = result.get("diagnostics") or {}
    warnings = diag.get("warnings") or []
    if not isinstance(warnings, list):
        return False
    return any(
        isinstance(w, str) and ("time/context mismatch" in w.lower() or "time-dependent" in w.lower())
        for w in warnings
    )


def _on_original_sanity(
    *,
    chain_reverted: bool,
    orig_local_reverted: Optional[bool],
    orig_result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Decide whether the original-bytecode replay reproduced chain behaviour.

    Returns a dict with:
      ok           - True iff the original replay is a trustworthy baseline
      reason       - matches_chain | oog | timestamp_risk | status_mismatch | replay_error
      remediation  - suggested fix (when ok=False)
      details      - human-readable explanation
    """
    if _replay_failed(orig_result):
        return {
            "ok": False,
            "reason": "replay_error",
            "remediation": "investigate replayer error",
            "details": (orig_result.get("error") or "replay machinery error")[:200],
        }

    if orig_local_reverted is None:
        return {
            "ok": False,
            "reason": "replay_error",
            "remediation": "investigate replayer (no status produced)",
            "details": "replay produced no local_status",
        }

    orig_reason = _local_failure_reason(orig_result)

    if orig_local_reverted and orig_reason == "out_of_gas":
        return {
            "ok": False,
            "reason": "oog",
            "remediation": "rerun with --bump-gas-for-original (experiment) or --bump-gas-for-patch (CLI)",
            "details": (
                "original replay hit out-of-gas — the source tx's gas limit "
                "is too tight for the simulated execution"
            ),
        }

    if bool(orig_local_reverted) == bool(chain_reverted):
        details = (
            "original replay reproduced the on-chain "
            + ("revert" if chain_reverted else "success")
        )
        if _has_time_risk_warning(orig_result):
            details += (
                " (preflight notes time/context mismatch risk — advisory only)"
            )
        return {
            "ok": True,
            "reason": "matches_chain",
            "remediation": None,
            "details": details,
        }

    # Original replay disagrees with chain: chain reverted but replay didn't,
    # or chain succeeded but replay did. This is the unfaithful-original case.
    if _has_time_risk_warning(orig_result):
        return {
            "ok": False,
            "reason": "timestamp_risk",
            "remediation": "rerun with --strict-anvil",
            "details": (
                "original replay disagrees with chain and preflight flagged "
                "a time/context mismatch — likely block.timestamp drift"
            ),
        }
    return {
        "ok": False,
        "reason": "status_mismatch",
        "remediation": "investigate (chain vs original-replay disagreement)",
        "details": (
            "chain "
            + ("reverted" if chain_reverted else "succeeded")
            + " but original replay "
            + ("reverted" if orig_local_reverted else "succeeded")
        ),
    }


def _classify_tx(
    *,
    is_malicious: bool,
    chain_reverted: bool,
    orig_local_reverted: Optional[bool],
    patch_local_reverted: Optional[bool],
    orig_result: Dict[str, Any],
    patch_result: Dict[str, Any],
    on_original: Dict[str, Any],
) -> str:
    """
    Classify a tx. The sanity layer (``on_original``) is consulted first:
    if the original-replay baseline isn't trustworthy for this tx, we never
    blame the patch and instead surface an ``on_original_*`` category.
    """
    # Patch-side replay machinery error trumps everything (no usable patch result).
    if _replay_failed(patch_result):
        return "replay_failure"
    if patch_local_reverted is None:
        return "replay_failure"

    # If the original-replay baseline is unreliable, the patch verdict is
    # inconclusive for this tx.
    if not on_original.get("ok"):
        reason = on_original.get("reason") or "other"
        return f"on_original_unreliable_{reason}"

    # Patch-side OOG is also a replay artifact (not a real patch revert).
    patch_reason = _local_failure_reason(patch_result)
    if patch_local_reverted and patch_reason == "out_of_gas":
        return "patch_oog_replay_artifact"

    if is_malicious:
        if patch_local_reverted and not orig_local_reverted:
            return "patch_blocked_attack"
        if not patch_local_reverted:
            return "malicious_not_blocked"
        # Both reverted — chain succeeded (we're past sanity gate). The patch
        # didn't change behaviour vs. the (faithful) original replay, but the
        # original replay reverted matching the chain — wait, we're inside
        # ok=True so chain_reverted == orig_local_reverted. If chain reverted
        # and patch reverts too, it's expected_revert; if chain succeeded
        # then orig_local_reverted is False so we'd be in the branches above.
        return "expected_revert"

    # Benign tx — use the original replay (now trusted) as the reference.
    if orig_local_reverted == patch_local_reverted:
        if patch_local_reverted:
            return "expected_revert"
        return "patch_no_effect"

    if patch_local_reverted and not orig_local_reverted:
        return "patch_breaks_benign"

    return "patch_relaxed"


def _revert_message(result: Dict[str, Any]) -> Optional[str]:
    if not isinstance(result, dict):
        return None
    msg = result.get("revert_message")
    if isinstance(msg, str) and msg:
        return msg
    diag = result.get("diagnostics") or {}
    msg = diag.get("revert_message")
    if isinstance(msg, str) and msg:
        return msg
    err = result.get("error")
    if isinstance(err, str) and err:
        return err
    return None


def _is_unfaithful(result: Dict[str, Any]) -> bool:
    if not isinstance(result, dict):
        return False
    diag = result.get("diagnostics") or {}
    return diag.get("faithfulness") == "unfaithful"


def _analyze_case(
    *,
    case: Dict[str, Any],
    orig_report: Dict[str, Any],
    patch_report: Dict[str, Any],
) -> Dict[str, Any]:
    orig_flat = _flatten_results(orig_report)
    patch_flat = _flatten_results(patch_report)

    malicious_tx_lower = (
        case["malicious_tx"].lower() if case.get("malicious_tx") else None
    )

    classifications: Dict[str, int] = {}
    txs: List[Dict[str, Any]] = []
    suspicious_txs: List[Dict[str, Any]] = []
    unfaithful_pairs: List[str] = []
    on_original_failures: List[Dict[str, Any]] = []

    for key, record in case["tx_records"].items():
        orig_result = orig_flat.get(key, {})
        patch_result = patch_flat.get(key, {})
        orig_local_reverted = _local_reverted(orig_result)
        patch_local_reverted = _local_reverted(patch_result)
        chain_reverted = bool(record.get("reverted"))
        is_malicious = malicious_tx_lower is not None and key == malicious_tx_lower

        if _is_unfaithful(orig_result) or _is_unfaithful(patch_result):
            unfaithful_pairs.append(record["tx_hash"])

        on_original = _on_original_sanity(
            chain_reverted=chain_reverted,
            orig_local_reverted=orig_local_reverted,
            orig_result=orig_result,
        )

        category = _classify_tx(
            is_malicious=is_malicious,
            chain_reverted=chain_reverted,
            orig_local_reverted=orig_local_reverted,
            patch_local_reverted=patch_local_reverted,
            orig_result=orig_result,
            patch_result=patch_result,
            on_original=on_original,
        )
        classifications[category] = classifications.get(category, 0) + 1

        entry = {
            "tx_hash": record["tx_hash"],
            "is_malicious": is_malicious,
            "chain_reverted": chain_reverted,
            "orig_local_reverted": orig_local_reverted,
            "patch_local_reverted": patch_local_reverted,
            "orig_revert_message": _revert_message(orig_result),
            "patch_revert_message": _revert_message(patch_result),
            "orig_local_failure_reason": _local_failure_reason(orig_result),
            "patch_local_failure_reason": _local_failure_reason(patch_result),
            "orig_replay_mode": orig_result.get("replay_mode"),
            "patch_replay_mode": patch_result.get("replay_mode"),
            "orig_unfaithful": _is_unfaithful(orig_result),
            "patch_unfaithful": _is_unfaithful(patch_result),
            "selector": record.get("selector"),
            "canonical_sig": record.get("canonical_sig"),
            "block_number": record.get("block_number"),
            "tx_index": record.get("tx_index"),
            "source_file": record.get("source_file"),
            "on_original": on_original,
            "category": category,
        }
        txs.append(entry)
        if category == "patch_breaks_benign":
            suspicious_txs.append(entry)
        if not on_original.get("ok"):
            on_original_failures.append(
                {
                    "tx_hash": record["tx_hash"],
                    "is_malicious": is_malicious,
                    "reason": on_original.get("reason"),
                    "remediation": on_original.get("remediation"),
                    "details": on_original.get("details"),
                }
            )

    total = len(txs)
    orig_passed = sum(1 for t in txs if t["orig_local_reverted"] is False)
    orig_failed = sum(1 for t in txs if t["orig_local_reverted"] is True)
    patch_passed = sum(1 for t in txs if t["patch_local_reverted"] is False)
    patch_failed = sum(1 for t in txs if t["patch_local_reverted"] is True)

    malicious_entry = (
        next((t for t in txs if t["is_malicious"]), None)
        if malicious_tx_lower
        else None
    )

    on_original_ok_count = sum(1 for t in txs if t["on_original"]["ok"])
    on_original_failed_count = total - on_original_ok_count
    on_original_quality = _on_original_quality(
        total=total,
        ok_count=on_original_ok_count,
        malicious_entry=malicious_entry,
    )
    on_original_summary = {
        "txs_total": total,
        "ok": on_original_ok_count,
        "failed": on_original_failed_count,
        "quality": on_original_quality,
        "failures": on_original_failures,
    }

    verdict = _case_verdict(
        malicious_entry=malicious_entry,
        suspicious_count=len(suspicious_txs),
        replay_failures=classifications.get("replay_failure", 0),
        on_original_summary=on_original_summary,
    )

    return {
        "case_id": case["id"],
        "contract_address": case["contract_address"],
        "proxy_address": case.get("proxy_address"),
        "malicious_tx": case.get("malicious_tx"),
        "modified_functions": case.get("modified_functions"),
        "totals": {
            "txs": total,
            "orig_local_passed": orig_passed,
            "orig_local_failed": orig_failed,
            "patch_local_passed": patch_passed,
            "patch_local_failed": patch_failed,
            "orig_unfaithful_count": len(
                orig_report.get("unfaithful_replay_txs") or []
            ),
            "patch_unfaithful_count": len(
                patch_report.get("unfaithful_replay_txs") or []
            ),
        },
        "classifications": classifications,
        "malicious_entry": malicious_entry,
        "suspicious_txs": suspicious_txs,
        "unfaithful_pairs": unfaithful_pairs,
        "on_original": on_original_summary,
        "verdict": verdict,
        "tx_results": txs,
    }


def _on_original_quality(
    *,
    total: int,
    ok_count: int,
    malicious_entry: Optional[Dict[str, Any]],
) -> str:
    """
    Quality of the original-replay baseline for this case:

    - good     : every tx replayed faithfully (ok == total)
    - partial  : some txs failed sanity but the malicious tx (when present)
                 still has a usable baseline — patch verdict on the attack tx
                 can still be trusted
    - broken   : the malicious tx itself failed sanity, OR there's no
                 malicious tx and most txs failed sanity
    """
    if total == 0:
        return "broken"
    if ok_count == total:
        return "good"
    if malicious_entry is not None:
        if not malicious_entry.get("on_original", {}).get("ok"):
            return "broken"
        return "partial"
    if ok_count >= max(1, total // 2):
        return "partial"
    return "broken"


def _case_verdict(
    *,
    malicious_entry: Optional[Dict[str, Any]],
    suspicious_count: int,
    replay_failures: int,
    on_original_summary: Dict[str, Any],
) -> Dict[str, Any]:
    notes: List[str] = []
    status = "sound"

    quality = on_original_summary.get("quality", "good")
    on_orig_failed = on_original_summary.get("failed", 0)

    if quality == "broken":
        status = "inconclusive"
        notes.append(
            "original-replay baseline is broken (malicious tx or majority of "
            "txs do not reproduce on-chain behaviour)"
        )
    elif quality == "partial":
        notes.append(
            f"{on_orig_failed} tx(s) lack a trustworthy original-replay "
            "baseline (excluded from patch verdict)"
        )

    if malicious_entry is None:
        notes.append("malicious tx not present in tx set")
    else:
        cat = malicious_entry.get("category")
        if cat == "patch_blocked_attack":
            notes.append("malicious tx blocked by patch")
        elif cat == "malicious_not_blocked":
            notes.append("malicious tx still succeeds under patch")
            status = "unsound"
        elif cat and cat.startswith("on_original_unreliable_"):
            reason = cat.split("on_original_unreliable_", 1)[1]
            notes.append(
                f"malicious tx baseline unreliable ({reason}); cannot "
                "conclude on patch effectiveness"
            )
            if status == "sound":
                status = "inconclusive"
        elif cat == "expected_revert":
            notes.append(
                "malicious tx replays as revert under both variants (chain "
                "also reverted)"
            )
        else:
            notes.append(f"malicious tx classified as {cat}")
            if malicious_entry.get("patch_local_reverted") is False:
                status = "unsound"

    if suspicious_count > 0:
        notes.append(
            f"{suspicious_count} benign tx(s) revert under patch but not "
            "under original (and chain didn't revert) — patch breaks "
            "legitimate behaviour"
        )
        status = "unsound"

    if replay_failures > 0 and status == "sound":
        status = "inconclusive"
        notes.append(f"{replay_failures} txs failed to replay cleanly")

    return {"status": status, "notes": notes}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _write_summary_md(summary: Dict[str, Any], path: Path) -> None:
    lines: List[str] = []
    lines.append("# PonDeReplay DFHL full-experiment summary\n")
    totals = summary["totals"]
    lines.append(
        f"- **Cases analyzed**: {totals['cases']}  "
        f"(sound: {totals['cases_sound']}, "
        f"unsound: {totals['cases_unsound']}, "
        f"inconclusive: {totals['cases_inconclusive']})"
    )
    lines.append(
        f"- **Transactions analyzed**: {totals['txs']}  "
        f"(orig pass {totals['orig_local_passed']}/{totals['txs']}, "
        f"patch pass {totals['patch_local_passed']}/{totals['txs']})"
    )
    oo = totals.get("on_original") or {}
    cats = totals.get("categories") or {}
    lines.append(
        f"- **on_original sanity** (original replay matches chain): "
        f"{oo.get('ok', 0)}/{totals['txs']} ok, "
        f"{oo.get('failed', 0)} failed "
        f"(OOG: {oo.get('failed_oog', 0)}, "
        f"timestamp: {oo.get('failed_timestamp_risk', 0)}, "
        f"mismatch: {oo.get('failed_status_mismatch', 0)})"
    )
    lines.append(
        f"- **Cases by on_original quality**: "
        f"good={oo.get('cases_quality_good', 0)}, "
        f"partial={oo.get('cases_quality_partial', 0)}, "
        f"broken={oo.get('cases_quality_broken', 0)}"
    )
    lines.append(
        f"- **Patch blocked attack** (on_original ok): "
        f"{cats.get('patch_blocked_attack', 0)}"
    )
    lines.append(
        f"- **Patch breaks benign** (on_original ok): "
        f"{cats.get('patch_breaks_benign', 0)}"
    )
    lines.append(
        f"- **Malicious not blocked** (on_original ok): "
        f"{cats.get('malicious_not_blocked', 0)}"
    )
    lines.append("")

    lines.append("## Per-case results\n")
    lines.append(
        "| Case | Verdict | on_original | Txs | Orig pass | Patch pass | "
        "Malicious | patch_breaks_benign |"
    )
    lines.append(
        "|------|---------|-------------|-----|-----------|------------|"
        "-----------|---------------------|"
    )
    for case in summary["cases"]:
        cid = case["case_id"]
        verdict = case["verdict"]["status"]
        t = case["totals"]
        oo_case = case.get("on_original") or {}
        quality = oo_case.get("quality", "?")
        malicious = case.get("malicious_entry")
        if malicious is None:
            malicious_cell = "—"
        else:
            malicious_cell = malicious.get("category", "?")
        suspicious = len(case.get("suspicious_txs") or [])
        lines.append(
            f"| {cid} | {verdict} | {quality} | {t['txs']} | "
            f"{t['orig_local_passed']}/{t['txs']} | "
            f"{t['patch_local_passed']}/{t['txs']} | "
            f"{malicious_cell} | {suspicious} |"
        )
    lines.append("")

    on_original_fail_cases = [
        c for c in summary["cases"]
        if (c.get("on_original") or {}).get("failed", 0) > 0
    ]
    if on_original_fail_cases:
        lines.append("## on_original failures (replay ≠ chain on original bytecode)\n")
        for case in on_original_fail_cases:
            oo_case = case.get("on_original") or {}
            lines.append(
                f"### {case['case_id']} "
                f"({oo_case.get('failed', 0)} failed, quality={oo_case.get('quality')})"
            )
            for failure in oo_case.get("failures") or []:
                tx = failure.get("tx_hash", "?")
                reason = failure.get("reason", "?")
                remediation = failure.get("remediation") or ""
                lines.append(
                    f"- `{tx}` — {reason}"
                    + (f" → {remediation}" if remediation else "")
                )
            lines.append("")

    suspicious_cases = [
        c for c in summary["cases"] if c.get("suspicious_txs")
    ]
    if suspicious_cases:
        lines.append("## Patch breaks benign (on_original ok)\n")
        for case in suspicious_cases:
            lines.append(f"### {case['case_id']}")
            for tx in case["suspicious_txs"]:
                msg = tx.get("patch_revert_message") or "(no revert message)"
                sig = tx.get("canonical_sig") or tx.get("selector") or ""
                lines.append(
                    f"- `{tx['tx_hash']}` `{sig}` — patch revert: {msg}"
                )
            lines.append("")

    for case in summary["cases"]:
        if case["verdict"]["status"] == "sound":
            continue
        notes = "; ".join(case["verdict"]["notes"])
        lines.append(f"- **{case['case_id']}** ({case['verdict']['status']}): {notes}")
    lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a full PonDeReplay experiment on the dfhl-invariants dataset"
    )
    parser.add_argument(
        "--dataset-info",
        default=str(DEFAULT_DATASET_INFO),
        help="Path to dataset-info.json",
    )
    parser.add_argument(
        "--dfhl-root",
        default=str(DEFAULT_DFHL_ROOT),
        help="Path to the dfhl-invariants repo root",
    )
    parser.add_argument(
        "--results-dir",
        default=str(DEFAULT_RESULTS_DIR),
        help="Where to write per-case outputs and summary.json",
    )
    parser.add_argument(
        "--only",
        nargs="*",
        default=None,
        help="Restrict to these case IDs",
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        default=[],
        help="Skip these case IDs",
    )
    parser.add_argument(
        "--limit-tx",
        type=int,
        default=None,
        help="Optional cap on number of txs per case (for smoke runs)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose progress",
    )
    parser.add_argument(
        "--skip-existing",
        action="store_true",
        help=(
            "Reuse <case>/{original,patch}/replay-result.json when present "
            "instead of running the replay again."
        ),
    )
    parser.add_argument(
        "--reclassify-only",
        action="store_true",
        help=(
            "Skip all replays. Only re-read existing replay-result.json files "
            "and re-generate soundness.json + summary.json/.md. Useful when "
            "the classifier rules change."
        ),
    )
    parser.add_argument(
        "--bump-gas-for-original",
        action="store_true",
        help=(
            "Also re-estimate gas on the original variant when Anvil is used. "
            "The patch variant always bumps gas automatically."
        ),
    )
    parser.add_argument(
        "--strict-anvil",
        action="store_true",
        help=(
            "Force the Anvil-strict path (sequential same-timestamp replay) "
            "instead of fast eth_call. Use this for time-sensitive cases "
            "where the preflight warned about a time/context mismatch risk."
        ),
    )
    parser.add_argument(
        "--variants",
        nargs="+",
        choices=["original", "patch"],
        default=["original", "patch"],
        help="Which variants to run (default both).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Re-run variants even if their replay-result.json exists "
            "(overrides --skip-existing for the requested variants/cases)."
        ),
    )
    args = parser.parse_args()

    load_dotenv(dotenv_path=REPO_ROOT / ".env", override=False)

    rpc_url = os.environ.get("ETH_RPC_URL")
    if not rpc_url:
        print("ETH_RPC_URL must be set (in .env or env).", file=sys.stderr)
        return 1

    dataset_info = _load_json(Path(args.dataset_info).resolve())
    dfhl_root = Path(args.dfhl_root).resolve()
    dfhl_src = dfhl_root / "src"
    results_dir = Path(args.results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)

    cases = _eligible_cases(
        dataset_info=dataset_info,
        dfhl_src=dfhl_src,
        only_ids=args.only,
        skip_ids=args.skip or [],
    )
    if not cases:
        print("No eligible cases found.", file=sys.stderr)
        return 1

    print(
        f"Eligible cases ({len(cases)}): "
        + ", ".join(c["id"] for c in cases),
        file=sys.stderr,
    )

    batch: Optional[BatchReplayer] = None
    if not args.reclassify_only:
        batch = BatchReplayer(
            rpc_url=rpc_url,
            strict_anvil_context=args.strict_anvil,
        )

    summary: Dict[str, Any] = {
        "meta": {
            "dataset_info": str(args.dataset_info),
            "dfhl_root": str(dfhl_root),
            "results_dir": str(results_dir),
            "rpc_url": rpc_url,
            "limit_tx": args.limit_tx,
        },
        "cases": [],
        "totals": {
            "cases": 0,
            "cases_sound": 0,
            "cases_unsound": 0,
            "cases_inconclusive": 0,
            "txs": 0,
            "orig_local_passed": 0,
            "orig_local_failed": 0,
            "patch_local_passed": 0,
            "patch_local_failed": 0,
            "malicious_present": 0,
            "on_original": {
                "ok": 0,
                "failed": 0,
                "failed_oog": 0,
                "failed_timestamp_risk": 0,
                "failed_status_mismatch": 0,
                "failed_replay_error": 0,
                "cases_quality_good": 0,
                "cases_quality_partial": 0,
                "cases_quality_broken": 0,
            },
            "categories": {},
        },
    }

    for case in cases:
        cid = case["id"]
        case_out = results_dir / cid
        case_out.mkdir(parents=True, exist_ok=True)

        tx_records = case["tx_records"]

        # In reclassify mode we replay nothing; restrict to the txs actually
        # replayed previously, inferred from the replay-result.json files
        # which are the ground truth for what was executed.
        if args.reclassify_only:
            replayed_keys: set = set()
            for variant_name in ("original", "patch"):
                rr_path = case_out / variant_name / "replay-result.json"
                if not rr_path.exists():
                    continue
                try:
                    rr = _load_json(rr_path)
                except Exception:
                    continue
                if not isinstance(rr, dict):
                    continue
                results_block = rr.get("results")
                if isinstance(results_block, dict):
                    for h in results_block.keys():
                        if isinstance(h, str):
                            replayed_keys.add(h.lower())
            if replayed_keys:
                tx_records = {
                    k: v for k, v in tx_records.items() if k in replayed_keys
                }
                case["tx_records"] = tx_records

        if args.limit_tx is not None and len(tx_records) > args.limit_tx:
            keep = list(tx_records.keys())[: args.limit_tx]
            if case.get("malicious_tx"):
                mal = case["malicious_tx"].lower()
                if mal not in keep and mal in tx_records:
                    keep[-1] = mal
            tx_records = {k: tx_records[k] for k in keep}
            case["tx_records"] = tx_records

        tx_hashes = [r["tx_hash"] for r in tx_records.values()]

        _write_json(case_out / "txs.json", tx_hashes)
        _write_json(
            case_out / "tx_metadata.json",
            {
                "case_id": cid,
                "contract_address": case["contract_address"],
                "proxy_address": case.get("proxy_address"),
                "malicious_tx": case.get("malicious_tx"),
                "tx_records": list(tx_records.values()),
            },
        )

        print(
            f"\n=== {cid} — {len(tx_hashes)} txs on {case['contract_address']} ===",
            file=sys.stderr,
        )

        orig_report: Optional[Dict[str, Any]] = None
        patch_report: Optional[Dict[str, Any]] = None

        for variant, hex_path in (
            ("original", case["original_hex"]),
            ("patch", case["patch_hex"]),
        ):
            if variant not in args.variants:
                # Reuse whatever exists for variants we're not running this pass.
                variant_dir = case_out / variant
                existing = variant_dir / "replay-result.json"
                if existing.exists():
                    try:
                        report = _load_json(existing)
                        if isinstance(report, dict):
                            if variant == "original":
                                orig_report = report
                            else:
                                patch_report = report
                    except Exception:
                        pass
                continue

            variant_dir = case_out / variant
            existing = variant_dir / "replay-result.json"
            reuse = (args.reclassify_only or args.skip_existing) and not args.force

            if reuse and existing.exists():
                try:
                    report = _load_json(existing)
                    if isinstance(report, dict) and (
                        args.reclassify_only
                        or report.get("total") == len(tx_hashes)
                    ):
                        if args.verbose:
                            print(
                                f"   [{variant}] reusing existing {existing}",
                                file=sys.stderr,
                            )
                        if variant == "original":
                            orig_report = report
                        else:
                            patch_report = report
                        continue
                except Exception:
                    pass

            if args.reclassify_only:
                print(
                    f"   [{variant}] no existing replay-result.json — skipping case",
                    file=sys.stderr,
                )
                continue

            try:
                assert batch is not None
                report = _run_variant(
                    variant=variant,
                    batch=batch,
                    tx_hashes=tx_hashes,
                    contract_address=case["contract_address"],
                    bytecode_path=hex_path,
                    output_dir=variant_dir,
                    attack_tx=case.get("malicious_tx"),
                    verbose=args.verbose,
                    bump_gas_for_original=args.bump_gas_for_original,
                )
            except Exception as exc:
                traceback.print_exc()
                print(
                    f"   [{variant}] FAILED: {exc}",
                    file=sys.stderr,
                )
                report = None

            if variant == "original":
                orig_report = report
            else:
                patch_report = report

        if orig_report is None or patch_report is None:
            summary["cases"].append(
                {
                    "case_id": cid,
                    "contract_address": case["contract_address"],
                    "malicious_tx": case.get("malicious_tx"),
                    "verdict": {
                        "status": "error",
                        "notes": ["one or both variant runs failed"],
                    },
                    "totals": {
                        "txs": len(tx_hashes),
                        "orig_local_passed": 0,
                        "orig_local_failed": 0,
                        "patch_local_passed": 0,
                        "patch_local_failed": 0,
                        "orig_unfaithful_count": 0,
                        "patch_unfaithful_count": 0,
                    },
                    "classifications": {},
                    "suspicious_txs": [],
                    "malicious_entry": None,
                    "tx_results": [],
                }
            )
            summary["totals"]["cases"] += 1
            continue

        analysis = _analyze_case(
            case=case,
            orig_report=orig_report,
            patch_report=patch_report,
        )
        _write_json(case_out / "soundness.json", analysis)

        summary["cases"].append(
            {
                **{
                    k: v
                    for k, v in analysis.items()
                    if k != "tx_results"
                },
                "tx_results_path": str(case_out / "soundness.json"),
            }
        )

        t = analysis["totals"]
        c = analysis["classifications"]
        oo = analysis["on_original"]
        totals = summary["totals"]
        totals["cases"] += 1
        if analysis["verdict"]["status"] == "sound":
            totals["cases_sound"] += 1
        elif analysis["verdict"]["status"] == "unsound":
            totals["cases_unsound"] += 1
        else:
            totals["cases_inconclusive"] += 1
        totals["txs"] += t["txs"]
        totals["orig_local_passed"] += t["orig_local_passed"]
        totals["orig_local_failed"] += t["orig_local_failed"]
        totals["patch_local_passed"] += t["patch_local_passed"]
        totals["patch_local_failed"] += t["patch_local_failed"]
        if analysis.get("malicious_tx"):
            totals["malicious_present"] += 1

        totals["on_original"]["ok"] += oo.get("ok", 0)
        totals["on_original"]["failed"] += oo.get("failed", 0)
        totals["on_original"][f"cases_quality_{oo.get('quality', 'good')}"] += 1
        for failure in oo.get("failures", []):
            reason = failure.get("reason") or "other"
            key = f"failed_{reason}"
            totals["on_original"].setdefault(key, 0)
            totals["on_original"][key] += 1

        for cat, n in c.items():
            totals["categories"].setdefault(cat, 0)
            totals["categories"][cat] += n

        print(
            f"   verdict: {analysis['verdict']['status']} "
            f"(orig pass {t['orig_local_passed']}/{t['txs']}, "
            f"patch pass {t['patch_local_passed']}/{t['txs']}, "
            f"suspicious {len(analysis['suspicious_txs'])})",
            file=sys.stderr,
        )

    _write_json(results_dir / "summary.json", summary)
    _write_summary_md(summary, results_dir / "summary.md")

    print("\n=== Overall ===", file=sys.stderr)
    print(json.dumps(summary["totals"], indent=2), file=sys.stderr)
    print(f"\nReports written under {results_dir}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

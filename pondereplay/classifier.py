"""
Scientific classification of patch replay outcomes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .replayer import ReplayResult


def classify_patch_effect(
    original_replay: ReplayResult,
    patched_replay: ReplayResult,
    *,
    chain_tx_succeeded: bool = True,
    is_attack_tx: bool = False,
) -> str:
    """
    Classify patch experiment outcome.

    Returns one of:
    - effective_patch
    - ineffective_patch
    - unfaithful_replay
    - inconclusive
    """
    orig_diag = (original_replay.diagnostics or {}).get("faithfulness", "approximate")
    patch_diag = (patched_replay.diagnostics or {}).get("faithfulness", "approximate")

    def _faithful_mode(mode: str) -> bool:
        return "same_block" in mode or mode.startswith("anvil_indexed")

    if (original_replay.diagnostics or {}).get("same_block_setup_required"):
        if not _faithful_mode(original_replay.replay_mode) or not _faithful_mode(
            patched_replay.replay_mode
        ):
            return "unfaithful_replay"

    if is_attack_tx:
        if chain_tx_succeeded and not original_replay.success:
            return "inconclusive"
        if chain_tx_succeeded and original_replay.success and not patched_replay.success:
            patch_diag = patched_replay.diagnostics or {}
            if patch_diag.get("local_failure_reason") == "out_of_gas":
                return "inconclusive"
            if patch_diag.get("trace_out_of_gas_on_impl"):
                return "inconclusive"
            return "effective_patch"
        if chain_tx_succeeded and original_replay.success and patched_replay.success:
            return "ineffective_patch"
        if not chain_tx_succeeded:
            return "inconclusive"
        return "inconclusive"

    # Benign tx: patch should preserve success
    if original_replay.success and patched_replay.success:
        return "ineffective_patch"
    if original_replay.success and not patched_replay.success:
        patch_diag = patched_replay.diagnostics or {}
        if patch_diag.get("local_failure_reason") == "out_of_gas":
            return "inconclusive"
        if patch_diag.get("trace_out_of_gas_on_impl"):
            return "inconclusive"
        return "effective_patch"
    if not original_replay.success and not patched_replay.success:
        return "inconclusive"
    return "inconclusive"


def build_classification_report(
    original: ReplayResult,
    patched: ReplayResult,
    *,
    chain_tx_succeeded: bool = True,
    is_attack_tx: bool = False,
    trace_summary: Optional[Dict[str, Any]] = None,
    include_trace: bool = False,
) -> Dict[str, Any]:
    """Build a JSON-serializable classification report."""
    classification = classify_patch_effect(
        original,
        patched,
        chain_tx_succeeded=chain_tx_succeeded,
        is_attack_tx=is_attack_tx,
    )
    report: Dict[str, Any] = {
        "classification": classification,
        "is_attack_tx": is_attack_tx,
        "chain_tx_succeeded": chain_tx_succeeded,
        "original": {
            "success": original.success,
            "error": original.error,
            "faithfulness": (original.diagnostics or {}).get("faithfulness"),
            "replay_mode": original.replay_mode,
        },
        "patched": {
            "success": patched.success,
            "error": patched.error,
            "faithfulness": (patched.diagnostics or {}).get("faithfulness"),
            "replay_mode": patched.replay_mode,
        },
    }
    if include_trace and trace_summary:
        report["trace"] = trace_summary
    return report

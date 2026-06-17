"""
Scientific classification of patch replay outcomes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from .replayer import ReplayResult


def _state_says_diverged(state: Optional[Dict[str, Any]]) -> Optional[bool]:
    """
    Resolve the state-comparison axis to a tri-state from the **test** (patched-replay
    vs original-replay), which is the sound, same-context comparison.

    Returns:
    - None  -> no usable state signal (capture unavailable)
    - True  -> patched state differs from original (critical divergence)
    - False -> patched state matches original

    The live-state diff is handled separately as the *structural* reproduction check (see
    ``_chain_not_reproduced``); it is not part of this signal, because comparing the
    local fork against real chain induces benign value drift (interest accrual) that the
    same-context test cancels (see docs/state-comparison.md).
    """
    if not state or not state.get("available"):
        return None
    eq = state.get("state_equivalent")
    if eq is None:
        return None
    return not eq


def _chain_not_reproduced(state: Optional[Dict[str, Any]]) -> bool:
    """
    True if the STRUCTURAL reproduction check failed (original replay diverged from live
    chain in status / account-scope / code — i.e. did not reproduce reality). Value-level
    accrual drift is tolerated, so this does not fire on benign drift.

    Load-bearing only where the verdict depends on the state comparison (the both-succeed
    branches); a clean top-level status flip is decided by status alone.
    """
    return bool(
        state and state.get("available") and state.get("reproduces_chain") is False
    )


def classify_patch_effect(
    original_replay: ReplayResult,
    patched_replay: ReplayResult,
    *,
    chain_tx_succeeded: bool = True,
    is_attack_tx: bool = False,
    state: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Classify patch experiment outcome. Labels are kind-specific so the *quality* of an
    outcome is never ambiguous (the old shared ``ineffective_patch`` meant "good" for
    benign but "bad" for attack):

    Benign tx (patch should preserve the live behaviour):
    - ``preserved``        — replay reproduces chain AND the patch changed nothing
    - ``needs_inspection`` — the patch changed a benign tx (status or state); inspect (it
                             may be a mislabeled malicious tx or a real regression)
    - ``inconclusive``     — replay not faithful, can't judge

    Attack tx (patch should change/neutralise the exploit):
    - ``effective_patch``   — exploit blocked (top-level revert, or its state effect gone)
    - ``ineffective_patch`` — exploit still lands unchanged
    - ``inconclusive``      — replay didn't reproduce the exploit

    Plus ``unfaithful_replay`` when same-block setup wasn't honoured.

    ``state`` is the optional state-comparison result (see ``state_compare``): the
    same-context test (``state_equivalent``) decides whether the patch changed the state
    effect, and the structural reproduction check (``reproduces_chain``) decides whether
    the original replay reproduced reality.
    """

    def _faithful_mode(mode: str) -> bool:
        return "same_block" in mode or mode.startswith("anvil_indexed")

    if (original_replay.diagnostics or {}).get("same_block_setup_required"):
        if not _faithful_mode(original_replay.replay_mode) or not _faithful_mode(
            patched_replay.replay_mode
        ):
            return "unfaithful_replay"

    diverged = _state_says_diverged(state)
    chain_not_reproduced = _chain_not_reproduced(state)

    if is_attack_tx:
        if chain_tx_succeeded and not original_replay.success:
            return "inconclusive"
        if (
            chain_tx_succeeded
            and original_replay.success
            and not patched_replay.success
        ):
            patch_diag = patched_replay.diagnostics or {}
            if patch_diag.get("local_failure_reason") == "out_of_gas":
                return "inconclusive"
            if patch_diag.get("trace_out_of_gas_on_impl"):
                return "inconclusive"
            return "effective_patch"
        if chain_tx_succeeded and original_replay.success and patched_replay.success:
            # Top-level status unchanged: only the same-context state test can tell
            # whether the exploit's effect was neutralized (e.g. a reverted sub-call the
            # attacker swallowed). Here the reproduction check is load-bearing: if the
            # original replay didn't structurally reproduce live, we can't conclude.
            if diverged is True:
                return "effective_patch"
            if chain_not_reproduced:
                return "inconclusive"
            return "ineffective_patch"
        if not chain_tx_succeeded:
            return "inconclusive"
        return "inconclusive"

    # Benign tx: the patch should preserve the live behaviour. "preserved" requires the
    # replay to reproduce chain AND the patch to change nothing (test). Any change
    # the patch introduces — a different state effect, or breaking the tx by reverting —
    # is flagged for manual inspection (could be a mislabeled malicious tx).
    if not original_replay.success:
        return "inconclusive"  # replay didn't reproduce the benign tx
    if not patched_replay.success:
        patch_diag = patched_replay.diagnostics or {}
        if patch_diag.get("local_failure_reason") == "out_of_gas":
            return "inconclusive"
        if patch_diag.get("trace_out_of_gas_on_impl"):
            return "inconclusive"
        return "needs_inspection"  # patch broke a benign tx (now reverts)
    # Both succeed.
    if chain_not_reproduced:
        return "inconclusive"  # original replay did not reproduce chain
    if diverged is True:
        return "needs_inspection"  # patch changed the state effect of a benign tx
    return "preserved"


def build_classification_report(
    original: ReplayResult,
    patched: ReplayResult,
    *,
    chain_tx_succeeded: bool = True,
    is_attack_tx: bool = False,
    trace_summary: Optional[Dict[str, Any]] = None,
    include_trace: bool = False,
    state: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a JSON-serializable classification report."""
    classification = classify_patch_effect(
        original,
        patched,
        chain_tx_succeeded=chain_tx_succeeded,
        is_attack_tx=is_attack_tx,
        state=state,
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
    if state is not None:
        report["state_comparison"] = state
    if include_trace and trace_summary:
        report["trace"] = trace_summary
    return report

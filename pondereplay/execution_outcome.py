"""
Normalize on-chain vs local execution outcome (revert status and messages).
"""

from __future__ import annotations

from typing import Any, Dict, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .replayer import ReplayResult


def _status_to_reverted(status: Optional[int]) -> Optional[bool]:
    if status is None:
        return None
    return int(status) == 0


def build_execution_outcome(result: "ReplayResult") -> Dict[str, Any]:
    """
    Build a clear execution summary independent of faithfulness ``success``.
    """
    diag = result.diagnostics or {}
    onchain_status = diag.get("onchain_status")
    local_status = diag.get("local_status")

    if local_status is None:
        # eth_call replay: success means call returned without revert
        if result.replay_mode.startswith("eth_call"):
            local_status = 0 if result.error else 1
        elif result.error and "revert" in (result.error or "").lower():
            local_status = 0

    onchain_reverted = _status_to_reverted(onchain_status)
    local_reverted = _status_to_reverted(local_status)

    local_revert_message = None
    if local_reverted:
        local_revert_message = (
            diag.get("revert_message")
            or result.error
            or "execution reverted"
        )

    status_matches = None
    if onchain_status is not None and local_status is not None:
        status_matches = int(onchain_status) == int(local_status)

    return {
        "onchain_status": onchain_status,
        "local_status": local_status,
        "onchain_reverted": onchain_reverted,
        "local_reverted": local_reverted,
        "status_matches_onchain": status_matches,
        "local_revert_message": local_revert_message,
        "revert_data": diag.get("revert_data") if local_reverted else None,
        "revert_source": diag.get("revert_source") if local_reverted else None,
        # ``result.success`` means faithful replay (local matches chain context), not "tx succeeded"
        "faithful_to_chain": result.success,
        "local_failure_reason": infer_local_failure_reason(diag),
    }


def trace_impl_out_of_gas(
    trace_root: Dict[str, Any],
    impl_address: Optional[str],
) -> bool:
    """True if callTracer shows out-of-gas on the patched implementation."""
    if not isinstance(trace_root, dict) or not impl_address:
        return False
    impl_lower = impl_address.lower()

    def walk(node: Dict[str, Any]) -> bool:
        err = (node.get("error") or "").lower()
        to_addr = (node.get("to") or "").lower()
        call_type = (node.get("type") or "").upper()
        if err == "out of gas" and (
            to_addr == impl_lower or call_type == "DELEGATECALL"
        ):
            if to_addr == impl_lower:
                return True
        for child in node.get("calls") or []:
            if isinstance(child, dict) and walk(child):
                return True
        return False

    return walk(trace_root)


def infer_local_failure_reason(diagnostics: Dict[str, Any]) -> Optional[str]:
    """
    Distinguish patch semantic failure from replay artifacts (e.g. out-of-gas).
    """
    if diagnostics.get("local_status") == 1:
        return None
    if diagnostics.get("local_failure_reason"):
        return diagnostics["local_failure_reason"]
    msg = (diagnostics.get("revert_message") or "").lower()
    if "out of gas" in msg or diagnostics.get("trace_out_of_gas_on_impl"):
        return "out_of_gas"
    if diagnostics.get("patch_guard_would_block") or "borrower is solvent" in msg:
        return "patch_guard"
    return "revert_other"


def apply_execution_outcome(result: "ReplayResult") -> "ReplayResult":
    """Write execution fields into diagnostics and return result."""
    outcome = build_execution_outcome(result)
    diag = dict(result.diagnostics or {})
    failure_reason = infer_local_failure_reason(diag)
    if failure_reason:
        outcome["local_failure_reason"] = failure_reason
        diag["local_failure_reason"] = failure_reason
    diag["execution"] = outcome
    diag["onchain_status"] = outcome.get("onchain_status", diag.get("onchain_status"))
    if outcome.get("local_status") is not None:
        diag["local_status"] = outcome["local_status"]
    result.diagnostics = diag
    return result

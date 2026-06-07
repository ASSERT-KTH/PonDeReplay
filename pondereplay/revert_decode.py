"""
Decode revert reasons from RPC errors, eth_call data, and callTracer output.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

ERROR_STRING_SELECTOR = "08c379a0"

# AlkemiEarn ErrorReporter.Error enum (subset used in messages)
ALKEMI_ERROR_NAMES: Dict[int, str] = {
    0: "NO_ERROR",
    1: "OPAQUE_ERROR",
    2: "UNAUTHORIZED",
    3: "INTEGER_OVERFLOW",
    4: "INTEGER_UNDERFLOW",
    5: "DIVISION_BY_ZERO",
    6: "BAD_INPUT",
    7: "TOKEN_INSUFFICIENT_ALLOWANCE",
    8: "TOKEN_INSUFFICIENT_BALANCE",
    9: "TOKEN_TRANSFER_FAILED",
    10: "MARKET_NOT_SUPPORTED",
    11: "SUPPLY_RATE_CALCULATION_FAILED",
    12: "BORROW_RATE_CALCULATION_FAILED",
    13: "TOKEN_INSUFFICIENT_CASH",
    14: "TOKEN_TRANSFER_OUT_FAILED",
    15: "INSUFFICIENT_LIQUIDITY",
    16: "INSUFFICIENT_BALANCE",
    17: "INVALID_COLLATERAL_RATIO",
    18: "MISSING_ASSET_PRICE",
    19: "EQUITY_INSUFFICIENT_BALANCE",
    20: "INVALID_CLOSE_AMOUNT_REQUESTED",
    21: "ASSET_NOT_PRICED",
    22: "INVALID_LIQUIDATION_DISCOUNT",
    23: "INVALID_COMBINED_RISK_PARAMETERS",
    24: "ZERO_ORACLE_ADDRESS",
    25: "CONTRACT_PAUSED",
    26: "KYC_ADMIN_CHECK_FAILED",
    27: "KYC_ADMIN_ADD_OR_DELETE_ADMIN_CHECK_FAILED",
    28: "KYC_CUSTOMER_VERIFICATION_CHECK_FAILED",
    29: "LIQUIDATOR_CHECK_FAILED",
    30: "LIQUIDATOR_ADD_OR_DELETE_ADMIN_CHECK_FAILED",
    31: "SET_WETH_ADDRESS_ADMIN_CHECK_FAILED",
    32: "WETH_ADDRESS_NOT_SET_ERROR",
    33: "ETHER_AMOUNT_MISMATCH_ERROR",
}


@dataclass
class RevertDetails:
    message: str
    data: Optional[str] = None
    source: str = "unknown"  # eth_call | trace | rpc_message


def decode_error_string(data_hex: str) -> Optional[str]:
    """Decode standard Solidity Error(string) revert data (0x08c379a0)."""
    if not data_hex:
        return None
    h = data_hex[2:].lower() if data_hex.startswith("0x") else data_hex.lower()
    if len(h) < 8 or h[:8] != ERROR_STRING_SELECTOR:
        return None
    try:
        # ABI: selector (4) + offset (32) + length (32) + string bytes
        if len(h) < 8 + 64 + 64:
            return None
        length = int(h[8 + 64 : 8 + 64 + 64], 16)
        str_start = 8 + 64 + 64
        str_hex = h[str_start : str_start + length * 2]
        if not str_hex:
            return None
        return bytes.fromhex(str_hex).decode("utf-8", errors="replace").strip("\x00")
    except (ValueError, IndexError):
        return None


def decode_alkemi_error_code(data_hex: str) -> Optional[str]:
    """Decode 32-byte Alkemi-style `fail(Error)` return/revert data (uint256 err code)."""
    if not data_hex:
        return None
    h = data_hex[2:].lower() if data_hex.startswith("0x") else data_hex.lower()
    if len(h) != 64:
        return None
    if decode_error_string(data_hex):
        return None
    try:
        code = int(h, 16)
    except ValueError:
        return None
    if code == 0:
        return None
    name = ALKEMI_ERROR_NAMES.get(code)
    if name:
        return f"AlkemiEarn Error.{name} ({code})"
    return f"AlkemiEarn error code {code}"


def _frame_failed(node: Dict[str, Any]) -> bool:
    err = node.get("error")
    if isinstance(err, str) and err.strip() and err.lower() not in ("none",):
        return True
    revert_reason = node.get("revertReason")
    return isinstance(revert_reason, str) and bool(revert_reason.strip())


def _normalize_trace_error(err: str) -> str:
    e = err.strip()
    low = e.lower()
    if low in ("revert", "reverted"):
        return "execution reverted"
    if low == "out of gas":
        return "out of gas"
    if low.startswith("execution reverted"):
        return e
    return e


def _message_from_frame(
    node: Dict[str, Any],
    *,
    only_revert_output: bool = True,
) -> Tuple[Optional[str], Optional[str]]:
    """Return (display_message, data_hex) from a callTracer node."""
    err = node.get("error")
    revert_reason = node.get("revertReason")
    output = node.get("output") or ""
    data_hex = output if isinstance(output, str) and output.startswith("0x") else None

    if isinstance(revert_reason, str) and revert_reason.strip():
        msg = revert_reason.strip()
        if not msg.startswith("execution reverted"):
            msg = f"execution reverted: {msg}"
        return msg, data_hex

    if isinstance(err, str) and err.strip() and err.lower() not in ("none",):
        norm = _normalize_trace_error(err)
        decoded = decode_error_string(data_hex) if data_hex else None
        if decoded:
            return f"execution reverted: {decoded}", data_hex
        alkemi = decode_alkemi_error_code(data_hex) if data_hex else None
        if alkemi and norm == "execution reverted":
            return f"execution reverted: {alkemi}", data_hex
        if norm == "execution reverted" and data_hex:
            formatted = format_revert_message(data_hex, norm)
            if formatted:
                return formatted, data_hex
        return norm, data_hex

    if only_revert_output:
        return None, None

    decoded = decode_error_string(data_hex) if data_hex else None
    if decoded:
        return f"execution reverted: {decoded}", data_hex
    return None, data_hex


def _extract_data_hex_from_obj(obj: Any) -> Optional[str]:
    if obj is None:
        return None
    if isinstance(obj, dict):
        data = obj.get("data")
        if isinstance(data, str) and data.startswith("0x") and len(data) > 2:
            return data
        err = obj.get("error")
        if isinstance(err, dict):
            return _extract_data_hex_from_obj(err)
        return None
    if isinstance(obj, (list, tuple)) and len(obj) >= 1:
        return _extract_data_hex_from_obj(obj[0])
    # web3 ContractLogicError often has .data or args
    data = getattr(obj, "data", None)
    if isinstance(data, str) and data.startswith("0x"):
        return data
    if hasattr(data, "hex"):
        hx = data.hex()
        return hx if hx.startswith("0x") else "0x" + hx
    return None


def _extract_rpc_message(obj: Any) -> Optional[str]:
    if isinstance(obj, dict):
        msg = obj.get("message")
        if isinstance(msg, str):
            return msg
        err = obj.get("error")
        if isinstance(err, dict):
            return _extract_rpc_message(err)
    msg = getattr(obj, "message", None) or getattr(obj, "args", None)
    if isinstance(msg, str):
        return msg
    if isinstance(msg, (list, tuple)) and msg:
        first = msg[0]
        if isinstance(first, str):
            return first
    s = str(obj)
    m = re.search(r"execution reverted(?::\s*(.+?))?(?:'|$)", s, re.DOTALL)
    if m:
        reason = (m.group(1) or "").strip().strip("'\"")
        if reason and not reason.startswith("0x"):
            return reason
    m2 = re.search(r"\bout of gas\b", s, re.IGNORECASE)
    if m2:
        return "out of gas"
    return None


def normalize_rpc_error(exc: Any) -> Tuple[Optional[str], Optional[str]]:
    """
    Return (rpc_message, data_hex) from assorted exception/RPC shapes.
    """
    data_hex = _extract_data_hex_from_obj(exc)
    rpc_message = _extract_rpc_message(exc)

    if isinstance(exc, str):
        if exc.startswith("0x") and len(exc) > 10:
            data_hex = data_hex or exc
        else:
            # Sometimes str(exc) is a dict repr
            try:
                parsed = ast_literal_or_json(exc)
                if parsed is not None:
                    d2, m2 = normalize_rpc_error(parsed)
                    data_hex = data_hex or d2
                    rpc_message = rpc_message or m2
            except Exception:
                rpc_message = rpc_message or exc

    return rpc_message, data_hex


def ast_literal_or_json(s: str) -> Any:
    import ast

    try:
        return ast.literal_eval(s)
    except (ValueError, SyntaxError):
        pass
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        return None


def format_revert_message(
    data_hex: Optional[str] = None,
    rpc_message: Optional[str] = None,
) -> Optional[str]:
    decoded = decode_error_string(data_hex) if data_hex else None
    if decoded:
        return f"execution reverted: {decoded}"
    alkemi = decode_alkemi_error_code(data_hex) if data_hex else None
    if alkemi:
        return f"execution reverted: {alkemi}"
    if rpc_message:
        if rpc_message.startswith("execution reverted") or rpc_message == "out of gas":
            return rpc_message
        return f"execution reverted: {rpc_message}"
    return None


def find_revert_in_call_trace(
    trace_root: Dict[str, Any],
    patched_address: Optional[str] = None,
) -> Optional[RevertDetails]:
    """
    Walk callTracer output; return the most informative failure frame.
    """
    patched_lower = patched_address.lower() if patched_address else None
    candidates: List[Tuple[int, int, int, RevertDetails]] = []

    def walk(node: Dict[str, Any], depth: int) -> None:
        if not _frame_failed(node):
            for child in node.get("calls") or []:
                if isinstance(child, dict):
                    walk(child, depth + 1)
            return

        to_addr = (node.get("to") or "").lower()
        call_type = (node.get("type") or "").upper()
        msg, data_hex = _message_from_frame(node, only_revert_output=True)

        priority = 0
        if patched_lower and to_addr == patched_lower:
            priority = 3
        elif call_type == "DELEGATECALL" and patched_lower:
            priority = 2

        specificity = 0
        err_raw = (node.get("error") or "").lower()
        if node.get("revertReason"):
            specificity = 4
        elif decode_error_string(data_hex or ""):
            specificity = 3
        elif err_raw == "out of gas":
            specificity = 3
        elif err_raw in ("revert", "reverted", "execution reverted"):
            specificity = 2
        elif msg and msg != "execution reverted":
            specificity = 2

        display = msg or "execution reverted"
        candidates.append(
            (
                specificity,
                depth,
                priority,
                RevertDetails(message=display, data=data_hex, source="trace"),
            )
        )

        for child in node.get("calls") or []:
            if isinstance(child, dict):
                walk(child, depth + 1)

    if isinstance(trace_root, dict):
        walk(trace_root, 0)

        # Frames with Error(string) output even if callTracer omits error on child
        def walk_abi_strings(node: Dict[str, Any], depth: int) -> None:
            output = node.get("output") or ""
            if isinstance(output, str) and output.startswith("0x"):
                decoded = decode_error_string(output)
                if decoded:
                    to_addr = (node.get("to") or "").lower()
                    priority = 3 if patched_lower and to_addr == patched_lower else 0
                    candidates.append(
                        (
                            3,
                            depth,
                            priority,
                            RevertDetails(
                                message=f"execution reverted: {decoded}",
                                data=output,
                                source="trace",
                            ),
                        )
                    )
            for child in node.get("calls") or []:
                if isinstance(child, dict):
                    walk_abi_strings(child, depth + 1)

        walk_abi_strings(trace_root, 0)

    if not candidates:
        return None

    candidates.sort(key=lambda x: (x[0], x[1], x[2]), reverse=True)
    return candidates[0][3]


def _rpc_call(url: str, method: str, params: list) -> Any:
    import requests

    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    r = requests.post(url, json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data.get("result")


def resolve_revert_details(
    rpc_url: str,
    tx_params: Dict[str, Any],
    *,
    local_tx_hash: Optional[str] = None,
    patched_address: Optional[str] = None,
    fetch_trace: bool = True,
) -> RevertDetails:
    """
    Best-effort revert resolution: eth_call on latest, then callTracer on local tx.
    """
    rpc_message: Optional[str] = None
    data_hex: Optional[str] = None
    eth_call_formatted: Optional[str] = None

    try:
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(rpc_url))
        w3.eth.call(tx_params, "latest")
    except Exception as exc:
        rpc_message, data_hex = normalize_rpc_error(exc)
        eth_call_formatted = format_revert_message(data_hex, rpc_message)
        if eth_call_formatted and (
            decode_error_string(data_hex or "")
            or "execution reverted:" in eth_call_formatted
            or eth_call_formatted == "out of gas"
        ):
            return RevertDetails(
                message=eth_call_formatted,
                data=data_hex,
                source="eth_call",
            )

    if fetch_trace and local_tx_hash:
        try:
            trace = _rpc_call(
                rpc_url,
                "debug_traceTransaction",
                [local_tx_hash, {"tracer": "callTracer", "timeout": "60s"}],
            )
            if isinstance(trace, dict):
                found = find_revert_in_call_trace(trace, patched_address)
                if found and found.message:
                    return found
        except Exception:
            pass

    if eth_call_formatted:
        return RevertDetails(
            message=eth_call_formatted,
            data=data_hex,
            source="eth_call",
        )

    if rpc_message:
        return RevertDetails(
            message=format_revert_message(data_hex, rpc_message) or rpc_message,
            data=data_hex,
            source="rpc_message",
        )

    return RevertDetails(message="execution reverted", source="unknown")


def apply_revert_to_diagnostics(
    diagnostics: Dict[str, Any],
    details: RevertDetails,
) -> str:
    """Write revert fields into diagnostics; return message for ReplayResult.error."""
    diagnostics["revert_message"] = details.message
    if details.data:
        diagnostics["revert_data"] = details.data
    diagnostics["revert_source"] = details.source
    return details.message

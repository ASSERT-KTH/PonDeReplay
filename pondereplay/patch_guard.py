"""
Preflight checks for AlkemiEarn patch guard on liquidateBorrow.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from eth_abi import decode
from web3 import Web3

LIQUIDATE_BORROW_SELECTOR = "e61604cf"
PROXY_ADDRESS = "0x4822D9172e5b76b9Db37B75f5552F9988F98a888"


def _tx_input_hex(tx: dict) -> str:
    raw = tx.get("input") or b""
    if hasattr(raw, "hex"):
        return raw.hex()
    if isinstance(raw, str):
        return raw[2:] if raw.startswith("0x") else raw
    return bytes(raw).hex()


def parse_liquidate_borrow_target(tx: dict) -> Optional[str]:
    """Return targetAccount from liquidateBorrow calldata, if applicable."""
    inp = _tx_input_hex(tx)
    if len(inp) < 8 or inp[:8].lower() != LIQUIDATE_BORROW_SELECTOR:
        return None
    try:
        target, _, _, _ = decode(
            ["address", "address", "address", "uint256"],
            bytes.fromhex(inp[8:]),
        )
        return Web3.to_checksum_address(target)
    except Exception:
        return None


def get_account_liquidity(
    w3: Web3,
    proxy: str,
    account: str,
    block_identifier: int,
) -> Optional[int]:
    """AlkemiEarn getAccountLiquidity(address) → int256 (negative = underwater)."""
    sel = w3.keccak(text="getAccountLiquidity(address)")[:4]
    data = sel + bytes.fromhex(account[2:].lower().rjust(64, "0"))
    try:
        out = w3.eth.call(
            {"to": Web3.to_checksum_address(proxy), "data": data},
            block_identifier,
        )
        return int.from_bytes(out[:32], byteorder="big", signed=True)
    except Exception:
        return None


def analyze_patch_guard(
    w3: Web3,
    tx: dict,
    *,
    fork_block: int,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate whether the patch require(getAccountLiquidity(target) < 0) would revert.

    The revert message is "borrower is solvent" when liquidity >= 0 (borrower NOT underwater).
    """
    target = parse_liquidate_borrow_target(tx)
    if not target:
        return {"patch_guard_applies": False}

    proxy_addr = Web3.to_checksum_address(proxy or tx.get("to") or PROXY_ADDRESS)
    liquidity = get_account_liquidity(w3, proxy_addr, target, fork_block)
    if liquidity is None:
        return {
            "patch_guard_applies": True,
            "patch_guard_target": target,
            "patch_guard_liquidity": None,
            "patch_guard_would_block": None,
            "patch_guard_note": "Could not read getAccountLiquidity at fork block",
        }

    would_block = liquidity >= 0
    if would_block:
        note = (
            "Patch would revert with 'borrower is solvent' "
            f"(liquidity={liquidity} >= 0)"
        )
    else:
        note = (
            "Patch allows liquidation: borrower is underwater "
            f"(liquidity={liquidity} < 0)"
        )

    return {
        "patch_guard_applies": True,
        "patch_guard_target": target,
        "patch_guard_liquidity": liquidity,
        "patch_guard_would_block": would_block,
        "patch_guard_note": note,
    }

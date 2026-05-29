"""
Preflight diagnostics and pre-state relevance gate for transaction replay.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from web3 import Web3


@dataclass
class SameBlockCreation:
    """Contract created by an earlier transaction in the same block."""

    transaction_index: int
    contract_address: str
    creator_tx_hash: str


@dataclass
class PreflightDiagnostics:
    """Cheap checks before replay to detect unfaithful block-1 replay."""

    block_number: int
    transaction_index: int
    tx_to: Optional[str]
    tx_to_code_len_at_prev_block: int
    tx_to_code_len_at_block: int
    patched_address: str
    patched_code_len_at_prev_block: int
    same_block_setup_required: bool
    escalate_replay: bool
    faithfulness: str  # faithful | unfaithful | approximate
    onchain_status: Optional[int] = None
    prev_block_timestamp: Optional[int] = None
    block_timestamp: Optional[int] = None
    timestamp_delta_seconds: Optional[int] = None
    context_mismatch_risk: bool = False
    warnings: List[str] = field(default_factory=list)
    same_block_creations: List[SameBlockCreation] = field(default_factory=list)
    trace_touched_same_block_contracts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["same_block_creations"] = [asdict(c) for c in self.same_block_creations]
        return d


def _code_len(w3: Web3, address: Optional[str], block: int) -> int:
    if not address:
        return 0
    try:
        code = w3.eth.get_code(
            Web3.to_checksum_address(address), block_identifier=block
        )
        return len(code)
    except Exception:
        return 0


def _find_same_block_creations(
    w3: Web3, block_number: int, before_index: int
) -> List[SameBlockCreation]:
    """Scan earlier txs in the block for contract creations."""
    creations: List[SameBlockCreation] = []
    block = w3.eth.get_block(block_number, full_transactions=False)
    tx_hashes = block.get("transactions", [])
    for idx, tx_hash in enumerate(tx_hashes):
        if idx >= before_index:
            break
        h = tx_hash.hex() if hasattr(tx_hash, "hex") else tx_hash
        receipt = w3.eth.get_transaction_receipt(h)
        created = receipt.get("contractAddress")
        if created:
            creations.append(
                SameBlockCreation(
                    transaction_index=idx,
                    contract_address=Web3.to_checksum_address(created),
                    creator_tx_hash=h,
                )
            )
    return creations


def run_preflight(
    w3: Web3,
    tx: dict,
    receipt: dict,
    patched_address: str,
    trace_touched_addresses: Optional[Set[str]] = None,
) -> PreflightDiagnostics:
    """
    Run preflight diagnostics and decide whether same-block replay is needed.
    """
    block_number = int(tx["blockNumber"])
    tx_index = int(tx["transactionIndex"])
    tx_to = tx.get("to")
    if tx_to:
        tx_to = Web3.to_checksum_address(tx_to)
    patched_address = Web3.to_checksum_address(patched_address)

    prev_block = block_number - 1
    tx_to_prev = _code_len(w3, tx_to, prev_block)
    tx_to_at = _code_len(w3, tx_to, block_number)
    patched_prev = _code_len(w3, patched_address, prev_block)
    onchain_status = (
        int(receipt.get("status", 0)) if receipt.get("status") is not None else None
    )
    prev_ts: Optional[int] = None
    block_ts: Optional[int] = None
    ts_delta: Optional[int] = None
    context_mismatch_risk = False

    warnings: List[str] = []
    same_block_setup_required = False

    if tx_index > 0 and tx_to and tx_to_prev == 0 and tx_to_at > 0:
        same_block_setup_required = True
        warnings.append(
            f"tx.to {tx_to} has no code at block {prev_block} but has code at "
            f"block {block_number}; created earlier in same block"
        )

    same_block_creations: List[SameBlockCreation] = []
    if tx_index > 0:
        same_block_creations = _find_same_block_creations(w3, block_number, tx_index)

    trace_touched: List[str] = []
    if trace_touched_addresses and same_block_creations:
        creation_addrs = {c.contract_address.lower() for c in same_block_creations}
        for addr in trace_touched_addresses:
            if addr.lower() in creation_addrs:
                trace_touched.append(Web3.to_checksum_address(addr))
                if not same_block_setup_required:
                    same_block_setup_required = True
                    warnings.append(
                        f"Trace touches same-block deployed contract {addr}"
                    )

    escalate = same_block_setup_required

    if tx_index == 0 and tx_to_prev > 0 and not warnings:
        faithfulness = "faithful"
    elif same_block_setup_required:
        faithfulness = "unfaithful"
    elif tx_to_prev > 0:
        faithfulness = "approximate"
    else:
        faithfulness = "unfaithful"

    if patched_prev == 0:
        warnings.append(
            f"Patched address {patched_address} has no code at block {prev_block}"
        )
        if not escalate:
            escalate = True

    try:
        prev_ts = int(w3.eth.get_block(prev_block).get("timestamp", 0))
        block_ts = int(w3.eth.get_block(block_number).get("timestamp", 0))
        ts_delta = block_ts - prev_ts
        if ts_delta > 0:
            context_mismatch_risk = True
    except Exception:
        prev_ts = None
        block_ts = None
        ts_delta = None

    if context_mismatch_risk and onchain_status == 1:
        warnings.append(
            "Potential time/context mismatch risk: replay at block-1 may alter time-dependent checks"
        )

    return PreflightDiagnostics(
        block_number=block_number,
        transaction_index=tx_index,
        tx_to=tx_to,
        tx_to_code_len_at_prev_block=tx_to_prev,
        tx_to_code_len_at_block=tx_to_at,
        patched_address=patched_address,
        patched_code_len_at_prev_block=patched_prev,
        same_block_setup_required=same_block_setup_required,
        escalate_replay=escalate,
        faithfulness=faithfulness,
        onchain_status=onchain_status,
        prev_block_timestamp=prev_ts,
        block_timestamp=block_ts,
        timestamp_delta_seconds=ts_delta,
        context_mismatch_risk=context_mismatch_risk,
        warnings=warnings,
        same_block_creations=same_block_creations,
        trace_touched_same_block_contracts=trace_touched,
    )


def build_same_block_code_overrides(
    w3: Web3,
    diagnostics: PreflightDiagnostics,
    extra_addresses: Optional[Set[str]] = None,
) -> Dict[str, Dict[str, str]]:
    """
    Build state_override code entries for contracts that exist only after
    same-block setup transactions.
    """
    overrides: Dict[str, Dict[str, str]] = {}
    block = diagnostics.block_number
    addresses: Set[str] = set()

    if diagnostics.tx_to and diagnostics.tx_to_code_len_at_prev_block == 0:
        addresses.add(diagnostics.tx_to)

    for creation in diagnostics.same_block_creations:
        addresses.add(creation.contract_address)

    if extra_addresses:
        addresses.update(extra_addresses)

    for addr in addresses:
        code = w3.eth.get_code(addr, block_identifier=block)
        if len(code) > 0:
            hex_code = code.hex()
            if not hex_code.startswith("0x"):
                hex_code = "0x" + hex_code
            overrides[addr] = {"code": hex_code}

    return overrides

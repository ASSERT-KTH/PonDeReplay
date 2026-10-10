"""
Opcodes a patched bytecode uses that the replayed block's hardfork does not have yet.

A patch compiled for a recent ``evmVersion`` (e.g. ``SHR`` from Constantinople, ``PUSH0``
from Shanghai) halts with ``NotActivated`` when replayed at an older block. That is a
build-target artifact, not an effect of the patch logic, so it must not be read as the patch
changing (or blocking) the transaction.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

# opcode -> (name, hardfork that introduced it)
NEW_OPCODES: Dict[int, Tuple[str, str]] = {
    0x1B: ("SHL", "constantinople"),
    0x1C: ("SHR", "constantinople"),
    0x1D: ("SAR", "constantinople"),
    0x3F: ("EXTCODEHASH", "constantinople"),
    0xF5: ("CREATE2", "constantinople"),
    0x46: ("CHAINID", "istanbul"),
    0x47: ("SELFBALANCE", "istanbul"),
    0x48: ("BASEFEE", "london"),
    0x5F: ("PUSH0", "shanghai"),
    0x49: ("BLOBHASH", "cancun"),
    0x4A: ("BLOBBASEFEE", "cancun"),
    0x5C: ("TLOAD", "cancun"),
    0x5D: ("TSTORE", "cancun"),
    0x5E: ("MCOPY", "cancun"),
}

# chain id -> hardfork -> first block (Ethereum mainnet only; other chains are not judged)
ACTIVATION_BLOCKS: Dict[int, Dict[str, int]] = {
    1: {
        "constantinople": 7_280_000,
        "istanbul": 9_069_000,
        "london": 12_965_000,
        "shanghai": 17_034_870,
        "cancun": 19_426_587,
    },
}


def strip_metadata(code: bytes) -> bytes:
    """Drop solc's CBOR metadata trailer (a map, its length in the last 2 bytes): data, not code."""
    if len(code) < 2:
        return code
    n = int.from_bytes(code[-2:], "big")
    start = len(code) - 2 - n
    if 0 < n and start >= 0 and code[start] in (0xA1, 0xA2, 0xA3, 0xA4, 0xA5):
        return code[:start]
    return code


def used_opcodes(bytecode: str) -> List[int]:
    """Opcodes present in ``bytecode`` (hex, optional 0x), skipping PUSH immediates and
    solc's metadata trailer."""
    code = strip_metadata(bytes.fromhex(bytecode[2:] if bytecode.startswith("0x") else bytecode))
    seen: List[int] = []
    i = 0
    while i < len(code):
        op = code[i]
        if op not in seen:
            seen.append(op)
        i += 1 + (op - 0x5F if 0x60 <= op <= 0x7F else 0)
    return seen


def inactive_opcodes(
    bytecode: str, chain_id: Optional[int], block_number: int
) -> List[Dict[str, object]]:
    """
    Opcodes of ``bytecode`` not yet activated at ``block_number`` on ``chain_id``.

    Empty when the chain's schedule is unknown. The scan is static: a listed opcode may sit in
    code the transaction never reaches (or in metadata), so it explains a ``NotActivated``
    halt, it does not predict one.
    """
    schedule = ACTIVATION_BLOCKS.get(chain_id or -1)
    if not schedule:
        return []
    out: List[Dict[str, object]] = []
    for op in used_opcodes(bytecode):
        if op not in NEW_OPCODES:
            continue
        name, fork = NEW_OPCODES[op]
        first = schedule[fork]
        if block_number < first:
            out.append({"opcode": name, "hardfork": fork, "activation_block": first})
    return out

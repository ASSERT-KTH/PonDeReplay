"""
Shared utilities for PonDeReplay.
"""

import json
import sys
from pathlib import Path


def verbose_log(message: str, *, enabled: bool = True) -> None:
    """Write progress messages to stderr so stdout stays clean for JSON."""
    if enabled:
        print(message, file=sys.stderr)


def read_bytecode(bytecode_file: str) -> str:
    """
    Read contract bytecode from a file.

    Supported formats:
    - Raw hex string (with or without ``0x`` prefix)
    - JSON artifacts (Foundry, Hardhat, Truffle)
    - Raw binary ``.bin`` files
    """
    path = Path(bytecode_file)

    if not path.exists():
        raise FileNotFoundError(f"Bytecode file not found: {bytecode_file}")

    raw = path.read_bytes()

    # Try UTF-8 text first (hex string or JSON artifact)
    try:
        content = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        return "0x" + raw.hex()

    # Try JSON artifact
    try:
        artifact = json.loads(content)
        if isinstance(artifact, dict):
            if "bytecode" in artifact:
                bytecode = artifact["bytecode"]
            elif "evm" in artifact and "bytecode" in artifact["evm"]:
                bytecode = artifact["evm"]["bytecode"]["object"]
            elif "deployedBytecode" in artifact:
                bytecode = artifact["deployedBytecode"]
            else:
                raise ValueError("Could not find bytecode in JSON artifact")

            if isinstance(bytecode, dict) and "object" in bytecode:
                bytecode = bytecode["object"]

            bytecode = str(bytecode).strip()
            if not bytecode.startswith("0x"):
                bytecode = "0x" + bytecode.lstrip("0x")
            return bytecode
    except json.JSONDecodeError:
        pass

    # Plain hex text
    if content.startswith("0x"):
        return content
    return "0x" + content

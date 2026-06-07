"""Tests for preflight diagnostics and relevance gate."""

from unittest.mock import Mock, patch

import pytest
from web3 import Web3

from pondereplay.preflight import (
    PreflightDiagnostics,
    build_same_block_code_overrides,
    run_preflight,
)


def _mock_w3(
    tx_to_prev: int = 100,
    tx_to_at: int = 100,
    patched_prev: int = 200,
    tx_index: int = 0,
    creations=None,
):
    w3 = Mock()
    tx = {
        "blockNumber": 100,
        "transactionIndex": tx_index,
        "to": "0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B",
    }
    receipt = {"status": 1}

    def get_code(addr, block_identifier=None):
        addr = Web3.to_checksum_address(addr)
        if addr == Web3.to_checksum_address(tx["to"]):
            if block_identifier == 99:
                return b"\x00" * tx_to_prev
            return b"\x00" * tx_to_at
        if block_identifier == 99:
            return b"\x00" * patched_prev
        return b"\x00" * patched_prev

    w3.eth.get_code.side_effect = get_code
    w3.eth.get_block.return_value = {"transactions": []}
    if creations:
        w3.eth.get_block.return_value = {"transactions": ["0x" + "a" * 64]}
        w3.eth.get_transaction_receipt.return_value = {
            "contractAddress": creations,
        }
    return w3, tx, receipt


class TestRunPreflight:
    def test_faithful_when_tx_index_zero_and_code_exists(self):
        w3, tx, receipt = _mock_w3(tx_index=0)
        diag = run_preflight(
            w3, tx, receipt, "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7"
        )
        assert diag.faithfulness == "faithful"
        assert not diag.same_block_setup_required
        assert not diag.escalate_replay

    def test_unfaithful_when_tx_to_missing_at_prev_block(self):
        w3, tx, receipt = _mock_w3(tx_to_prev=0, tx_to_at=50, tx_index=3)
        diag = run_preflight(
            w3, tx, receipt, "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7"
        )
        assert diag.same_block_setup_required
        assert diag.escalate_replay
        assert diag.faithfulness == "unfaithful"
        assert any("no code at block" in w for w in diag.warnings)


class TestSameBlockOverrides:
    def test_build_override_for_tx_to(self):
        w3, tx, receipt = _mock_w3(tx_to_prev=0, tx_to_at=40, tx_index=2)
        diag = run_preflight(
            w3, tx, receipt, "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7"
        )
        overrides = build_same_block_code_overrides(w3, diag)
        assert tx["to"] in overrides or Web3.to_checksum_address(tx["to"]) in overrides

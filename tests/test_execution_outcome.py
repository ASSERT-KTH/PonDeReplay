"""Tests for execution outcome normalization."""

from pondereplay.execution_outcome import build_execution_outcome
from pondereplay.replayer import ReplayResult


class TestExecutionOutcome:
    def test_anvil_success_not_reverted(self):
        result = ReplayResult(
            success=True,
            tx_hash="0xabc",
            block_number=1,
            replay_mode="anvil_indexed_strict",
            diagnostics={
                "onchain_status": 1,
                "local_status": 1,
            },
        )
        ex = build_execution_outcome(result)
        assert ex["onchain_reverted"] is False
        assert ex["local_reverted"] is False
        assert ex["local_revert_message"] is None

    def test_anvil_revert_with_message(self):
        result = ReplayResult(
            success=False,
            tx_hash="0xabc",
            block_number=1,
            error="execution reverted: borrower is solvent",
            replay_mode="anvil_indexed_strict",
            diagnostics={
                "onchain_status": 1,
                "local_status": 0,
                "revert_message": "execution reverted: borrower is solvent",
                "revert_source": "trace",
            },
        )
        ex = build_execution_outcome(result)
        assert ex["local_reverted"] is True
        assert "borrower is solvent" in ex["local_revert_message"]

    def test_eth_call_revert(self):
        result = ReplayResult(
            success=False,
            tx_hash="0xabc",
            block_number=1,
            error="execution reverted: foo",
            replay_mode="eth_call",
            diagnostics={
                "onchain_status": 1,
                "revert_message": "execution reverted: foo",
            },
        )
        ex = build_execution_outcome(result)
        assert ex["local_reverted"] is True
        assert ex["local_status"] == 0

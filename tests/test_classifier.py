"""Tests for patch effect classification."""

from pondereplay.classifier import classify_patch_effect
from pondereplay.replayer import ReplayResult


def _result(success: bool, faithfulness: str = "faithful", mode: str = "eth_call"):
    return ReplayResult(
        success=success,
        tx_hash="0x" + "a" * 64,
        block_number=1,
        diagnostics={"faithfulness": faithfulness},
        replay_mode=mode,
        error=None if success else "revert",
    )


class TestClassifyPatchEffect:
    def test_effective_patch_on_attack_tx(self):
        original = _result(True, mode="eth_call_same_block_override")
        patched = _result(False, mode="eth_call_same_block_override")
        assert (
            classify_patch_effect(
                original, patched, chain_tx_succeeded=True, is_attack_tx=True
            )
            == "effective_patch"
        )

    def test_ineffective_patch_on_attack_tx(self):
        original = _result(True)
        patched = _result(True)
        assert (
            classify_patch_effect(
                original, patched, chain_tx_succeeded=True, is_attack_tx=True
            )
            == "ineffective_patch"
        )

    def test_unfaithful_replay(self):
        original = _result(
            True,
            faithfulness="unfaithful",
            mode="eth_call",
        )
        original.diagnostics["same_block_setup_required"] = True
        patched = _result(False, faithfulness="unfaithful", mode="eth_call")
        patched.diagnostics["same_block_setup_required"] = True
        assert (
            classify_patch_effect(
                original, patched, chain_tx_succeeded=True, is_attack_tx=True
            )
            == "unfaithful_replay"
        )

    def test_effective_with_same_block_override_mode(self):
        original = _result(
            True, faithfulness="faithful", mode="eth_call_same_block_override_original"
        )
        patched = _result(
            False, faithfulness="faithful", mode="eth_call_same_block_override_patched"
        )
        assert (
            classify_patch_effect(
                original, patched, chain_tx_succeeded=True, is_attack_tx=True
            )
            == "effective_patch"
        )

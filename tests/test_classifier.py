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


def _state(available=True, equivalent=True, reproduces_chain=True):
    # ``state_equivalent`` = same-context test (patched vs original); ``reproduces_chain``
    # = STRUCTURAL reproduction check (status/scope/code). None means unavailable.
    return {
        "available": available,
        "state_equivalent": equivalent,
        "reproduces_chain": reproduces_chain,
    }


class TestStateAxis:
    def test_benign_both_success_state_equal_is_preserved(self):
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o, p, is_attack_tx=False, state=_state(equivalent=True)
            )
            == "preserved"
        )

    def test_benign_both_success_state_diverges_needs_inspection(self):
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o, p, is_attack_tx=False, state=_state(equivalent=False)
            )
            == "needs_inspection"
        )

    def test_benign_patch_breaks_tx_needs_inspection(self):
        # Patch makes a benign tx revert -> changed benign behaviour -> inspect.
        o, p = _result(True), _result(False)
        assert (
            classify_patch_effect(
                o, p, is_attack_tx=False, state=_state(equivalent=True)
            )
            == "needs_inspection"
        )

    def test_benign_chain_not_reproduced_is_inconclusive(self):
        # Both succeed, test equivalent, but the structural reproduction check failed ->
        # the original replay didn't reproduce reality -> inconclusive.
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o,
                p,
                is_attack_tx=False,
                state=_state(equivalent=True, reproduces_chain=False),
            )
            == "inconclusive"
        )

    def test_benign_value_drift_reproduces_chain_is_preserved(self):
        # Reproduces chain (value drift tolerated) + test equivalent -> preserved.
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o,
                p,
                is_attack_tx=False,
                state=_state(equivalent=True, reproduces_chain=True),
            )
            == "preserved"
        )

    def test_benign_no_state_falls_back_to_status_only(self):
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(o, p, is_attack_tx=False, state=None) == "preserved"
        )

    def test_attack_subcall_blocked_is_effective(self):
        # Top-level both succeed, but patched state diverges -> exploit effect gone.
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o,
                p,
                chain_tx_succeeded=True,
                is_attack_tx=True,
                state=_state(equivalent=False),
            )
            == "effective_patch"
        )

    def test_attack_state_equal_stays_ineffective(self):
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o,
                p,
                chain_tx_succeeded=True,
                is_attack_tx=True,
                state=_state(equivalent=True),
            )
            == "ineffective_patch"
        )

    def test_attack_top_level_revert_still_effective_regardless_of_state(self):
        o = _result(True, mode="anvil_indexed")
        p = _result(False, mode="anvil_indexed")
        assert (
            classify_patch_effect(
                o,
                p,
                chain_tx_succeeded=True,
                is_attack_tx=True,
                state=_state(equivalent=True),
            )
            == "effective_patch"
        )

    def test_attack_unfaithful_original_is_inconclusive(self):
        # original.success False (status-unfaithful) -> inconclusive.
        o = _result(False, mode="anvil_indexed")
        p = _result(False, mode="anvil_indexed")
        assert (
            classify_patch_effect(
                o,
                p,
                chain_tx_succeeded=True,
                is_attack_tx=True,
                state=_state(equivalent=False),
            )
            == "inconclusive"
        )

    def test_attack_top_level_revert_effective_even_if_chain_not_reproduced(self):
        # Clean status flip is decided by status alone; reproduction check not consulted.
        o = _result(True, mode="anvil_indexed")
        p = _result(False, mode="anvil_indexed")
        assert (
            classify_patch_effect(
                o,
                p,
                chain_tx_succeeded=True,
                is_attack_tx=True,
                state=_state(equivalent=True, reproduces_chain=False),
            )
            == "effective_patch"
        )

    def test_attack_both_succeed_chain_not_reproduced_is_inconclusive(self):
        # Both succeed, test equivalent (exploit lands), but reproduction check failed ->
        # original replay didn't reproduce reality -> inconclusive.
        o, p = _result(True), _result(True)
        assert (
            classify_patch_effect(
                o,
                p,
                chain_tx_succeeded=True,
                is_attack_tx=True,
                state=_state(equivalent=True, reproduces_chain=False),
            )
            == "inconclusive"
        )

"""Classifier must not treat out-of-gas as effective patch."""

from pondereplay.classifier import classify_patch_effect
from pondereplay.replayer import ReplayResult


def test_benign_oog_is_inconclusive_not_effective_patch():
    original = ReplayResult(
        success=True,
        tx_hash="0x1",
        block_number=1,
        diagnostics={"faithfulness": "faithful", "local_status": 1},
        replay_mode="anvil_indexed_strict",
    )
    patched = ReplayResult(
        success=False,
        tx_hash="0x1",
        block_number=1,
        diagnostics={
            "faithfulness": "faithful",
            "local_status": 0,
            "local_failure_reason": "out_of_gas",
            "trace_out_of_gas_on_impl": True,
        },
        replay_mode="anvil_indexed_strict",
    )
    assert (
        classify_patch_effect(
            original, patched, chain_tx_succeeded=True, is_attack_tx=False
        )
        == "inconclusive"
    )

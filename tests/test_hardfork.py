"""A patch built for a newer hardfork than the replayed block must not be read as a patch effect."""

from pondereplay.classifier import classify_patch_effect
from pondereplay.execution_outcome import infer_local_failure_reason
from pondereplay.hardfork import inactive_opcodes, used_opcodes
from pondereplay.replayer import ReplayResult

# solc >=0.5 selector dispatch: PUSH1 0 CALLDATALOAD PUSH1 0xe0 SHR
SHR_DISPATCH = "0x60003560e01c"
# PUSH2 0x1c5f: the SHR / PUSH0 bytes are immediates, not opcodes
PUSHED_ONLY = "0x611c5f00"


def test_used_opcodes_skips_push_immediates():
    assert 0x1C in used_opcodes(SHR_DISPATCH)
    assert used_opcodes(PUSHED_ONLY) == [0x61, 0x00]


def test_metadata_trailer_is_not_scanned():
    # byzantium-target runtime tail: ... STOP INVALID + solc 0.8.35 CBOR metadata (ipfs, solc),
    # whose bytes include 0x5c (TLOAD) and 0x1b (SHL)
    tail = (
        "5056fea2646970667358221220fc3dca355c68d3cfcc14268b101947a8e11b8ecaacf9349211776deb8fe8"
        "344864736f6c63430008230033"
    )
    assert inactive_opcodes(tail, 1, 4_759_527) == []


def test_shr_inactive_before_constantinople():
    assert inactive_opcodes(SHR_DISPATCH, 1, 4_759_527) == [
        {"opcode": "SHR", "hardfork": "constantinople", "activation_block": 7_280_000}
    ]


def test_shr_active_from_constantinople():
    assert inactive_opcodes(SHR_DISPATCH, 1, 7_280_000) == []


def test_unknown_chain_is_not_judged():
    assert inactive_opcodes("0x5f", 56, 1) == []


def test_push0_inactive_before_shanghai():
    assert [o["opcode"] for o in inactive_opcodes("0x5f00", 1, 17_034_869)] == ["PUSH0"]


def test_not_activated_halt_is_a_failure_reason():
    diag = {"local_status": 0, "revert_message": "NotActivated", "revert_source": "trace"}
    assert infer_local_failure_reason(diag) == "opcode_not_activated"


def _pair(patched_error: str):
    original = ReplayResult(
        success=True,
        tx_hash="0x1",
        block_number=4_759_527,
        diagnostics={"faithfulness": "faithful", "local_status": 1},
        replay_mode="anvil_indexed_strict_original",
    )
    patched = ReplayResult(
        success=False,
        tx_hash="0x1",
        block_number=4_759_527,
        error=patched_error,
        diagnostics={
            "faithfulness": "faithful",
            "local_status": 0,
            "revert_message": patched_error,
            "revert_source": "trace",
        },
        replay_mode="anvil_indexed_strict_patched",
    )
    return original, patched


def test_benign_not_activated_is_inconclusive_not_needs_inspection():
    original, patched = _pair("NotActivated")
    assert classify_patch_effect(original, patched, is_attack_tx=False) == "inconclusive"


def test_attack_not_activated_is_inconclusive_not_effective_patch():
    original, patched = _pair("NotActivated")
    assert classify_patch_effect(original, patched, is_attack_tx=True) == "inconclusive"


def test_genuine_patch_revert_still_counts():
    original, patched = _pair("execution reverted: blocked")
    assert classify_patch_effect(original, patched, is_attack_tx=False) == "needs_inspection"
    assert classify_patch_effect(original, patched, is_attack_tx=True) == "effective_patch"

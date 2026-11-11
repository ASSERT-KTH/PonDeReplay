"""Batch report: every unfaithful replay is listed, whichever tier produced it."""

from unittest.mock import Mock

from pondereplay.batch import BatchReplayer
from pondereplay.replayer import ReplayResult


def _result(tx: str, faithfulness: str) -> ReplayResult:
    return ReplayResult(
        success=faithfulness == "faithful",
        tx_hash=tx,
        block_number=1,
        diagnostics={"faithfulness": faithfulness},
    )


def test_report_lists_context_unfaithful_replays():
    results = {
        "0xa": _result("0xa", "faithful"),
        "0xb": _result("0xb", "unfaithful"),
        "0xc": _result("0xc", "context_unfaithful"),
        "0xd": _result("0xd", "approximate"),
    }
    report = BatchReplayer.generate_report(None, results)
    assert report["unfaithful_replay_txs"] == ["0xb", "0xc"]


def test_report_counts_patch_classifications():
    a = _result("0xa", "faithful")
    a.patch_classification = "preserved"
    b = _result("0xb", "faithful")
    b.patch_classification = "needs_inspection"
    c = _result("0xc", "faithful")
    c.patch_classification = "preserved"
    d = _result("0xd", "faithful")  # replayed without --compare: no label
    report = BatchReplayer.generate_report(
        None, {"0xa": a, "0xb": b, "0xc": c, "0xd": d}
    )
    assert report["classification_counts"] == {"needs_inspection": 1, "preserved": 2}
    assert report["classifications"] == {
        "0xa": "preserved",
        "0xb": "needs_inspection",
        "0xc": "preserved",
    }


def _batch_with_mock_replayer():
    batch = BatchReplayer.__new__(BatchReplayer)
    batch.replayer = Mock()

    def compare(tx_hash, contract_address, patched_bytecode, is_attack_tx):
        r = _result(tx_hash, "faithful")
        r.patch_classification = "effective_patch" if is_attack_tx else "preserved"
        return _result(tx_hash, "faithful"), r, {}

    batch.replayer.replay_original_and_patched.side_effect = compare
    return batch


def test_compare_classifies_each_tx_and_flags_the_attack():
    batch = _batch_with_mock_replayer()
    results = batch.replay_batch(
        ["0xa", "0xB"], "0xc0", "0x00", compare=True, attack_tx="0xb"
    )
    assert results["0xa"].patch_classification == "preserved"
    assert results["0xB"].patch_classification == "effective_patch"
    batch.replayer.replay_transaction.assert_not_called()


def test_without_compare_only_the_patched_replay_runs():
    batch = _batch_with_mock_replayer()
    batch.replayer.replay_transaction.return_value = _result("0xa", "faithful")
    batch.replay_batch(["0xa"], "0xc0", "0x00")
    batch.replayer.replay_original_and_patched.assert_not_called()

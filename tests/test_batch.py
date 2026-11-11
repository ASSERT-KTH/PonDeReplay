"""Batch report: every unfaithful replay is listed, whichever tier produced it."""

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

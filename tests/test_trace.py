"""Tests for trace analysis."""

from pondereplay.trace import (
    TraceAnalysis,
    analyze_transaction_trace,
    count_failed_subcalls,
    failed_call_frames,
)


class TestFailedSubcalls:
    def _trace(self):
        # root OK; child A reverts (swallowed); A's child OOG; sibling B OK.
        return {
            "type": "CALL",
            "to": "0xroot",
            "calls": [
                {
                    "type": "CALL",
                    "to": "0xA",
                    "error": "execution reverted",
                    "revertReason": "boom",
                    "calls": [
                        {"type": "CALL", "to": "0xA1", "error": "out of gas"},
                    ],
                },
                {"type": "STATICCALL", "to": "0xB"},
            ],
        }

    def test_counts_nested_errors_excludes_root(self):
        assert count_failed_subcalls(self._trace()) == 2

    def test_include_root_counts_top_level_error(self):
        t = {"type": "CALL", "to": "0xroot", "error": "reverted", "calls": []}
        assert count_failed_subcalls(t, include_root=False) == 0
        assert count_failed_subcalls(t, include_root=True) == 1

    def test_no_errors_is_zero(self):
        t = {"type": "CALL", "calls": [{"type": "CALL", "calls": []}]}
        assert count_failed_subcalls(t) == 0

    def test_failed_call_frames_detail(self):
        frames = failed_call_frames(self._trace())
        tos = {f["to"] for f in frames}
        assert tos == {"0xA", "0xA1"}
        assert any(f["revertReason"] == "boom" for f in frames)

    def test_handles_non_dict(self):
        assert count_failed_subcalls(None) == 0
        assert failed_call_frames("nope") == []


class TestAnalyzeTransactionTrace:
    def test_walks_nested_calls(self):
        w3 = type("W3", (), {})()
        trace_root = {
            "from": "0x0ed1c01b8420a965d7bd2374db02896464c91cd7",
            "to": "0xe408b52aefb27a2fb4f1cd760a76daa4bf23794b",
            "input": "0xe1fa7638",
            "type": "CALL",
            "calls": [
                {
                    "from": "0x4822d9172e5b76b9db37b75f5552f9988f98a888",
                    "to": "0x85a948fd70b2b415bda93324581fb5fff1293df7",
                    "input": "0xe61604cf",
                    "type": "DELEGATECALL",
                    "calls": [],
                }
            ],
        }

        def make_request(method, params):
            assert method == "debug_traceTransaction"
            return {"result": trace_root}

        class Provider:
            def make_request(self, method, params):
                return make_request(method, params)

        w3.provider = Provider()

        analysis = analyze_transaction_trace(
            w3,
            "0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d",
            "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
        )
        assert analysis.patched_contract_reached
        assert analysis.patched_contract_delegatecall
        assert "e61604cf" in analysis.selectors_seen

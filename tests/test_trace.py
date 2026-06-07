"""Tests for trace analysis."""

from pondereplay.trace import TraceAnalysis, analyze_transaction_trace


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

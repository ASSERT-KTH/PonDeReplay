"""Tests for revert reason decoding."""

from pondereplay.revert_decode import (
    RevertDetails,
    apply_revert_to_diagnostics,
    decode_alkemi_error_code,
    decode_error_string,
    find_revert_in_call_trace,
    format_revert_message,
    normalize_rpc_error,
)

# Error(string) for "borrower is solvent"
BORROWER_SOLVENT_DATA = (
    "0x08c379a000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000013626f72726f77657220697320736f6c76656e7400000000000000000000000000"
)


class TestDecodeErrorString:
    def test_borrower_is_solvent(self):
        assert decode_error_string(BORROWER_SOLVENT_DATA) == "borrower is solvent"

    def test_empty_data(self):
        assert decode_error_string("0x") is None
        assert decode_error_string("") is None


class TestNormalizeRpcError:
    def test_rpc_dict_with_data(self):
        err = {
            "code": 3,
            "message": "execution reverted",
            "data": BORROWER_SOLVENT_DATA,
        }
        msg, data = normalize_rpc_error(err)
        assert data == BORROWER_SOLVENT_DATA
        assert msg == "execution reverted"

    def test_format_message(self):
        formatted = format_revert_message(BORROWER_SOLVENT_DATA, "execution reverted")
        assert formatted == "execution reverted: borrower is solvent"


class TestAlkemiErrorCode:
    def test_bad_input_code(self):
        data = "0x" + "0" * 63 + "6"
        assert decode_alkemi_error_code(data) == "AlkemiEarn Error.BAD_INPUT (6)"


class TestCallTracerWalk:
    def test_prefers_out_of_gas_over_return_data(self):
        trace = {
            "type": "CALL",
            "to": "0x4822D9172e5b76b9Db37B75f5552F9988F98a888",
            "error": "execution reverted",
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "to": "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
                    "error": "out of gas",
                },
                {
                    "type": "CALL",
                    "to": "0xa0b86991c6218fc8c0c03c78348a0c09ff4779dd",
                    "output": "0x" + "0" * 63 + "6",
                },
            ],
        }
        found = find_revert_in_call_trace(
            trace, patched_address="0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7"
        )
        assert found is not None
        assert found.message == "out of gas"

    def test_finds_deepest_revert(self):
        trace = {
            "type": "CALL",
            "to": "0x4822D9172e5b76b9Db37B75f5552F9988F98a888",
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "to": "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
                    "error": "Reverted",
                    "output": BORROWER_SOLVENT_DATA,
                }
            ],
        }
        found = find_revert_in_call_trace(
            trace, patched_address="0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7"
        )
        assert found is not None
        assert "borrower is solvent" in found.message


class TestApplyDiagnostics:
    def test_writes_fields(self):
        diag = {}
        msg = apply_revert_to_diagnostics(
            diag,
            RevertDetails(
                message="execution reverted: borrower is solvent",
                data=BORROWER_SOLVENT_DATA,
                source="trace",
            ),
        )
        assert "borrower is solvent" in msg
        assert diag["revert_source"] == "trace"
        assert diag["revert_data"] == BORROWER_SOLVENT_DATA

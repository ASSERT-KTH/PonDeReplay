"""
Tests for the TransactionReplayer core functionality
"""

import pytest
from unittest.mock import Mock, patch
from web3 import Web3
from pondereplay.replayer import TransactionReplayer, ReplayResult
from pondereplay.preflight import PreflightDiagnostics
from pondereplay.trace import TraceAnalysis


class TestReplayResult:
    """Test ReplayResult dataclass"""

    def test_replay_result_creation(self):
        """Test creating a ReplayResult"""
        result = ReplayResult(
            success=True,
            tx_hash="0x1234",
            block_number=12345,
            return_value="0xabcd",
            gas_used=50000,
        )

        assert result.success is True
        assert result.tx_hash == "0x1234"
        assert result.block_number == 12345
        assert result.return_value == "0xabcd"
        assert result.gas_used == 50000

    def test_replay_result_to_dict(self):
        """Test converting ReplayResult to dict"""
        result = ReplayResult(success=True, tx_hash="0x1234", block_number=12345)

        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["success"] is True
        assert d["tx_hash"] == "0x1234"
        assert d["block_number"] == 12345

    def test_replay_result_with_error(self):
        """Test ReplayResult with error"""
        result = ReplayResult(
            success=False,
            tx_hash="0x1234",
            block_number=12345,
            error="execution reverted",
        )

        assert result.success is False
        assert result.error == "execution reverted"


class TestTransactionReplayer:
    """Test TransactionReplayer class"""

    @patch("pondereplay.replayer.Web3")
    def test_init_with_connection(self, mock_web3):
        """Test replayer initialization with successful connection"""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545")

        assert replayer.rpc_url == "http://localhost:8545"
        assert replayer.fork_url == "http://localhost:8545"
        mock_web3.HTTPProvider.assert_called_once_with("http://localhost:8545")

    @patch("pondereplay.replayer.Web3")
    def test_init_connection_error(self, mock_web3):
        """Test replayer initialization with connection error"""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = False
        mock_web3.return_value = mock_w3_instance

        with pytest.raises(ConnectionError, match="Cannot connect to RPC"):
            TransactionReplayer("http://localhost:8545")

    @patch("pondereplay.replayer.Web3")
    def test_replay_transaction_not_found(self, mock_web3):
        """Test replay with non-existent transaction"""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_w3_instance.eth.get_transaction.return_value = None
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545")

        with pytest.raises(ValueError, match="Transaction not found"):
            replayer.replay_transaction(
                tx_hash="0x1234", contract_address="0xabcd", new_bytecode="0x6080"
            )

    @patch("pondereplay.replayer.analyze_transaction_trace")
    @patch("pondereplay.replayer.Web3")
    def test_replay_transaction_success(self, mock_web3, mock_trace):
        """Test successful transaction replay"""
        mock_trace.return_value = TraceAnalysis(
            tx_hash="0x1234",
            patched_contract_reached=True,
            patched_contract_delegatecall=False,
        )
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_web3.to_checksum_address = Web3.to_checksum_address

        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True

        mock_tx = {
            "hash": Mock(hex=lambda: "0x1234"),
            "blockNumber": 12345,
            "transactionIndex": 0,
            "from": "0x0Ed1C01b8420a965d7BD2374dB02896464C91cd7",
            "to": "0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B",
            "value": 0,
            "input": "0xdata",
            "gas": 100000,
        }
        mock_w3_instance.eth.get_transaction.return_value = mock_tx
        mock_receipt = {"gasUsed": 50000, "status": 1}
        mock_w3_instance.eth.get_transaction_receipt.return_value = mock_receipt

        mock_w3_instance.eth.get_code.return_value = b"\x00" * 10

        mock_result = Mock()
        mock_result.hex.return_value = "0xabcd"
        mock_w3_instance.eth.call.return_value = mock_result

        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545", use_trace_for_gate=False)
        result = replayer.replay_transaction(
            tx_hash="0x1234",
            contract_address="0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
            new_bytecode="0x6080",
            skip_trace=True,
        )

        assert result.success is True
        assert result.block_number == 12345
        assert result.gas_used == 50000
        assert "faithfulness" in result.diagnostics

    @patch("pondereplay.replayer.Web3")
    def test_auto_strict_escalation_on_status_mismatch(self, mock_web3):
        """Auto-escalate to strict anvil when chain succeeded but replay failed."""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer(
            "http://localhost:8545",
            auto_strict_on_mismatch=True,
            strict_anvil_context=False,
        )

        tx = {
            "hash": Mock(hex=lambda: "0x1234"),
            "blockNumber": 12345,
            "transactionIndex": 1,
            "from": "0x0Ed1C01b8420a965d7BD2374dB02896464C91cd7",
            "to": "0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B",
            "value": 0,
            "input": "0xdata",
            "gas": 100000,
        }
        receipt = {"gasUsed": 50000, "status": 1}
        diag = PreflightDiagnostics(
            block_number=12345,
            transaction_index=1,
            tx_to=tx["to"],
            tx_to_code_len_at_prev_block=10,
            tx_to_code_len_at_block=10,
            patched_address="0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
            patched_code_len_at_prev_block=100,
            same_block_setup_required=False,
            escalate_replay=False,
            faithfulness="approximate",
        )
        replayer.run_preflight = Mock(return_value=(tx, receipt, diag, None))
        replayer._replay_with_web3 = Mock(
            return_value=ReplayResult(
                success=False,
                tx_hash="0x1234",
                block_number=12345,
                error="execution reverted: time",
                replay_mode="eth_call",
                diagnostics={"faithfulness": "approximate"},
            )
        )
        replayer._replay_with_anvil = Mock(
            return_value=ReplayResult(
                success=True,
                tx_hash="0x1234",
                block_number=12345,
                replay_mode="anvil_indexed_strict",
                diagnostics={"faithfulness": "faithful"},
            )
        )

        result = replayer.replay_transaction(
            tx_hash="0x1234",
            contract_address="0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
            new_bytecode="0x6080",
            skip_trace=True,
        )

        assert result.success is True
        assert result.diagnostics["auto_strict_escalated"] is True
        assert "auto_strict" in result.replay_mode
        assert replayer._replay_with_anvil.call_count == 1

    @patch("pondereplay.replayer.Web3")
    def test_no_auto_strict_when_disabled(self, mock_web3):
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer(
            "http://localhost:8545",
            auto_strict_on_mismatch=False,
        )
        failed = ReplayResult(
            success=False,
            tx_hash="0x1234",
            block_number=12345,
            error="execution reverted: time",
            replay_mode="eth_call",
            diagnostics={"faithfulness": "approximate"},
        )

        assert replayer._should_auto_strict_escalate(failed, {"status": 1}) is False

    @patch("pondereplay.replayer.analyze_transaction_trace")
    @patch("pondereplay.replayer.Web3")
    def test_sanity_check_success(self, mock_web3, mock_trace):
        mock_trace.return_value = TraceAnalysis(
            tx_hash="0x1234",
            patched_contract_reached=True,
            patched_contract_delegatecall=False,
        )
        """Test sanity check with matching results"""
        # Setup mocks
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_web3.to_checksum_address = Web3.to_checksum_address

        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True

        mock_tx = {
            "hash": Mock(hex=lambda: "0x1234"),
            "blockNumber": 12345,
            "transactionIndex": 0,
            "from": "0x0Ed1C01b8420a965d7BD2374dB02896464C91cd7",
            "to": "0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B",
            "value": 0,
            "input": "0xdata",
            "gas": 100000,
        }
        mock_w3_instance.eth.get_transaction.return_value = mock_tx

        mock_receipt = {"gasUsed": 50000, "status": 1, "output": "0xabcd"}
        mock_w3_instance.eth.get_transaction_receipt.return_value = mock_receipt

        code_mock = Mock()
        code_mock.hex.return_value = "0x6080"
        mock_w3_instance.eth.get_code.return_value = b"\x00" * 5

        # Mock eth_call result
        mock_result = Mock()
        mock_result.hex.return_value = "0xabcd"
        mock_w3_instance.eth.call.return_value = mock_result

        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545", use_trace_for_gate=False)
        result, matches = replayer.sanity_check(
            tx_hash="0x1234",
            contract_address="0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
        )

        assert result.success is True
        assert matches is True


class TestCompareResults:
    """Test result comparison logic"""

    @patch("pondereplay.replayer.Web3")
    def test_compare_results_match(self, mock_web3):
        """Test comparing matching results"""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545")

        result = ReplayResult(
            success=True, tx_hash="0x1234", block_number=12345, return_value="0xabcd"
        )

        receipt = {"output": "0xabcd"}

        matches = replayer._compare_results(result, receipt)
        assert matches is True

    @patch("pondereplay.replayer.Web3")
    def test_compare_results_no_match(self, mock_web3):
        """Test comparing non-matching results"""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545")

        result = ReplayResult(
            success=True, tx_hash="0x1234", block_number=12345, return_value="0xabcd"
        )

        receipt = {"output": "0x1234"}

        matches = replayer._compare_results(result, receipt)
        assert matches is False

    @patch("pondereplay.replayer.Web3")
    def test_compare_results_failed_replay(self, mock_web3):
        """Test comparing when replay failed"""
        mock_provider = Mock()
        mock_web3.HTTPProvider.return_value = mock_provider
        mock_w3_instance = Mock()
        mock_w3_instance.is_connected.return_value = True
        mock_web3.return_value = mock_w3_instance

        replayer = TransactionReplayer("http://localhost:8545")

        result = ReplayResult(
            success=False,
            tx_hash="0x1234",
            block_number=12345,
            error="execution reverted",
        )

        receipt = {"output": "0xabcd"}

        matches = replayer._compare_results(result, receipt)
        assert matches is False

"""
Tests for CLI functionality
"""

import json
import pytest
from pathlib import Path
from click.testing import CliRunner
from unittest.mock import Mock, patch, MagicMock
from pondereplay.cli import cli, _read_bytecode
from pondereplay.replayer import ReplayResult


class TestBytecodeReading:
    """Test bytecode file reading"""

    def test_read_hex_file(self, tmp_path):
        """Test reading raw hex file"""
        hex_file = tmp_path / "test.hex"
        hex_file.write_text("0x6080604052")

        bytecode = _read_bytecode(str(hex_file))
        assert bytecode == "0x6080604052"

    def test_read_hex_without_prefix(self, tmp_path):
        """Test reading hex without 0x prefix"""
        hex_file = tmp_path / "test.hex"
        hex_file.write_text("6080604052")

        bytecode = _read_bytecode(str(hex_file))
        assert bytecode == "0x6080604052"

    def test_read_json_artifact_bytecode(self, tmp_path):
        """Test reading Foundry-style JSON artifact"""
        json_file = tmp_path / "artifact.json"
        artifact = {"bytecode": "0x6080604052"}
        json_file.write_text(json.dumps(artifact))

        bytecode = _read_bytecode(str(json_file))
        assert bytecode == "0x6080604052"

    def test_read_json_artifact_evm(self, tmp_path):
        """Test reading JSON artifact with evm.bytecode structure"""
        json_file = tmp_path / "artifact.json"
        artifact = {"evm": {"bytecode": {"object": "0x6080604052"}}}
        json_file.write_text(json.dumps(artifact))

        bytecode = _read_bytecode(str(json_file))
        assert bytecode == "0x6080604052"

    def test_read_json_artifact_deployed(self, tmp_path):
        """Test reading JSON artifact with deployedBytecode"""
        json_file = tmp_path / "artifact.json"
        artifact = {"deployedBytecode": "0x6080604052"}
        json_file.write_text(json.dumps(artifact))

        bytecode = _read_bytecode(str(json_file))
        assert bytecode == "0x6080604052"

    def test_read_binary_file(self, tmp_path):
        """Test reading raw binary .bin file"""
        bin_file = tmp_path / "test.bin"
        bin_file.write_bytes(bytes.fromhex("6080604052"))

        bytecode = _read_bytecode(str(bin_file))
        assert bytecode == "0x6080604052"

    def test_read_nonexistent_file(self):
        """Test reading non-existent file"""
        with pytest.raises(FileNotFoundError):
            _read_bytecode("/nonexistent/file.hex")

    def test_read_json_without_bytecode_field(self, tmp_path):
        """Test reading JSON without bytecode field"""
        json_file = tmp_path / "invalid.json"
        json_file.write_text(json.dumps({"other": "data"}))

        with pytest.raises(ValueError, match="Could not find bytecode"):
            _read_bytecode(str(json_file))


class TestCLIReplay:
    """Test CLI replay command"""

    @patch("pondereplay.cli.TransactionReplayer")
    def test_replay_command_success(self, mock_replayer_class, tmp_path):
        """Test successful replay command"""
        runner = CliRunner()

        # Create test bytecode file
        hex_file = tmp_path / "test.hex"
        hex_file.write_text("0x6080604052")

        # Mock replayer
        mock_replayer = Mock()
        mock_result = ReplayResult(
            success=True,
            tx_hash="0x1234",
            block_number=12345,
            return_value="0xabcd",
            gas_used=50000,
        )
        mock_replayer.replay_transaction.return_value = mock_result
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "replay",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--bytecode-file",
                str(hex_file),
                "--output",
                "json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert output["success"] is True
        assert output["tx_hash"] == "0x1234"

    @patch("pondereplay.cli.TransactionReplayer")
    def test_replay_command_failure(self, mock_replayer_class, tmp_path):
        """Test replay command with failed transaction"""
        runner = CliRunner()

        hex_file = tmp_path / "test.hex"
        hex_file.write_text("0x6080604052")

        mock_replayer = Mock()
        mock_result = ReplayResult(
            success=False,
            tx_hash="0x1234",
            block_number=12345,
            error="execution reverted",
        )
        mock_replayer.replay_transaction.return_value = mock_result
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "replay",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--bytecode-file",
                str(hex_file),
                "--output",
                "json",
            ],
        )

        assert result.exit_code == 1
        output = json.loads(result.output)
        assert output["success"] is False
        assert output["error"] == "execution reverted"

    def test_replay_command_missing_required_args(self):
        """Test replay command with missing arguments"""
        runner = CliRunner()

        result = runner.invoke(cli, ["replay"])

        assert result.exit_code != 0
        assert "Missing option" in result.output or "required" in result.output.lower()

    @patch("pondereplay.cli.TransactionReplayer")
    def test_replay_verbose_prints_auto_strict_hint(
        self, mock_replayer_class, tmp_path
    ):
        runner = CliRunner()
        hex_file = tmp_path / "test.hex"
        hex_file.write_text("0x6080604052")

        mock_replayer = Mock()
        mock_result = ReplayResult(
            success=False,
            tx_hash="0x1234",
            block_number=12345,
            error="execution reverted: time",
            diagnostics={
                "faithfulness": "faithful",
                "auto_strict_escalated": True,
                "status_mismatch": True,
            },
            replay_mode="anvil_indexed_strict_auto_strict",
        )
        mock_replayer.replay_transaction.return_value = mock_result
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "replay",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--bytecode-file",
                str(hex_file),
                "-v",
            ],
        )

        assert result.exit_code == 1
        assert "auto-escalated to strict Anvil context" in result.output
        assert "status mismatch detected" in result.output

    @patch("pondereplay.cli.TransactionReplayer")
    def test_replay_passes_strict_flags(self, mock_replayer_class, tmp_path):
        runner = CliRunner()
        hex_file = tmp_path / "test.hex"
        hex_file.write_text("0x6080604052")

        mock_replayer = Mock()
        mock_replayer.replay_transaction.return_value = ReplayResult(
            success=True, tx_hash="0x1234", block_number=12345
        )
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "replay",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--bytecode-file",
                str(hex_file),
                "--strict-anvil",
                "--no-auto-strict-on-mismatch",
            ],
        )

        assert result.exit_code == 0
        kwargs = mock_replayer_class.call_args.kwargs
        assert kwargs["strict_anvil_context"] is True
        assert kwargs["auto_strict_on_mismatch"] is False


class TestCLISanityCheck:
    """Test CLI sanity-check command"""

    @patch("pondereplay.cli.TransactionReplayer")
    def test_sanity_check_pass(self, mock_replayer_class):
        """Test sanity check that passes"""
        runner = CliRunner()

        mock_replayer = Mock()
        mock_result = ReplayResult(
            success=True, tx_hash="0x1234", block_number=12345, return_value="0xabcd"
        )
        mock_replayer.sanity_check.return_value = (mock_result, True)
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "sanity-check",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--output",
                "json",
            ],
        )

        assert result.exit_code == 0
        output = json.loads(result.output)
        assert output["sanity_check_passed"] is True

    @patch("pondereplay.cli.TransactionReplayer")
    def test_sanity_check_fail(self, mock_replayer_class):
        """Test sanity check that fails"""
        runner = CliRunner()

        mock_replayer = Mock()
        mock_result = ReplayResult(
            success=True, tx_hash="0x1234", block_number=12345, return_value="0xabcd"
        )
        mock_replayer.sanity_check.return_value = (mock_result, False)
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "sanity-check",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--output",
                "json",
            ],
        )

        assert result.exit_code == 1
        output = json.loads(result.output)
        assert output["sanity_check_passed"] is False


class TestCLIBytecode:
    """Test CLI bytecode command"""

    def test_bytecode_command(self):
        """Test fetching bytecode from contract"""
        runner = CliRunner()

        # Patch Web3 where it's imported (inside the bytecode function)
        with patch("web3.Web3") as mock_web3_class:
            mock_w3_instance = Mock()
            mock_code = Mock()
            mock_code.hex.return_value = "0x6080604052"
            mock_w3_instance.eth.get_code.return_value = mock_code
            mock_web3_class.return_value = mock_w3_instance
            mock_web3_class.HTTPProvider = Mock()

            result = runner.invoke(
                cli, ["bytecode", "--rpc-url", "http://localhost:8545", "0xabcd"]
            )

            assert result.exit_code == 0
            assert "0x6080604052" in result.output


class TestCLITextOutput:
    """Test text output formatting"""

    @patch("pondereplay.cli.TransactionReplayer")
    def test_text_output_success(self, mock_replayer_class, tmp_path):
        """Test text output for successful replay"""
        runner = CliRunner()

        hex_file = tmp_path / "test.hex"
        hex_file.write_text("0x6080604052")

        mock_replayer = Mock()
        mock_result = ReplayResult(
            success=True,
            tx_hash="0x1234",
            block_number=12345,
            return_value="0xabcd",
            gas_used=50000,
            output="0xabcd",
        )
        mock_replayer.replay_transaction.return_value = mock_result
        mock_replayer_class.return_value = mock_replayer

        result = runner.invoke(
            cli,
            [
                "replay",
                "--rpc-url",
                "http://localhost:8545",
                "--tx-hash",
                "0x1234",
                "--contract-address",
                "0xabcd",
                "--bytecode-file",
                str(hex_file),
                "--output",
                "text",
            ],
        )

        assert result.exit_code == 0
        assert "Local replay: SUCCESS" in result.output
        assert "Faithful to chain: True" in result.output
        assert "Block Number: 12345" in result.output
        assert "Gas Used: 50000" in result.output


class TestCLIReplayHistory:
    """Test CLI replay-history command"""

    @patch("pondereplay.cli.BatchReplayer")
    def test_replay_history_from_tx_list_file(self, mock_batch_class, tmp_path):
        runner = CliRunner()

        txs_file = tmp_path / "txs.txt"
        txs_file.write_text("0x" + "1" * 64 + "\n" + "0x" + "2" * 64 + "\n")

        mock_batch = Mock()
        mock_batch.replay_batch.return_value = {
            "0x"
            + "1"
            * 64: ReplayResult(success=True, tx_hash="0x" + "1" * 64, block_number=1),
            "0x"
            + "2"
            * 64: ReplayResult(
                success=False, tx_hash="0x" + "2" * 64, block_number=2, error="reverted"
            ),
        }
        mock_batch.generate_report.return_value = {
            "total": 2,
            "passed": 1,
            "failed": 1,
            "passed_txs": ["0x" + "1" * 64],
            "failed_txs": ["0x" + "2" * 64],
            "attack_tx_failed_as_expected": False,
            "results": mock_batch.replay_batch.return_value,
        }
        mock_batch_class.return_value = mock_batch

        res = runner.invoke(
            cli,
            [
                "replay-history",
                "--rpc-url",
                "http://localhost:8545",
                "--contract-address",
                "0xabcd",
                "--tx-list-file",
                str(txs_file),
                "--bytecode-hex",
                "0x" + "6" * 10,
                "--output",
                "json",
            ],
        )

        assert res.exit_code == 0
        out = json.loads(res.output)
        assert out["total"] == 2
        assert out["passed"] == 1
        assert out["failed"] == 1
        mock_batch.replay_batch.assert_called_once()

    def test_replay_history_requires_exactly_one_source(self, tmp_path):
        runner = CliRunner()

        txs_file = tmp_path / "txs.txt"
        txs_file.write_text("0x" + "1" * 64 + "\n")

        # both provided => error
        res = runner.invoke(
            cli,
            [
                "replay-history",
                "--rpc-url",
                "http://localhost:8545",
                "--contract-address",
                "0xabcd",
                "--tx-list-file",
                str(txs_file),
                "--etherscan-api-key",
                "k",
                "--bytecode-hex",
                "0x" + "6" * 10,
            ],
        )
        assert res.exit_code != 0
        assert "exactly one history source" in res.output.lower()


class TestCLITxList:
    @patch("pondereplay.cli.get_contract_history")
    def test_tx_list_etherscan_json(self, mock_get_history):
        runner = CliRunner()
        mock_get_history.return_value = ["0x" + "1" * 64, "0x" + "2" * 64]

        out_file = "txs.json"

        res = runner.invoke(
            cli,
            [
                "tx-list",
                "--rpc-url",
                "http://localhost:8545",
                "--contract-address",
                "0xabcd",
                "--etherscan-api-key",
                "k",
                "--etherscan-network",
                "mainnet",
                "--output",
                out_file,
            ],
        )

        assert res.exit_code == 0
        path = Path(out_file)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["count"] == 2
        assert data["tx_hashes"] == ["0x" + "1" * 64, "0x" + "2" * 64]

    def test_tx_list_etherscan_requires_key(self):
        runner = CliRunner()

        res = runner.invoke(
            cli,
            [
                "tx-list",
                "--rpc-url",
                "http://localhost:8545",
                "--contract-address",
                "0xabcd",
            ],
            env={"ETHERSCAN_API_KEY": ""},
        )

        assert res.exit_code != 0
        assert "tx-list requires --etherscan-api-key" in res.output.lower()

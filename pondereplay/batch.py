"""
Batch replay operations for multiple transactions
"""

from typing import List, Dict, Any, Optional
from web3 import Web3
from .replayer import TransactionReplayer, ReplayResult


class BatchReplayer:
    """Replay multiple transactions and generate comparison reports"""

    def __init__(
        self,
        rpc_url: str,
        *,
        strict_anvil_context: bool = False,
        auto_strict_on_mismatch: bool = True,
        prefer_anvil_when_escalated: bool = False,
        bump_gas_for_patch: bool = False,
    ):
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC: {rpc_url}")
        self.replayer = TransactionReplayer(
            rpc_url,
            strict_anvil_context=strict_anvil_context,
            auto_strict_on_mismatch=auto_strict_on_mismatch,
            prefer_anvil_when_escalated=prefer_anvil_when_escalated,
            bump_gas_for_patch=bump_gas_for_patch,
        )

    def get_transactions_to_address(
        self,
        address: str,
        start_block: int = 0,
        end_block: int = None,
        verbose: bool = False,
    ) -> List[str]:
        """
        Scan blockchain for all transactions to an address.

        Note: This scans blocks manually, which is slow for large ranges.
        For production use, consider using Etherscan API or an indexing service.

        Args:
            address: Contract/account address (0x-prefixed)
            start_block: Block to start scanning from
            end_block: Block to end scanning (defaults to latest)
            verbose: Enable verbose logging

        Returns:
            List of transaction hashes
        """
        address = Web3.to_checksum_address(address)

        if end_block is None:
            end_block = self.w3.eth.block_number

        if verbose:
            print(
                f"[*] Scanning blocks {start_block} to {end_block} for txs to {address}..."
            )

        tx_hashes = []

        for block_num in range(start_block, end_block + 1):
            try:
                block = self.w3.eth.get_block(block_num)
                for tx_hash in block.get("transactions", []):
                    try:
                        tx = self.w3.eth.get_transaction(tx_hash)
                        if (
                            tx.get("to")
                            and Web3.to_checksum_address(tx["to"]) == address
                        ):
                            tx_hashes.append(
                                tx_hash.hex() if hasattr(tx_hash, "hex") else tx_hash
                            )
                    except Exception:
                        continue
            except Exception:
                continue

            if verbose and (block_num + 1) % 100 == 0:
                print(
                    f"  Scanned {block_num + 1} blocks, found {len(tx_hashes)} txs so far..."
                )

        if verbose:
            print(f"[*] Found {len(tx_hashes)} total transactions")

        return tx_hashes

    def replay_batch(
        self,
        tx_hashes: List[str],
        contract_address: str,
        new_bytecode: Optional[str] = None,
        verbose: bool = False,
    ) -> Dict[str, ReplayResult]:
        """
        Replay multiple transactions with patched bytecode.

        Args:
            tx_hashes: List of transaction hashes
            contract_address: Contract address to patch
            new_bytecode: New bytecode. If omitted, each transaction is replayed
                with the contract bytecode as it existed at (block_number - 1)
                for that transaction.
            verbose: Enable verbose logging

        Returns:
            Dict mapping tx_hash -> ReplayResult
        """
        results = {}

        if verbose:
            print(f"[*] Starting batch replay of {len(tx_hashes)} transactions...")

        for i, tx_hash in enumerate(tx_hashes, 1):
            if verbose:
                print(f"[{i}/{len(tx_hashes)}] Replaying {tx_hash}...")

            try:
                result = self.replayer.replay_transaction(
                    tx_hash=tx_hash,
                    contract_address=contract_address,
                    new_bytecode=new_bytecode,
                    verbose=False,
                )
                results[tx_hash] = result
            except Exception as e:
                if verbose:
                    print(f"  Error: {e}")
                results[tx_hash] = ReplayResult(
                    success=False,
                    tx_hash=tx_hash,
                    block_number=0,
                    error=str(e),
                )

        return results

    def generate_report(
        self,
        results: Dict[str, ReplayResult],
        attack_tx: str = None,
        verbose: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate a summary report of batch replay results.

        Args:
            results: Results dict from replay_batch
            attack_tx: Expected attack transaction hash (marked specially)
            verbose: Enable verbose logging

        Returns:
            Summary dict with statistics and transaction details
        """
        passed = []
        failed = []
        attack_expected_fail = False

        attack_tx_lower = attack_tx.lower() if attack_tx else None

        unfaithful = []

        for tx_hash, result in results.items():
            tx_lower = tx_hash.lower()
            is_attack = attack_tx_lower and tx_lower == attack_tx_lower
            faith = (result.diagnostics or {}).get("faithfulness")
            if faith == "unfaithful":
                unfaithful.append(tx_hash)

            if result.success:
                passed.append(tx_hash)
                if is_attack:
                    if verbose:
                        print("⚠️  Attack tx succeeded (expected to fail)")
            else:
                failed.append(tx_hash)
                if is_attack:
                    attack_expected_fail = True
                    if verbose:
                        print("✓ Attack tx failed as expected")

        return {
            "total": len(results),
            "passed": len(passed),
            "failed": len(failed),
            "passed_txs": passed,
            "failed_txs": failed,
            "unfaithful_replay_txs": unfaithful,
            "attack_tx_failed_as_expected": attack_expected_fail,
            "results": {k: v.to_dict() for k, v in results.items()},
        }


def print_batch_report(report: Dict[str, Any], attack_tx: str = None):
    """Print a human-readable batch report"""
    print("=" * 80)
    print("BATCH REPLAY REPORT")
    print("=" * 80)
    print()
    print(f"Total Transactions: {report['total']}")
    print(f"Passed: {report['passed']}")
    print(f"Failed: {report['failed']}")
    print()

    if attack_tx:
        status = (
            "✓ As Expected"
            if report["attack_tx_failed_as_expected"]
            else "✗ Unexpected"
        )
        print(f"Attack Tx Status: {status}")
        print()

    if report.get("unfaithful_replay_txs"):
        print(
            f"Unfaithful replays ({len(report['unfaithful_replay_txs'])}): "
            "same-block setup may invalidate fast replay"
        )
        for tx in report["unfaithful_replay_txs"][:10]:
            print(f"  {tx}")
        print()

    if report["failed_txs"]:
        print(f"Failed Transactions ({len(report['failed_txs'])}):")
        for tx in report["failed_txs"]:
            raw = report["results"][tx]
            err = (
                raw.get("error")
                if isinstance(raw, dict)
                else getattr(raw, "error", None)
            )
            is_attack = attack_tx and tx.lower() == attack_tx.lower()
            marker = " [ATTACK]" if is_attack else ""
            print(f"  {tx}{marker}")
            if err:
                print(f"    Error: {err}")
        print()

    if report["passed_txs"]:
        print(f"Passed Transactions ({len(report['passed_txs'])}):")
        for i, tx in enumerate(report["passed_txs"][:10], 1):  # Show first 10
            is_attack = attack_tx and tx.lower() == attack_tx.lower()
            marker = " [ATTACK]" if is_attack else ""
            print(f"  {i}. {tx}{marker}")

        if len(report["passed_txs"]) > 10:
            print(f"  ... and {len(report['passed_txs']) - 10} more")
        print()

    print("=" * 80)

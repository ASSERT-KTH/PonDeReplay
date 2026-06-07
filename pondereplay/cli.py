"""
PonDeReplay CLI - Replay Ethereum transactions with patched contract bytecode
"""

import json
import os
import sys
from typing import Optional

import click
from dotenv import load_dotenv
from click.core import ParameterSource

from .replayer import TransactionReplayer, ReplayResult
from .batch import BatchReplayer, print_batch_report
from .trace import analyze_transaction_trace
from .classifier import build_classification_report
from .etherscan import EtherscanError, get_contract_history
from .txlist import read_tx_hashes_from_file
from .utils import read_bytecode as _read_bytecode_util

load_dotenv()


def _resolve_option_or_env(value: Optional[str], env_key: str) -> Optional[str]:
    """
    Resolve a CLI option value, falling back to environment when empty.

    This makes commands robust when users pass shell-expanded variables like
    `--rpc-url "$ETH_RPC_URL"` and the shell variable is unset/empty while
    `.env` contains the actual value.
    """
    if value is not None:
        trimmed = value.strip()
        if trimmed:
            return trimmed

    env_value = os.getenv(env_key)
    if env_value is None:
        return None

    env_trimmed = env_value.strip()
    return env_trimmed or None


@click.group()
@click.version_option()
def cli():
    """PonDeReplay: Replay transactions with patched contract bytecode"""
    pass


@cli.command()
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--tx-hash",
    required=True,
    type=str,
    help="Transaction hash to replay (0x-prefixed)",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Contract address to patch (0x-prefixed)",
)
@click.option(
    "--bytecode-file",
    required=False,
    type=click.Path(exists=True),
    help="Path to new contract bytecode (hex string or JSON artifact)",
)
@click.option(
    "--bytecode-hex",
    required=False,
    type=str,
    help="Patched deployed contract bytecode as a 0x-prefixed hex string",
)
@click.option(
    "--fork-url",
    required=False,
    envvar="ETH_FORK_URL",
    help="Separate fork URL if different from RPC (defaults to RPC_URL)",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="json",
    help="Output format",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--force-same-block",
    is_flag=True,
    help="Force same-block code overrides when preflight escalates",
)
@click.option(
    "--use-anvil",
    is_flag=True,
    help="Use Anvil indexed replay when same-block setup is required",
)
@click.option(
    "--strict-anvil",
    is_flag=True,
    help="Use stricter Anvil block-context alignment (timestamp/baseFee/coinbase best-effort)",
)
@click.option(
    "--auto-strict-on-mismatch/--no-auto-strict-on-mismatch",
    default=True,
    show_default=True,
    help="Auto-escalate to strict Anvil when replay result mismatches likely on-chain behavior",
)
@click.option(
    "--with-trace",
    is_flag=True,
    help="Run debug_traceTransaction for preflight (slower; off by default)",
)
@click.option(
    "--bump-gas-for-patch/--no-bump-gas-for-patch",
    default=None,
    help=(
        "Re-estimate gas on Anvil instead of reusing the source tx limit. "
        "Defaults to on when --bytecode-file or --bytecode-hex is provided."
    ),
)
def replay(
    rpc_url: str,
    tx_hash: str,
    contract_address: str,
    bytecode_file: Optional[str],
    bytecode_hex: Optional[str],
    fork_url: Optional[str],
    output: str,
    verbose: bool,
    force_same_block: bool,
    use_anvil: bool,
    strict_anvil: bool,
    auto_strict_on_mismatch: bool,
    with_trace: bool,
    bump_gas_for_patch: Optional[bool],
):
    """
    Replay a transaction with patched contract bytecode.

    This command:
    1. Fetches the original transaction details
    2. Forks the blockchain at the transaction's block
    3. Replaces the contract bytecode with the patched version
    4. Re-executes the transaction
    5. Reports all execution details
    """
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )

        if verbose:
            click.echo("🔧 Initializing PonDeReplay...", err=True)

        bytecode = _resolve_bytecode_override(
            bytecode_file=bytecode_file, bytecode_hex=bytecode_hex
        )

        if bump_gas_for_patch is None:
            bump_gas_for_patch = bytecode is not None

        if verbose:
            if bytecode is None:
                click.echo(
                    "✓ No patched bytecode provided (using original bytecode)", err=True
                )
            else:
                click.echo(f"✓ Bytecode loaded ({len(bytecode) // 2} bytes)", err=True)

        # Create replayer
        fork_url = fork_url or rpc_url
        replayer = TransactionReplayer(
            rpc_url,
            fork_url,
            prefer_anvil_when_escalated=use_anvil,
            strict_anvil_context=strict_anvil,
            auto_strict_on_mismatch=auto_strict_on_mismatch,
            bump_gas_for_patch=bump_gas_for_patch,
        )

        if verbose:
            click.echo(f"✓ Connected to {rpc_url}", err=True)
            click.echo(f"⏱️  Replaying transaction {tx_hash}...", err=True)

        # Replay transaction
        result = replayer.replay_transaction(
            tx_hash=tx_hash,
            contract_address=contract_address,
            new_bytecode=bytecode,
            verbose=verbose,
            force_same_block=force_same_block,
            force_anvil=use_anvil,
            skip_trace=not with_trace,
        )

        # Output results
        if output == "json":
            click.echo(json.dumps(result.to_dict(), indent=2))
        else:
            _print_text_output(result)

        if verbose:
            faith = (result.diagnostics or {}).get("faithfulness", "unknown")
            click.echo(f"Faithfulness: {faith}", err=True)
            click.echo(f"Replay mode: {result.replay_mode}", err=True)
            diag = result.diagnostics or {}
            if diag.get("auto_strict_escalated"):
                click.echo(
                    "⚠️  Replay auto-escalated to strict Anvil context due to mismatch risk",
                    err=True,
                )
            if diag.get("status_mismatch"):
                click.echo(
                    "⚠️  Replay status mismatch detected (local != on-chain receipt status)",
                    err=True,
                )
            if (result.diagnostics or {}).get("warnings"):
                for w in result.diagnostics["warnings"]:
                    click.echo(f"⚠️  {w}", err=True)
            _print_execution_summary(result, err=True)
            diag = result.diagnostics or {}
            if diag.get("patch_guard_applies"):
                click.echo(f"ℹ️  {diag.get('patch_guard_note')}", err=True)
                if diag.get("gas_bumped_for_patch"):
                    click.echo(
                        "ℹ️  Gas limit was raised for patched bytecode "
                        f"({diag.get('source_gas_limit')} → {diag.get('replay_gas_limit')})",
                        err=True,
                    )
            if result.success:
                click.echo(
                    "✅ Faithful to chain: local execution matches on-chain",
                    err=True,
                )
            else:
                click.echo(
                    "❌ Not faithful to chain: local execution differs from on-chain",
                    err=True,
                )
                ex = (result.diagnostics or {}).get("execution") or {}
                if ex.get("local_failure_reason") == "out_of_gas":
                    click.echo(
                        "⚠️  Local failure is OUT OF GAS, not patch revert — "
                        "this tx used ~98% of gas; patched bytecode is slightly larger",
                        err=True,
                    )

        sys.exit(0 if result.success else 1)

    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command("replay-history")
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Contract address to patch (0x-prefixed)",
)
@click.option(
    "--etherscan-api-key",
    required=False,
    envvar="ETHERSCAN_API_KEY",
    help="Etherscan API key (or set ETHERSCAN_API_KEY)",
)
@click.option(
    "--etherscan-network",
    required=False,
    type=click.Choice(["mainnet", "sepolia", "holesky"], case_sensitive=False),
    default="mainnet",
    show_default=True,
    help="Etherscan network to query",
)
@click.option(
    "--tx-list-file",
    required=False,
    type=click.Path(exists=True),
    help="Path to a file containing tx hashes (one per line) or JSON list",
)
@click.option(
    "--start-block",
    type=int,
    default=None,
    help="Starting block for history fetch (default: explorer/provider default)",
)
@click.option(
    "--end-block",
    type=int,
    default=None,
    help="Ending block for history fetch (default: explorer/provider default)",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of txs to replay",
)
@click.option(
    "--use-anvil",
    is_flag=True,
    help="Prefer Anvil indexed replay when escalation is required",
)
@click.option(
    "--strict-anvil",
    is_flag=True,
    help="Use stricter Anvil block-context alignment during escalated replays",
)
@click.option(
    "--auto-strict-on-mismatch/--no-auto-strict-on-mismatch",
    default=True,
    show_default=True,
    help="Auto-escalate to strict Anvil when replay result mismatches likely on-chain behavior",
)
@click.option(
    "--bytecode-file",
    required=False,
    type=click.Path(exists=True),
    help="Path to patched contract bytecode (hex string or JSON artifact)",
)
@click.option(
    "--bytecode-hex",
    required=False,
    type=str,
    help="Patched deployed contract bytecode as a 0x-prefixed hex string",
)
@click.option(
    "--attack-tx",
    type=str,
    default=None,
    help="Expected attack transaction hash (0x-prefixed, for reporting)",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
@click.option(
    "--bump-gas-for-patch/--no-bump-gas-for-patch",
    default=None,
    help=(
        "Re-estimate gas on Anvil for patch replays. "
        "Defaults to on when --bytecode-file or --bytecode-hex is provided."
    ),
)
def replay_history(
    rpc_url: str,
    contract_address: str,
    etherscan_api_key: Optional[str],
    etherscan_network: str,
    tx_list_file: Optional[str],
    start_block: Optional[int],
    end_block: Optional[int],
    limit: Optional[int],
    use_anvil: bool,
    strict_anvil: bool,
    auto_strict_on_mismatch: bool,
    bytecode_file: Optional[str],
    bytecode_hex: Optional[str],
    attack_tx: Optional[str],
    output: str,
    verbose: bool,
    bump_gas_for_patch: Optional[bool],
):
    """
    Replay a contract's historical transactions with patched bytecode.

    Each transaction is replayed against the chain state at (block_number - 1),
    i.e. the block immediately before the original transaction.
    """
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )

        if verbose:
            click.echo("🔧 Initializing history replay...", err=True)

        ctx = click.get_current_context()
        etherscan_src = ctx.get_parameter_source("etherscan_api_key")
        tx_list_src = ctx.get_parameter_source("tx_list_file")

        etherscan_selected = etherscan_src == ParameterSource.COMMANDLINE
        tx_list_selected = tx_list_src == ParameterSource.COMMANDLINE

        if etherscan_selected and tx_list_selected:
            raise click.UsageError(
                "Provide exactly one history source: --etherscan-api-key or --tx-list-file"
            )

        # If a tx list file is provided, prefer it even if ETHERSCAN_API_KEY is set
        # via environment/.env to avoid accidental source conflicts.
        if tx_list_file and not etherscan_selected:
            etherscan_api_key = None

        if not tx_list_file and not etherscan_api_key:
            raise click.UsageError(
                "Provide exactly one history source: --etherscan-api-key or --tx-list-file"
            )

        bytecode = _resolve_bytecode_override(
            bytecode_file=bytecode_file, bytecode_hex=bytecode_hex
        )

        if bump_gas_for_patch is None:
            bump_gas_for_patch = bytecode is not None

        if verbose:
            if bytecode is None:
                click.echo(
                    "✓ No patched bytecode provided (using original bytecode per-tx)",
                    err=True,
                )
            else:
                click.echo(f"✓ Bytecode loaded ({len(bytecode) // 2} bytes)", err=True)

        if etherscan_api_key:
            if verbose:
                click.echo(
                    f"🔍 Fetching transaction history from Etherscan ({etherscan_network})...",
                    err=True,
                )
            tx_hashes = get_contract_history(
                api_key=etherscan_api_key,
                contract_address=contract_address,
                network=etherscan_network,
                start_block=start_block,
                end_block=end_block,
                limit=limit,
                include_internal=True,
            )
        else:
            if verbose:
                click.echo(f"📄 Reading tx hashes from {tx_list_file}...", err=True)
            tx_hashes = read_tx_hashes_from_file(tx_list_file)  # type: ignore[arg-type]
            if limit is not None:
                tx_hashes = tx_hashes[:limit]

        if not tx_hashes:
            click.echo("No transactions found for the requested history source/range.")
            sys.exit(0)

        if verbose:
            click.echo(f"✓ Found {len(tx_hashes)} transactions", err=True)
            click.echo(f"🎬 Replaying {len(tx_hashes)} transactions...", err=True)

        batch = BatchReplayer(
            rpc_url,
            strict_anvil_context=strict_anvil,
            auto_strict_on_mismatch=auto_strict_on_mismatch,
            prefer_anvil_when_escalated=use_anvil,
            bump_gas_for_patch=bool(bump_gas_for_patch),
        )
        results = batch.replay_batch(
            tx_hashes=tx_hashes,
            contract_address=contract_address,
            new_bytecode=bytecode,
            verbose=verbose,
        )
        report = batch.generate_report(results, attack_tx=attack_tx, verbose=verbose)

        if output == "json":
            output_data = {
                "total": report["total"],
                "passed": report["passed"],
                "failed": report["failed"],
                "attack_tx_failed_as_expected": report.get(
                    "attack_tx_failed_as_expected", False
                ),
                "unfaithful_replay_txs": report.get("unfaithful_replay_txs", []),
                "passed_txs": report["passed_txs"],
                "failed_txs": report["failed_txs"],
            }
            click.echo(json.dumps(output_data, indent=2))
        else:
            print_batch_report(report, attack_tx=attack_tx)

        sys.exit(0)

    except (EtherscanError, click.ClickException) as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command("tx-list")
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Contract address (0x-prefixed)",
)
@click.option(
    "--etherscan-api-key",
    required=False,
    envvar="ETHERSCAN_API_KEY",
    help="Etherscan API key (or set ETHERSCAN_API_KEY)",
)
@click.option(
    "--etherscan-network",
    required=False,
    type=click.Choice(["mainnet", "sepolia", "holesky"], case_sensitive=False),
    default="mainnet",
    show_default=True,
    help="Etherscan network to query",
)
@click.option(
    "--start-block",
    type=int,
    default=None,
    help="Starting block for history fetch (default: explorer/provider default)",
)
@click.option(
    "--end-block",
    type=int,
    default=None,
    help="Ending block for history fetch (default: explorer/provider default)",
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help="Maximum number of txs to write to the JSON file (default: all)",
)
@click.option(
    "--output",
    "output_path",
    required=False,
    type=str,
    help="Output JSON file path (default: <contract-address>.json)",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def tx_list(
    rpc_url: str,
    contract_address: str,
    etherscan_api_key: Optional[str],
    etherscan_network: str,
    start_block: Optional[int],
    end_block: Optional[int],
    limit: Optional[int],
    output_path: Optional[str],
    verbose: bool,
):
    """
    Fetch and print the transaction hashes involving a contract.

    This does NOT replay transactions; it only retrieves the tx hash list and writes
    it to a JSON file.
    """
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )

        if not etherscan_api_key:
            raise click.UsageError(
                "tx-list requires --etherscan-api-key (or ETHERSCAN_API_KEY in .env)"
            )

        if verbose:
            click.echo(
                f"🔍 Fetching tx history from Etherscan ({etherscan_network})...",
                err=True,
            )

        # Fetch up to `limit` transactions from Etherscan. If limit is None,
        # this will return as many as the API allows (up to its internal cap).
        tx_hashes = get_contract_history(
            api_key=etherscan_api_key,
            contract_address=contract_address,
            network=etherscan_network,
            start_block=start_block,
            end_block=end_block,
            limit=limit,
            include_internal=True,
        )

        filename = output_path or f"{contract_address}.json"
        payload = {
            "contract_address": contract_address,
            "count": len(tx_hashes),
            "tx_hashes": tx_hashes,
            "source": "etherscan",
            "network": etherscan_network,
        }

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

        click.echo(f"Wrote {len(tx_hashes)} transactions to {filename}")

        sys.exit(0)

    except (EtherscanError, click.ClickException) as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command()
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL",
)
@click.argument("contract_address")
def bytecode(rpc_url: str, contract_address: str):
    """
    Fetch current bytecode of a contract
    """
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )

        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(rpc_url))
        code = w3.eth.get_code(contract_address)
        click.echo(code.hex())

    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command("trace-analyze")
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--tx-hash",
    required=True,
    type=str,
    help="Transaction hash to trace (0x-prefixed)",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Patched contract address to check for reachability",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="json",
    help="Output format",
)
@click.option(
    "--full-trace",
    is_flag=True,
    help="Include full call tree in JSON output (default: summary only)",
)
def trace_analyze(
    rpc_url: str,
    tx_hash: str,
    contract_address: str,
    output: str,
    full_trace: bool,
):
    """Analyze transaction trace and patch contract reachability."""
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )
        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(rpc_url))
        analysis = analyze_transaction_trace(w3, tx_hash, contract_address)
        if output == "json":
            payload = (
                analysis.to_dict(include_calls=True)
                if full_trace
                else analysis.to_summary_dict()
            )
            click.echo(json.dumps(payload, indent=2))
        else:
            click.echo(f"Tx: {tx_hash}")
            click.echo(f"Patched contract reached: {analysis.patched_contract_reached}")
            click.echo(
                f"Delegatecall to patched: {analysis.patched_contract_delegatecall}"
            )
            if analysis.errors:
                click.echo(f"Errors: {analysis.errors}")
            for call in analysis.calls[:30]:
                if call.matches_patched_contract or call.function_name:
                    click.echo(
                        f"  depth={call.depth} {call.call_type} "
                        f"{call.function_name or call.selector} "
                        f"to={call.to_address}"
                    )
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command("compare-patch")
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--tx-hash",
    required=True,
    type=str,
    help="Transaction hash to replay",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Contract address to patch",
)
@click.option(
    "--bytecode-file",
    required=True,
    type=click.Path(exists=True),
    help="Path to patched bytecode",
)
@click.option(
    "--original-bytecode-file",
    required=False,
    type=click.Path(exists=True),
    help="Original bytecode file (default: on-chain at block-1)",
)
@click.option(
    "--attack-tx",
    is_flag=True,
    help="Treat as attack tx (patch should cause revert vs original success)",
)
@click.option(
    "--use-anvil",
    is_flag=True,
    help="Use Anvil when same-block setup is required",
)
@click.option(
    "--strict-anvil",
    is_flag=True,
    help="Use stricter Anvil block-context alignment when Anvil replay is used",
)
@click.option(
    "--auto-strict-on-mismatch/--no-auto-strict-on-mismatch",
    default=True,
    show_default=True,
    help="Auto-escalate to strict Anvil when replay result mismatches likely on-chain behavior",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="json",
    help="Output format",
)
@click.option("--verbose", "-v", is_flag=True)
def compare_patch(
    rpc_url: str,
    tx_hash: str,
    contract_address: str,
    bytecode_file: str,
    original_bytecode_file: Optional[str],
    attack_tx: bool,
    use_anvil: bool,
    strict_anvil: bool,
    auto_strict_on_mismatch: bool,
    output: str,
    verbose: bool,
):
    """Replay original and patched bytecode and classify patch effect."""
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError("Missing RPC URL")

        patched = _read_bytecode_util(bytecode_file)
        original = (
            _read_bytecode_util(original_bytecode_file)
            if original_bytecode_file
            else None
        )
        replayer = TransactionReplayer(
            rpc_url,
            prefer_anvil_when_escalated=use_anvil,
            strict_anvil_context=strict_anvil,
            auto_strict_on_mismatch=auto_strict_on_mismatch,
        )
        orig_result, patch_result, report = replayer.replay_original_and_patched(
            tx_hash=tx_hash,
            contract_address=contract_address,
            patched_bytecode=patched,
            original_bytecode=original,
            verbose=verbose,
            is_attack_tx=attack_tx,
        )
        payload = {
            "classification": report["classification"],
            "report": report,
            "original": orig_result.to_dict(),
            "patched": patch_result.to_dict(),
        }
        if output == "json":
            click.echo(json.dumps(payload, indent=2))
        else:
            click.echo(f"Classification: {report['classification']}")
            click.echo(f"Original success: {orig_result.success}")
            click.echo(f"Patched success: {patch_result.success}")
            if patch_result.error:
                click.echo(f"Patched error: {patch_result.error}")
        sys.exit(0)
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command("sanity-check")
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--tx-hash",
    required=True,
    type=str,
    help="Transaction hash to check (0x-prefixed)",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Contract address (0x-prefixed)",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="json",
    help="Output format",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def sanity_check(
    rpc_url: str,
    tx_hash: str,
    contract_address: str,
    output: str,
    verbose: bool,
):
    """
    Sanity check: verify replay mechanism works with original bytecode.

    This command:
    1. Fetches the original contract bytecode
    2. Replays the transaction with the original bytecode
    3. Compares the result with the original transaction receipt

    If this passes, the replay mechanism is working correctly and you can
    trust results from replaying with patched bytecode.
    """
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )

        if verbose:
            click.echo("🔧 Initializing PonDeReplay...", err=True)

        # Create replayer
        replayer = TransactionReplayer(rpc_url)

        if verbose:
            click.echo(f"✓ Connected to {rpc_url}", err=True)
            click.echo(f"🧪 Running sanity check for {tx_hash}...", err=True)

        # Run sanity check
        result, matches = replayer.sanity_check(
            tx_hash=tx_hash,
            contract_address=contract_address,
            verbose=verbose,
        )

        # Output results
        if output == "json":
            output_data = {
                **result.to_dict(),
                "sanity_check_passed": matches,
            }
            click.echo(json.dumps(output_data, indent=2))
        else:
            _print_text_output(result)
            click.echo()
            if matches:
                click.echo(
                    "✅ SANITY CHECK PASSED - Replay mechanism is working correctly!"
                )
            else:
                click.echo(
                    "❌ SANITY CHECK FAILED - Replay output doesn't match original!"
                )
                click.echo("   There may be an issue with the replay mechanism.")

        if verbose:
            click.echo("✅ Sanity check completed", err=True)

        sys.exit(0 if matches else 1)

    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


@cli.command("batch-replay")
@click.option(
    "--rpc-url",
    required=True,
    envvar="ETH_RPC_URL",
    help="Ethereum RPC URL (or set ETH_RPC_URL env var)",
)
@click.option(
    "--contract-address",
    required=True,
    type=str,
    help="Contract address to scan and patch (0x-prefixed)",
)
@click.option(
    "--bytecode-file",
    required=True,
    type=click.Path(exists=True),
    help="Path to patched contract bytecode",
)
@click.option(
    "--bytecode-hex",
    required=False,
    type=str,
    help="Patched deployed contract bytecode as a 0x-prefixed hex string",
)
@click.option(
    "--start-block",
    type=int,
    default=0,
    help="Starting block for scan (default: 0)",
)
@click.option(
    "--end-block",
    type=int,
    default=None,
    help="Ending block for scan (default: latest)",
)
@click.option(
    "--attack-tx",
    type=str,
    default=None,
    help="Expected attack transaction hash (0x-prefixed, for reporting)",
)
@click.option(
    "--output",
    type=click.Choice(["json", "text"]),
    default="text",
    help="Output format",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output",
)
def batch_replay(
    rpc_url: str,
    contract_address: str,
    bytecode_file: str,
    bytecode_hex: Optional[str],
    start_block: int,
    end_block: int,
    attack_tx: str,
    use_anvil: bool,
    strict_anvil: bool,
    auto_strict_on_mismatch: bool,
    output: str,
    verbose: bool,
):
    """
    Batch replay all transactions to a contract address with patched bytecode.

    This command:
    1. Scans the blockchain for all transactions to the contract
    2. Replays each one with the patched bytecode
    3. Generates a report showing which passed/failed
    """
    try:
        rpc_url = _resolve_option_or_env(rpc_url, "ETH_RPC_URL")
        if not rpc_url:
            raise click.UsageError(
                "Missing RPC URL. Set ETH_RPC_URL in .env or pass --rpc-url."
            )

        if verbose:
            click.echo("🔧 Initializing batch replayer...", err=True)

        bytecode = _resolve_bytecode_override(
            bytecode_file=bytecode_file, bytecode_hex=bytecode_hex
        )
        if bytecode is None:
            raise click.UsageError(
                "batch-replay requires patched bytecode via --bytecode-file or --bytecode-hex"
            )
        if verbose:
            click.echo(f"✓ Bytecode loaded ({len(bytecode) // 2} bytes)", err=True)

        # Create batch replayer
        batch = BatchReplayer(
            rpc_url,
            strict_anvil_context=strict_anvil,
            auto_strict_on_mismatch=auto_strict_on_mismatch,
            prefer_anvil_when_escalated=use_anvil,
        )
        if verbose:
            click.echo(f"✓ Connected to {rpc_url}", err=True)

        # Scan for transactions
        if verbose:
            click.echo(
                f"🔍 Scanning for transactions to {contract_address}...", err=True
            )

        tx_hashes = batch.get_transactions_to_address(
            address=contract_address,
            start_block=start_block,
            end_block=end_block,
            verbose=verbose,
        )

        if verbose:
            click.echo(f"✓ Found {len(tx_hashes)} transactions", err=True)

        if not tx_hashes:
            click.echo("No transactions found for this address in the scanned range.")
            sys.exit(0)

        # Replay all transactions
        if verbose:
            click.echo(f"🎬 Replaying {len(tx_hashes)} transactions...", err=True)

        results = batch.replay_batch(
            tx_hashes=tx_hashes,
            contract_address=contract_address,
            new_bytecode=bytecode,
            verbose=verbose,
        )

        # Generate report
        report = batch.generate_report(results, attack_tx=attack_tx, verbose=verbose)

        # Output results
        if output == "json":
            output_data = {
                "total": report["total"],
                "passed": report["passed"],
                "failed": report["failed"],
                "attack_tx_failed_as_expected": report.get(
                    "attack_tx_failed_as_expected", False
                ),
                "passed_txs": report["passed_txs"],
                "failed_txs": report["failed_txs"],
            }
            click.echo(json.dumps(output_data, indent=2))
        else:
            print_batch_report(report, attack_tx=attack_tx)

        if verbose:
            click.echo("✅ Batch replay completed", err=True)

        sys.exit(0)

    except Exception as e:
        click.echo(f"❌ Error: {str(e)}", err=True)
        if verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)


def _read_bytecode(bytecode_file: str) -> str:
    """
    Backwards-compatible wrapper for CLI/tests.

    Prefer using `pondereplay.utils.read_bytecode` directly.
    """
    return _read_bytecode_util(bytecode_file)


def _resolve_bytecode_override(
    *, bytecode_file: Optional[str], bytecode_hex: Optional[str]
) -> Optional[str]:
    if bytecode_file and bytecode_hex:
        raise click.UsageError("Provide only one of --bytecode-file or --bytecode-hex")

    if bytecode_file:
        return _read_bytecode(bytecode_file)

    if bytecode_hex:
        h = bytecode_hex.strip()
        if not h.startswith("0x"):
            raise click.UsageError(
                "--bytecode-hex must be 0x-prefixed deployed bytecode"
            )
        return h

    return None


def _print_execution_summary(result: ReplayResult, *, err: bool = False) -> None:
    """Print whether the tx reverted (on-chain and locally) and the revert message."""
    from .execution_outcome import build_execution_outcome

    ex = (result.diagnostics or {}).get("execution") or build_execution_outcome(result)

    def _line(msg: str) -> None:
        (click.echo(msg, err=True) if err else click.echo(msg))

    on_rev = ex.get("onchain_reverted")
    loc_rev = ex.get("local_reverted")
    _line(
        f"On-chain: {'REVERTED' if on_rev else 'SUCCESS' if on_rev is False else 'unknown'}"
    )
    _line(
        f"Local replay: {'REVERTED' if loc_rev else 'SUCCESS' if loc_rev is False else 'unknown'}"
    )
    if loc_rev:
        msg = ex.get("local_revert_message") or "execution reverted"
        _line(f"Local revert message: {msg}")
        if ex.get("revert_source"):
            _line(f"Revert source: {ex['revert_source']}")
        reason = ex.get("local_failure_reason")
        if reason == "out_of_gas":
            _line(
                "Failure reason: out of gas at source tx gas limit "
                "(NOT patch logic — use --bump-gas-for-patch to test semantics)"
            )
        elif reason == "patch_guard":
            _line("Failure reason: patch guard (borrower is solvent)")
        elif reason:
            _line(f"Failure reason: {reason}")
    elif loc_rev is False:
        _line("Local revert message: (none — call succeeded)")


def _print_text_output(result: ReplayResult):
    """Print results in human-readable format"""
    click.echo("=" * 80)
    click.echo("Transaction Replay Result")
    click.echo("=" * 80)
    _print_execution_summary(result)
    click.echo(f"Faithful to chain: {result.success}")
    click.echo(f"Block Number: {result.block_number}")
    click.echo(f"Transaction Hash: {result.tx_hash}")
    click.echo(f"Replay Mode: {result.replay_mode}")

    if result.diagnostics:
        click.echo(f"Faithfulness: {result.diagnostics.get('faithfulness', 'n/a')}")
        if result.diagnostics.get("same_block_setup_required"):
            click.echo("Same-block setup required: yes")
        for w in result.diagnostics.get("warnings") or []:
            click.echo(f"Warning: {w}")

    if result.patch_classification:
        click.echo(f"Patch classification: {result.patch_classification}")

    if result.return_value:
        click.echo(f"Return Value: {result.return_value}")

    if result.gas_used:
        click.echo(f"Gas Used: {result.gas_used}")

    if result.output:
        click.echo(f"Output: {result.output}")

    if result.logs:
        click.echo(f"\nLogs ({len(result.logs)}):")
        for i, log in enumerate(result.logs, 1):
            click.echo(f"  {i}. {log}")

    click.echo("=" * 80)


def main():
    """Entry point"""
    cli()


if __name__ == "__main__":
    main()

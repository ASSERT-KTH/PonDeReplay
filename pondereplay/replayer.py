"""
Core transaction replay logic using web3.py and local state patching
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional, Set, Tuple

from web3 import Web3

from .preflight import (
    PreflightDiagnostics,
    build_same_block_code_overrides,
    run_preflight,
)
from .trace import TraceAnalysis, analyze_transaction_trace
from .utils import verbose_log


@dataclass
class ReplayResult:
    """Result of a transaction replay"""

    success: bool
    tx_hash: str
    block_number: int
    return_value: Optional[str] = None
    output: Optional[str] = None
    gas_used: Optional[int] = None
    error: Optional[str] = None
    logs: List[str] = None
    state_changes: Optional[Dict[str, Any]] = None
    diagnostics: Optional[Dict[str, Any]] = None
    replay_mode: str = "eth_call"
    patch_classification: Optional[str] = None
    trace_analysis: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.logs is None:
            self.logs = []
        if self.state_changes is None:
            self.state_changes = {}
        if self.diagnostics is None:
            self.diagnostics = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization (excludes trace by default)."""
        from .execution_outcome import build_execution_outcome

        raw = asdict(self)
        raw.pop("trace_analysis", None)
        execution = build_execution_outcome(self)
        # Lead with execution outcome; ``success`` means faithful to chain, not "tx succeeded".
        ordered: Dict[str, Any] = {
            "onchain_reverted": execution["onchain_reverted"],
            "local_reverted": execution["local_reverted"],
            "revert_message": execution["local_revert_message"],
            "local_failure_reason": execution.get("local_failure_reason"),
            "execution": execution,
            "faithful_to_chain": execution["faithful_to_chain"],
            "success": raw["success"],
        }
        for key, value in raw.items():
            if key not in ordered and key != "diagnostics":
                ordered[key] = value
        diag = dict(raw.get("diagnostics") or {})
        diag.pop("execution", None)
        ordered["diagnostics"] = diag
        return ordered


class TransactionReplayer:
    """
    Replays Ethereum transactions with patched contract bytecode.

    Uses a tiered strategy:
    1. Preflight diagnostics and relevance gate
    2. Fast eth_call at block-1 (faithful when no same-block setup)
    3. Same-block code overrides when escalated
    4. Optional Anvil indexed replay for scientific-grade fidelity
    """

    def __init__(
        self,
        rpc_url: str,
        fork_url: Optional[str] = None,
        *,
        use_trace_for_gate: bool = False,
        prefer_anvil_when_escalated: bool = False,
        strict_anvil_context: bool = False,
        auto_strict_on_mismatch: bool = True,
        anvil_bin: str = "anvil",
        bump_gas_for_patch: bool = False,
    ):
        self.rpc_url = rpc_url
        self.fork_url = fork_url or rpc_url
        self.use_trace_for_gate = use_trace_for_gate
        self.prefer_anvil_when_escalated = prefer_anvil_when_escalated
        self.strict_anvil_context = strict_anvil_context
        self.auto_strict_on_mismatch = auto_strict_on_mismatch
        self.anvil_bin = anvil_bin
        self.bump_gas_for_patch = bump_gas_for_patch
        self.w3 = Web3(Web3.HTTPProvider(rpc_url))

        if not self.w3.is_connected():
            raise ConnectionError(f"Cannot connect to RPC: {rpc_url}")

    def run_preflight(
        self,
        tx_hash: str,
        contract_address: str,
        *,
        use_trace: Optional[bool] = None,
    ) -> Tuple[dict, dict, PreflightDiagnostics, Optional[TraceAnalysis]]:
        """Fetch tx/receipt and run preflight diagnostics."""
        tx = self.w3.eth.get_transaction(tx_hash)
        receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        if not tx or not receipt:
            raise ValueError(f"Transaction not found: {tx_hash}")

        trace_analysis: Optional[TraceAnalysis] = None
        trace_touched: Optional[Set[str]] = None
        if use_trace if use_trace is not None else self.use_trace_for_gate:
            try:
                trace_analysis = analyze_transaction_trace(
                    self.w3, tx_hash, contract_address
                )
                trace_touched = trace_analysis.touched_address_set()
            except Exception:
                trace_analysis = None

        diagnostics = run_preflight(
            self.w3,
            tx,
            receipt,
            contract_address,
            trace_touched_addresses=trace_touched,
        )
        return tx, receipt, diagnostics, trace_analysis

    def replay_transaction(
        self,
        tx_hash: str,
        contract_address: str,
        new_bytecode: Optional[str] = None,
        verbose: bool = False,
        *,
        force_same_block: bool = False,
        force_anvil: bool = False,
        skip_trace: bool = False,
    ) -> ReplayResult:
        """
        Replay a transaction with patched bytecode.
        """
        if verbose:
            verbose_log(f"[*] Fetching transaction {tx_hash}...")

        tx, receipt, diagnostics, trace_analysis = self.run_preflight(
            tx_hash,
            contract_address,
            use_trace=not skip_trace,
        )
        block_number = diagnostics.block_number
        contract_address = diagnostics.patched_address

        if verbose:
            verbose_log(f"[*] Transaction found at block {block_number}")
            verbose_log(f"[*] Tx index: {diagnostics.transaction_index}")
            verbose_log(f"[*] Faithfulness (preflight): {diagnostics.faithfulness}")
            if diagnostics.warnings:
                for w in diagnostics.warnings:
                    verbose_log(f"[!] {w}")

        using_patched_bytecode = new_bytecode is not None
        if new_bytecode is None:
            if verbose:
                verbose_log(
                    f"[*] No patched bytecode provided; using original code at block {block_number - 1}..."
                )
            original = self.w3.eth.get_code(
                contract_address, block_identifier=block_number - 1
            )
            new_bytecode = original.hex()

        patch_guard: Dict[str, Any] = {}
        if using_patched_bytecode:
            from .patch_guard import analyze_patch_guard

            patch_guard = analyze_patch_guard(
                self.w3, tx, fork_block=block_number - 1
            )
            if verbose and patch_guard.get("patch_guard_applies"):
                verbose_log(f"[*] {patch_guard.get('patch_guard_note')}")

        escalate = diagnostics.escalate_replay or force_same_block

        if force_anvil or (self.prefer_anvil_when_escalated and escalate):
            result = self._replay_with_anvil(
                tx=tx,
                receipt=receipt,
                contract_address=contract_address,
                new_bytecode=new_bytecode,
                diagnostics=diagnostics,
                trace_analysis=trace_analysis,
                strict_context=self.strict_anvil_context,
                verbose=verbose,
            )
            if self._should_auto_strict_escalate(result, receipt):
                if verbose:
                    verbose_log("[*] Auto-escalating to strict Anvil context replay...")
                strict_result = self._replay_with_anvil(
                    tx=tx,
                    receipt=receipt,
                    contract_address=contract_address,
                    new_bytecode=new_bytecode,
                    diagnostics=diagnostics,
                    trace_analysis=trace_analysis,
                    strict_context=True,
                    verbose=verbose,
                )
                strict_result.diagnostics["auto_strict_escalated"] = True
                self._merge_patch_guard(strict_result, patch_guard)
                return self._finalize_result(strict_result, receipt)
            self._merge_patch_guard(result, patch_guard)
            return self._finalize_result(result, receipt)

        if escalate:
            result = self._replay_with_web3(
                tx=tx,
                receipt=receipt,
                block_number=block_number,
                contract_address=contract_address,
                new_bytecode=new_bytecode,
                diagnostics=diagnostics,
                trace_analysis=trace_analysis,
                use_same_block_overrides=True,
                verbose=verbose,
            )
            if self._should_auto_strict_escalate(result, receipt):
                if verbose:
                    verbose_log("[*] Auto-escalating to strict Anvil context replay...")
                strict_result = self._replay_with_anvil(
                    tx=tx,
                    receipt=receipt,
                    contract_address=contract_address,
                    new_bytecode=new_bytecode,
                    diagnostics=diagnostics,
                    trace_analysis=trace_analysis,
                    strict_context=True,
                    verbose=verbose,
                )
                strict_result.diagnostics["auto_strict_escalated"] = True
                strict_result.replay_mode = f"{strict_result.replay_mode}_auto_strict"
                self._merge_patch_guard(strict_result, patch_guard)
                return self._finalize_result(strict_result, receipt)
            self._merge_patch_guard(result, patch_guard)
            return self._finalize_result(result, receipt)

        result = self._replay_with_web3(
            tx=tx,
            receipt=receipt,
            block_number=block_number,
            contract_address=contract_address,
            new_bytecode=new_bytecode,
            diagnostics=diagnostics,
            trace_analysis=trace_analysis,
            use_same_block_overrides=False,
            verbose=verbose,
        )
        if self._should_auto_strict_escalate(result, receipt):
            if verbose:
                verbose_log("[*] Auto-escalating to strict Anvil context replay...")
            strict_result = self._replay_with_anvil(
                tx=tx,
                receipt=receipt,
                contract_address=contract_address,
                new_bytecode=new_bytecode,
                diagnostics=diagnostics,
                trace_analysis=trace_analysis,
                strict_context=True,
                verbose=verbose,
            )
            strict_result.diagnostics["auto_strict_escalated"] = True
            strict_result.replay_mode = f"{strict_result.replay_mode}_auto_strict"
            self._merge_patch_guard(strict_result, patch_guard)
            return self._finalize_result(strict_result, receipt)
        self._merge_patch_guard(result, patch_guard)
        return self._finalize_result(result, receipt)

    def _finalize_result(
        self, result: ReplayResult, receipt: dict
    ) -> ReplayResult:
        from .execution_outcome import apply_execution_outcome

        diag = result.diagnostics or {}
        if diag.get("onchain_status") is None and receipt.get("status") is not None:
            diag["onchain_status"] = int(receipt["status"])
            result.diagnostics = diag
        return apply_execution_outcome(result)

    @staticmethod
    def _merge_patch_guard(result: ReplayResult, patch_guard: Dict[str, Any]) -> None:
        if not patch_guard:
            return
        result.diagnostics = {**(result.diagnostics or {}), **patch_guard}

    def replay_original_and_patched(
        self,
        tx_hash: str,
        contract_address: str,
        patched_bytecode: str,
        original_bytecode: Optional[str] = None,
        verbose: bool = False,
        *,
        is_attack_tx: bool = False,
    ) -> Tuple[ReplayResult, ReplayResult, Dict[str, Any]]:
        """
        Run original-control and patched replays for scientific comparison.
        """
        from .classifier import build_classification_report

        tx, receipt, diagnostics, trace_analysis = self.run_preflight(
            tx_hash, contract_address
        )
        block_number = diagnostics.block_number
        contract_address = diagnostics.patched_address

        if original_bytecode is None:
            original = self.w3.eth.get_code(
                contract_address, block_identifier=block_number - 1
            )
            original_bytecode = original.hex()

        escalate = diagnostics.escalate_replay

        original_result = self._execute_replay(
            tx,
            receipt,
            contract_address,
            original_bytecode,
            diagnostics,
            trace_analysis,
            escalate,
            verbose,
            replay_mode_suffix="original",
        )
        patched_result = self._execute_replay(
            tx,
            receipt,
            contract_address,
            patched_bytecode,
            diagnostics,
            trace_analysis,
            escalate,
            verbose,
            replay_mode_suffix="patched",
        )

        chain_ok = receipt.get("status", 0) == 1
        report = build_classification_report(
            original_result,
            patched_result,
            chain_tx_succeeded=chain_ok,
            is_attack_tx=is_attack_tx,
            include_trace=False,
        )
        patched_result.patch_classification = report["classification"]
        original_result.patch_classification = report["classification"]
        return original_result, patched_result, report

    def _execute_replay(
        self,
        tx: dict,
        receipt: dict,
        contract_address: str,
        bytecode: str,
        diagnostics: PreflightDiagnostics,
        trace_analysis: Optional[TraceAnalysis],
        escalate: bool,
        verbose: bool,
        replay_mode_suffix: str,
    ) -> ReplayResult:
        bump_on_anvil = self.bump_gas_for_patch or replay_mode_suffix == "patched"
        if self.prefer_anvil_when_escalated and escalate:
            result = self._replay_with_anvil(
                tx,
                receipt,
                contract_address,
                bytecode,
                diagnostics,
                trace_analysis,
                strict_context=self.strict_anvil_context,
                verbose=verbose,
                bump_gas=bump_on_anvil,
            )
        elif escalate:
            result = self._replay_with_web3(
                tx,
                receipt,
                diagnostics.block_number,
                contract_address,
                bytecode,
                diagnostics,
                trace_analysis,
                use_same_block_overrides=True,
                verbose=verbose,
            )
        else:
            result = self._replay_with_web3(
                tx,
                receipt,
                diagnostics.block_number,
                contract_address,
                bytecode,
                diagnostics,
                trace_analysis,
                use_same_block_overrides=False,
                verbose=verbose,
            )
        result.replay_mode = f"{result.replay_mode}_{replay_mode_suffix}"
        return result

    def sanity_check(
        self,
        tx_hash: str,
        contract_address: str,
        verbose: bool = False,
    ) -> Tuple[ReplayResult, bool]:
        if verbose:
            verbose_log(f"[*] Running sanity check for {tx_hash}...")

        tx, receipt, diagnostics, trace_analysis = self.run_preflight(
            tx_hash, contract_address
        )
        block_number = diagnostics.block_number
        contract_address = diagnostics.patched_address

        original_bytecode = self.w3.eth.get_code(
            contract_address, block_identifier=block_number - 1
        )

        original_result = self._execute_replay(
            tx,
            receipt,
            contract_address,
            original_bytecode.hex(),
            diagnostics,
            trace_analysis,
            diagnostics.escalate_replay,
            verbose,
            replay_mode_suffix="sanity",
        )

        matches = self._compare_results(original_result, receipt, verbose)
        if verbose:
            status = "✓ SANITY CHECK PASSED" if matches else "✗ SANITY CHECK FAILED"
            verbose_log(f"[*] {status}")

        return original_result, matches

    def _compare_results(
        self, result: ReplayResult, receipt: dict, verbose: bool = False
    ) -> bool:
        if not result.success:
            if verbose:
                verbose_log("[!] Replay failed, cannot compare with original")
            return False

        original_output = receipt.get("output", None) or receipt.get("logs", None)
        replay_output = result.return_value or result.output

        if original_output and replay_output:
            return str(original_output).lower() == str(replay_output).lower()
        return True

    def _replay_with_anvil(
        self,
        tx: dict,
        receipt: dict,
        contract_address: str,
        new_bytecode: str,
        diagnostics: PreflightDiagnostics,
        trace_analysis: Optional[TraceAnalysis],
        strict_context: bool = False,
        verbose: bool = False,
        *,
        bump_gas: Optional[bool] = None,
    ) -> ReplayResult:
        from .anvil_replay import AnvilIndexedReplayer

        prior = AnvilIndexedReplayer.prior_tx_hashes_in_block(
            self.w3, diagnostics.block_number, diagnostics.transaction_index
        )
        if verbose:
            verbose_log(f"[*] Anvil indexed replay ({len(prior)} prior txs in block)...")

        effective_bump = (
            self.bump_gas_for_patch if bump_gas is None else bump_gas
        )
        with AnvilIndexedReplayer(
            self.fork_url,
            anvil_bin=self.anvil_bin,
            bump_gas_for_patch=effective_bump,
        ) as anvil:
            result = anvil.replay_indexed(
                self.w3,
                tx,
                receipt,
                contract_address,
                new_bytecode,
                prior,
                strict_context=strict_context,
                verbose=verbose,
            )

        diag_dict = diagnostics.to_dict()
        diag_dict["faithfulness"] = "faithful"
        if result.diagnostics:
            diag_dict.update(result.diagnostics)
        result.diagnostics = diag_dict
        if strict_context:
            result.replay_mode = f"{result.replay_mode}_strict"
        if trace_analysis:
            result.trace_analysis = trace_analysis.to_summary_dict()
        return result

    def _should_auto_strict_escalate(self, result: ReplayResult, receipt: dict) -> bool:
        if not self.auto_strict_on_mismatch:
            return False
        if result.success:
            return False
        if result.replay_mode.startswith("anvil_indexed") and "strict" in result.replay_mode:
            return False
        chain_ok = int(receipt.get("status", 0)) == 1
        if chain_ok:
            return True
        err = (result.error or "").lower()
        return any(k in err for k in ("execution reverted: time", "timestamp", "deadline"))

    def _replay_with_web3(
        self,
        tx: dict,
        receipt: dict,
        block_number: int,
        contract_address: str,
        new_bytecode: str,
        diagnostics: PreflightDiagnostics,
        trace_analysis: Optional[TraceAnalysis],
        use_same_block_overrides: bool,
        verbose: bool = False,
    ) -> ReplayResult:
        if verbose:
            verbose_log("[*] Preparing to replay with patched bytecode...")

        try:
            if not new_bytecode.startswith("0x"):
                new_bytecode = "0x" + new_bytecode

            state_overrides: Dict[str, Dict[str, str]] = {
                contract_address: {"code": new_bytecode}
            }

            replay_mode = "eth_call"
            if use_same_block_overrides:
                extra = build_same_block_code_overrides(self.w3, diagnostics)
                state_overrides.update(extra)
                replay_mode = "eth_call_same_block_override"
                if verbose:
                    verbose_log(
                        f"[*] Same-block overrides for {len(extra)} address(es)"
                    )

            if verbose:
                verbose_log(f"[*] Contract address: {contract_address}")
                verbose_log(
                    f"[*] New bytecode length: {len(new_bytecode)} chars "
                    f"({len(new_bytecode) // 2} bytes)"
                )

            result = self.w3.eth.call(
                {
                    "from": tx["from"],
                    "to": tx["to"],
                    "value": tx["value"],
                    "data": tx["input"],
                    "gas": tx["gas"],
                },
                block_identifier=block_number - 1,
                state_override=state_overrides,
            )

            if verbose:
                verbose_log("[*] Replay completed successfully")
                verbose_log(f"[*] Return value: {result.hex()}")

            diag = diagnostics.to_dict()
            diag["local_status"] = 1
            diag["onchain_status"] = int(receipt.get("status", 1))
            if use_same_block_overrides:
                diag["faithfulness"] = "faithful"
                diag["same_block_setup_required"] = True
            elif diagnostics.faithfulness == "unfaithful":
                diag["faithfulness"] = "unfaithful"
            else:
                diag["faithfulness"] = "approximate"

            return ReplayResult(
                success=True,
                tx_hash=tx["hash"].hex(),
                block_number=block_number,
                return_value=result.hex(),
                gas_used=receipt["gasUsed"],
                output=result.hex(),
                replay_mode=replay_mode,
                diagnostics=diag,
                trace_analysis=(
                    trace_analysis.to_summary_dict() if trace_analysis else None
                ),
            )

        except Exception as e:
            from .revert_decode import (
                RevertDetails,
                apply_revert_to_diagnostics,
                decode_error_string,
                format_revert_message,
                normalize_rpc_error,
            )

            if verbose:
                verbose_log(f"[!] Error during replay: {str(e)}")

            diag = diagnostics.to_dict()
            diag["local_status"] = 0
            diag["onchain_status"] = int(receipt.get("status", 1))
            if use_same_block_overrides:
                diag["faithfulness"] = "faithful"
                diag["same_block_setup_required"] = True
            elif diagnostics.faithfulness == "unfaithful":
                diag["faithfulness"] = "unfaithful"
            else:
                diag["faithfulness"] = "approximate"

            rpc_message, data_hex = normalize_rpc_error(e)
            error_msg = format_revert_message(data_hex, rpc_message) or str(e)
            if decode_error_string(data_hex or ""):
                apply_revert_to_diagnostics(
                    diag,
                    RevertDetails(
                        message=error_msg,
                        data=data_hex,
                        source="eth_call",
                    ),
                )
            elif error_msg != str(e):
                diag["revert_message"] = error_msg
                diag["revert_source"] = "eth_call"

            return ReplayResult(
                success=False,
                tx_hash=tx["hash"].hex(),
                block_number=block_number,
                error=error_msg,
                replay_mode=(
                    "eth_call_same_block_override"
                    if use_same_block_overrides
                    else "eth_call"
                ),
                diagnostics=diag,
                trace_analysis=(
                    trace_analysis.to_summary_dict() if trace_analysis else None
                ),
            )

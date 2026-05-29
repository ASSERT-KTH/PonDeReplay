"""
Anvil-backed indexed replay: fork at block-1, replay prior same-block txs, then target.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional

import requests
from web3 import Web3

from .replayer import ReplayResult
from .revert_decode import apply_revert_to_diagnostics, resolve_revert_details
from .utils import verbose_log


def _rpc_call(url: str, method: str, params: list) -> Any:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    r = requests.post(url, json=payload, timeout=120)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data.get("result")


def _wait_for_rpc(url: str, timeout_sec: float = 30.0) -> None:
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        try:
            _rpc_call(url, "eth_blockNumber", [])
            return
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"Anvil did not become ready at {url}")


def _normalize_bytecode(bytecode: str) -> str:
    if not bytecode.startswith("0x"):
        return "0x" + bytecode
    return bytecode


def _to_rpc_hex(value: Any) -> str:
    """Convert web3 HexBytes/int values to JSON-safe 0x-prefixed hex strings."""
    if value is None:
        return "0x"
    if isinstance(value, int):
        return hex(value)
    if hasattr(value, "hex"):
        h = value.hex()
        return h if h.startswith("0x") else "0x" + h
    if isinstance(value, str):
        return value if value.startswith("0x") else "0x" + value
    return str(value)


def _rpc_try(url: str, method: str, params: list) -> Any:
    """Best-effort JSON-RPC call that never raises."""
    try:
        return _rpc_call(url, method, params)
    except Exception:
        return None


def _rpc_succeeded(url: str, method: str, params: list) -> bool:
    """True if RPC completed without error (result may be null)."""
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    try:
        r = requests.post(url, json=payload, timeout=120)
        r.raise_for_status()
        data = r.json()
        return "error" not in data
    except Exception:
        return False


def _find_free_port(host: str, start: int, end: int) -> int:
    """Pick the first free TCP port in [start, end). Raises if none found."""
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind((host, port))
            except OSError:
                continue
            return port
    raise RuntimeError(
        f"No free port available in range [{start}, {end}) on {host}"
    )


def normalize_block_timestamp(timestamp: int) -> int:
    """
    Normalize block timestamp to Unix seconds.

    Some RPC paths return millisecond values; values above ~1e12 are treated as ms.
    """
    ts = int(timestamp)
    if ts > 1_000_000_000_000:
        return ts // 1000
    return ts


class AnvilIndexedReplayer:
    """Replay using a local Anvil fork with same-block transaction ordering."""

    def __init__(
        self,
        fork_url: str,
        anvil_bin: str = "anvil",
        port: int = 8545,
        host: str = "127.0.0.1",
        *,
        bump_gas_for_patch: bool = False,
        auto_port: bool = True,
        port_range: int = 100,
    ):
        self.fork_url = fork_url
        self.anvil_bin = anvil_bin
        self.port = port
        self.host = host
        self.bump_gas_for_patch = bump_gas_for_patch
        self.auto_port = auto_port
        self.port_range = port_range
        self.rpc_url = f"http://{host}:{port}"
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "AnvilIndexedReplayer":
        return self

    def __exit__(self, *args: Any) -> None:
        self.stop()

    def start(self, fork_block: int) -> None:
        if shutil.which(self.anvil_bin) is None:
            raise FileNotFoundError(
                f"{self.anvil_bin} not found on PATH; install Foundry (foundryup)"
            )
        if self.auto_port:
            self.port = _find_free_port(
                self.host, self.port, self.port + self.port_range
            )
            self.rpc_url = f"http://{self.host}:{self.port}"
        cmd = [
            self.anvil_bin,
            "--fork-url",
            self.fork_url,
            "--fork-block-number",
            str(fork_block),
            "--port",
            str(self.port),
            "--host",
            self.host,
            "--auto-impersonate",
            "--silent",
        ]
        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_rpc(self.rpc_url)
        except Exception:
            self.stop()
            raise

        # Verify the Anvil we are talking to is actually OUR Anvil
        # (catches stale instances on the same port or fork misalignment).
        try:
            head_hex = _rpc_call(self.rpc_url, "eth_blockNumber", [])
            head = int(head_hex, 16) if isinstance(head_hex, str) else int(head_hex)
        except Exception as exc:
            self.stop()
            raise RuntimeError(
                f"Anvil at {self.rpc_url} not responding to eth_blockNumber: {exc}"
            ) from exc
        if head != fork_block:
            self.stop()
            raise RuntimeError(
                f"Anvil head block {head} does not match fork_block {fork_block} "
                f"at {self.rpc_url}. A stale Anvil may be bound to this port."
            )

    def stop(self) -> None:
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def _impersonate(self, address: str) -> None:
        _rpc_call(
            self.rpc_url,
            "anvil_impersonateAccount",
            [Web3.to_checksum_address(address)],
        )

    def _set_code(self, address: str, bytecode: str) -> None:
        _rpc_call(
            self.rpc_url,
            "anvil_setCode",
            [Web3.to_checksum_address(address), _normalize_bytecode(bytecode)],
        )

    def _set_next_timestamp_seconds(self, timestamp_sec: int) -> bool:
        """
        Set next mined block timestamp (Unix seconds only).

        Anvil rejects timestamps lower than the current head. We surface that
        rather than silently swallowing it, because subsequent replay would
        execute against the wrong block.timestamp.
        """
        ts = normalize_block_timestamp(timestamp_sec)
        val_hex = hex(ts)
        last_error: Optional[str] = None
        for method in ("evm_setNextBlockTimestamp", "anvil_setNextBlockTimestamp"):
            payload = {"jsonrpc": "2.0", "method": method, "params": [val_hex], "id": 1}
            try:
                r = requests.post(self.rpc_url, json=payload, timeout=120)
                r.raise_for_status()
                data = r.json()
            except Exception as exc:
                last_error = str(exc)
                continue
            if "error" not in data:
                return True
            last_error = (data.get("error") or {}).get("message") or str(data["error"])
        self._last_timestamp_error = last_error
        return False

    def _set_automine(self, enabled: bool) -> bool:
        for method in ("anvil_setAutomine", "evm_setAutomine"):
            if _rpc_succeeded(self.rpc_url, method, [enabled]):
                return True
        return False

    def _mine_blocks(self, count: int = 1) -> bool:
        for method in ("evm_mine", "anvil_mine"):
            if _rpc_succeeded(self.rpc_url, method, [hex(count)]):
                return True
        if count == 1 and _rpc_succeeded(self.rpc_url, "evm_mine", []):
            return True
        return False

    def _set_block_context(self, source_block: dict, strict: bool = False) -> Dict[str, Any]:
        """Best-effort alignment of timestamp/baseFee/coinbase with source block."""
        out: Dict[str, Any] = {
            "timestamp_applied": False,
            "basefee_applied": False,
            "coinbase_applied": False,
            "timestamp_error": None,
        }
        ts = normalize_block_timestamp(int(source_block.get("timestamp", 0)))
        applied = self._set_next_timestamp_seconds(ts)
        out["timestamp_applied"] = applied
        if not applied:
            out["timestamp_error"] = getattr(self, "_last_timestamp_error", None)

        if strict:
            base_fee = source_block.get("baseFeePerGas")
            if base_fee is not None:
                out["basefee_applied"] = _rpc_succeeded(
                    self.rpc_url,
                    "anvil_setNextBlockBaseFeePerGas",
                    [_to_rpc_hex(base_fee)],
                )
            miner = source_block.get("miner")
            if miner:
                out["coinbase_applied"] = _rpc_succeeded(
                    self.rpc_url,
                    "anvil_setCoinbase",
                    [Web3.to_checksum_address(miner)],
                )
        return out

    def _replay_gas_limit(
        self, local: Web3, tx: dict, *, bytecode_override: bool = False
    ) -> tuple[int, Optional[int], bool]:
        """
        Use source tx gas unless patched bytecode needs more headroom (estimate or +10%).
        """
        original = int(tx.get("gas") or 0)
        if not bytecode_override or original <= 0:
            return original, None, False

        block = local.eth.get_block("latest")
        cap = max(int(block.get("gasLimit", 30_000_000)) - 50_000, original)
        estimate: Optional[int] = None
        try:
            estimate = int(
                local.eth.estimate_gas(
                    {
                        "from": Web3.to_checksum_address(tx["from"]),
                        "to": (
                            Web3.to_checksum_address(tx["to"])
                            if tx.get("to") is not None
                            else None
                        ),
                        "value": tx.get("value", 0),
                        "data": tx.get("input") or b"",
                    }
                )
            )
        except Exception:
            estimate = None

        if estimate and estimate > int(original * 0.98):
            bumped = min(int(estimate * 1.12) + 50_000, cap)
        else:
            bumped = min(int(original * 1.1) + 100_000, cap)

        if bumped > original:
            return bumped, estimate, True
        return original, estimate, False

    def _send_tx_like(self, tx: dict, *, gas: Optional[int] = None) -> str:
        self._impersonate(tx["from"])
        gas_limit = gas if gas is not None else tx.get("gas")
        params: Dict[str, Any] = {
            "from": Web3.to_checksum_address(tx["from"]),
            "to": (
                Web3.to_checksum_address(tx["to"]) if tx.get("to") is not None else None
            ),
            "value": _to_rpc_hex(tx.get("value", 0)),
            "data": _to_rpc_hex(tx.get("input") or "0x"),
            "gas": _to_rpc_hex(gas_limit),
        }
        if tx.get("maxFeePerGas") is not None:
            params["maxFeePerGas"] = _to_rpc_hex(tx["maxFeePerGas"])
            params["maxPriorityFeePerGas"] = _to_rpc_hex(
                tx.get("maxPriorityFeePerGas", 0)
            )
        elif tx.get("gasPrice") is not None:
            params["gasPrice"] = _to_rpc_hex(tx["gasPrice"])
        return _rpc_call(self.rpc_url, "eth_sendTransaction", [params])

    def _tx_params_from_source_tx(self, tx: dict) -> Dict[str, Any]:
        params: Dict[str, Any] = {
            "from": Web3.to_checksum_address(tx["from"]),
            "to": (Web3.to_checksum_address(tx["to"]) if tx.get("to") is not None else None),
            "value": _to_rpc_hex(tx.get("value", 0)),
            "data": _to_rpc_hex(tx.get("input") or "0x"),
            "gas": _to_rpc_hex(tx.get("gas")),
        }
        if tx.get("maxFeePerGas") is not None:
            params["maxFeePerGas"] = _to_rpc_hex(tx["maxFeePerGas"])
            params["maxPriorityFeePerGas"] = _to_rpc_hex(tx.get("maxPriorityFeePerGas", 0))
        elif tx.get("gasPrice") is not None:
            params["gasPrice"] = _to_rpc_hex(tx["gasPrice"])
        return params

    def _replay_sequential_same_timestamp(
        self,
        w3_source: Web3,
        tx: dict,
        prior_tx_hashes: List[str],
        contract_address: str,
        bytecode: str,
        source_block: dict,
        strict_context: bool,
        verbose: bool,
    ) -> tuple[str, Web3, Dict[str, Any]]:
        """
        Replay prior txs then target with automine on, forcing the same block timestamp
        before each mine so time-dependent checks see the source block time.
        """
        source_timestamp = normalize_block_timestamp(int(source_block.get("timestamp", 0)))
        ctx_flags = self._set_block_context(source_block, strict=strict_context)
        ctx_flags["replay_strategy"] = "sequential_same_timestamp"
        ctx_flags["automine_enabled"] = self._set_automine(True)
        local = Web3(Web3.HTTPProvider(self.rpc_url))

        def _fund_if_needed(from_addr: str) -> None:
            _rpc_succeeded(
                self.rpc_url,
                "anvil_setBalance",
                [Web3.to_checksum_address(from_addr), hex(10**21)],
            )

        for i, h in enumerate(prior_tx_hashes):
            if verbose:
                verbose_log(
                    f"[*] Anvil replay prior tx {i + 1}/{len(prior_tx_hashes)}: {h}"
                )
            if source_timestamp:
                self._set_next_timestamp_seconds(source_timestamp)
            prior = w3_source.eth.get_transaction(h)
            _fund_if_needed(prior["from"])
            prior_hash = self._send_tx_like(prior)
            local.eth.wait_for_transaction_receipt(prior_hash, timeout=120)

        self._set_code(contract_address, bytecode)

        if verbose:
            verbose_log("[*] Anvil executing target transaction...")

        if source_timestamp:
            self._set_next_timestamp_seconds(source_timestamp)
        _fund_if_needed(tx["from"])
        if self.bump_gas_for_patch:
            replay_gas, gas_estimate, gas_bumped = self._replay_gas_limit(
                local, tx, bytecode_override=True
            )
        else:
            replay_gas = int(tx.get("gas") or 0)
            gas_estimate, gas_bumped = None, False
        if gas_bumped and verbose:
            verbose_log(
                f"[*] Patched bytecode replay: gas {tx.get('gas')} -> {replay_gas}"
                + (f" (estimate {gas_estimate})" if gas_estimate else "")
            )
        target_local_hash = self._send_tx_like(tx, gas=replay_gas)
        local.eth.wait_for_transaction_receipt(target_local_hash, timeout=120)

        ctx_flags["replay_gas_limit"] = replay_gas
        ctx_flags["source_gas_limit"] = int(tx.get("gas") or 0)
        ctx_flags["gas_bumped_for_patch"] = gas_bumped
        if gas_estimate is not None:
            ctx_flags["gas_estimate"] = gas_estimate

        return target_local_hash, local, ctx_flags

    def replay_indexed(
        self,
        w3_source: Web3,
        tx: dict,
        receipt: dict,
        contract_address: str,
        bytecode: str,
        prior_tx_hashes: List[str],
        strict_context: bool = False,
        verbose: bool = False,
    ) -> ReplayResult:
        """
        Fork at block-1, replay prior block txs in one mined block, patch bytecode, execute target.
        """
        block_number = int(tx["blockNumber"])
        contract_address = Web3.to_checksum_address(contract_address)
        bytecode = _normalize_bytecode(bytecode)
        source_block = w3_source.eth.get_block(block_number)
        source_timestamp = normalize_block_timestamp(int(source_block.get("timestamp", 0)))

        self.start(fork_block=block_number - 1)
        try:
            timestamp_source = "source_block"
            target_local_hash, local, ctx_flags = self._replay_sequential_same_timestamp(
                w3_source,
                tx,
                prior_tx_hashes,
                contract_address,
                bytecode,
                source_block,
                strict_context,
                verbose,
            )
            if not ctx_flags.get("timestamp_applied", False):
                timestamp_source = "anvil_default"

            mined = local.eth.get_transaction_receipt(target_local_hash)
            mined_block_number = int(mined["blockNumber"])
            local_block = local.eth.get_block(mined_block_number)
            local_timestamp = normalize_block_timestamp(int(local_block.get("timestamp", 0)))

            block_tx_count = len(local_block.get("transactions", []))
            source_tx_index = int(tx.get("transactionIndex", 0))
            mined_tx_index = int(mined.get("transactionIndex", 0))
            strategy = ctx_flags.get("replay_strategy", "sequential_same_timestamp")
            if strategy == "sequential_same_timestamp":
                # State is built by ordered execution; index-in-block is not comparable.
                same_block_batch_ok = True
            else:
                same_block_batch_ok = mined_tx_index == source_tx_index

            time_context_mismatch = bool(
                source_timestamp and local_timestamp != source_timestamp
            )
            local_status = int(mined.get("status", 0))
            onchain_status = int(receipt.get("status", 0))
            status_mismatch = local_status != onchain_status
            context_unfaithful = time_context_mismatch or not same_block_batch_ok

            # Reproduced faithfully when local outcome matches chain and block context is valid.
            success = (local_status == onchain_status) and not context_unfaithful
            tx_params = self._tx_params_from_source_tx(tx)
            revert_reason = None
            diag: Dict[str, Any] = {
                "faithfulness": "faithful" if not context_unfaithful else "context_unfaithful",
                "prior_tx_count": len(prior_tx_hashes),
                "onchain_status": onchain_status,
                "local_status": local_status,
                "status_mismatch": status_mismatch,
                "timestamp_source": timestamp_source,
                "source_block_timestamp": source_timestamp,
                "local_block_timestamp": local_timestamp,
                "time_context_mismatch": time_context_mismatch,
                "same_block_batch_ok": same_block_batch_ok,
                "mined_block_tx_count": block_tx_count,
                "source_tx_index": source_tx_index,
                "mined_tx_index": mined_tx_index,
                "context_unfaithful": context_unfaithful,
                "strict_context": strict_context,
                "replay_strategy": ctx_flags.get(
                    "replay_strategy", "sequential_same_timestamp"
                ),
                "basefee_context_applied": bool(ctx_flags.get("basefee_applied", False)),
                "coinbase_context_applied": bool(ctx_flags.get("coinbase_applied", False)),
                "automine_enabled": bool(ctx_flags.get("automine_enabled", False)),
                "timestamp_applied": bool(ctx_flags.get("timestamp_applied", False)),
                "timestamp_error": ctx_flags.get("timestamp_error"),
                "anvil_port": self.port,
                "local_tx_hash": target_local_hash,
                "source_gas_limit": ctx_flags.get("source_gas_limit"),
                "replay_gas_limit": ctx_flags.get("replay_gas_limit"),
                "gas_bumped_for_patch": ctx_flags.get("gas_bumped_for_patch"),
                "gas_estimate": ctx_flags.get("gas_estimate"),
            }

            if local_status != onchain_status:
                if local_status != 1:
                    details = resolve_revert_details(
                        self.rpc_url,
                        tx_params,
                        local_tx_hash=target_local_hash,
                        patched_address=contract_address,
                    )
                    revert_reason = apply_revert_to_diagnostics(diag, details)
                    try:
                        from .execution_outcome import trace_impl_out_of_gas

                        trace = _rpc_call(
                            self.rpc_url,
                            "debug_traceTransaction",
                            [
                                target_local_hash,
                                {"tracer": "callTracer", "timeout": "60s"},
                            ],
                        )
                        if isinstance(trace, dict) and trace_impl_out_of_gas(
                            trace, contract_address
                        ):
                            diag["trace_out_of_gas_on_impl"] = True
                            diag["local_failure_reason"] = "out_of_gas"
                            if details.message in (
                                "execution reverted",
                                revert_reason,
                            ):
                                diag["revert_message"] = "out of gas"
                                revert_reason = (
                                    "out of gas (patched bytecode needs more gas than "
                                    "source tx limit; not a patch revert)"
                                )
                    except Exception:
                        pass
                else:
                    revert_reason = (
                        f"status mismatch: on-chain={onchain_status}, local={local_status}"
                    )
            elif context_unfaithful:
                if time_context_mismatch:
                    revert_reason = (
                        f"context unfaithful: local block timestamp {local_timestamp} "
                        f"!= source {source_timestamp}"
                    )
                else:
                    revert_reason = (
                        f"context unfaithful: mined tx index {mined_tx_index} "
                        f"!= source index {source_tx_index}"
                    )

            return ReplayResult(
                success=success,
                tx_hash=tx["hash"].hex() if hasattr(tx["hash"], "hex") else str(tx["hash"]),
                block_number=block_number,
                gas_used=mined.get("gasUsed", receipt.get("gasUsed")),
                replay_mode="anvil_indexed",
                diagnostics=diag,
                error=None if success else revert_reason,
            )
        except Exception as e:
            return ReplayResult(
                success=False,
                tx_hash=tx["hash"].hex() if hasattr(tx["hash"], "hex") else str(tx["hash"]),
                block_number=block_number,
                error=str(e),
                replay_mode="anvil_indexed",
                diagnostics={
                    "faithfulness": "context_unfaithful",
                    "prior_tx_count": len(prior_tx_hashes),
                    "strict_context": strict_context,
                    "replay_strategy": "sequential_same_timestamp",
                },
            )
        finally:
            self.stop()

    @staticmethod
    def prior_tx_hashes_in_block(
        w3: Web3, block_number: int, before_index: int
    ) -> List[str]:
        block = w3.eth.get_block(block_number, full_transactions=False)
        hashes = block.get("transactions", [])
        out: List[str] = []
        for idx, h in enumerate(hashes):
            if idx >= before_index:
                break
            out.append(h.hex() if hasattr(h, "hex") else h)
        return out

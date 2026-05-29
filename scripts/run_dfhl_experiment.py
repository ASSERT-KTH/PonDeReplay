#!/usr/bin/env python3
"""
Run a small DFHL replay experiment with PonDeReplay.

For each selected contract:
- fetch tx history via `pondereplay tx-list`
- sample 10 random benign txs (excluding malicious tx)
- append malicious tx from dataset-info.json
- run `pondereplay replay-history` on the 11 txs

Outputs are written under an experiment directory.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
from eth_utils import function_signature_to_4byte_selector


DEFAULT_DATASET_INFO = Path(
    "/home/sofia/Documents/Deffensive/dfhl-invariants/resources/dataset/dataset-info.json"
)
DEFAULT_DFHL_SRC = Path("/home/sofia/Documents/Deffensive/dfhl-invariants/src")
DEFAULT_OUTPUT_DIR = Path("experiment_runs/dfhl_5x10_plus_attack")
DEFAULT_SEED = 42


def _is_tx_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value.startswith("0x")
        and len(value) == 66
        and value.lower() != "tba"
    )


def _load_dataset_info(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("dataset-info.json must be a JSON object")
    return data


def _resolve_original_hex(patch_hex: Path) -> Optional[Path]:
    """Sibling original.hex next to patch.hex when present."""
    candidate = patch_hex.parent / "original.hex"
    if candidate.exists():
        return candidate
    return None


def _classify_attack_patch(
    rpc_url: str,
    malicious_tx: str,
    contract_address: str,
    patch_hex: Path,
) -> Optional[Dict[str, Any]]:
    """Scientific original-vs-patch comparison for the attack transaction."""
    try:
        from pondereplay.replayer import TransactionReplayer
        from pondereplay.utils import read_bytecode

        replayer = TransactionReplayer(rpc_url)
        patched_bytecode = read_bytecode(str(patch_hex))
        original_path = _resolve_original_hex(patch_hex)
        original_bytecode = read_bytecode(str(original_path)) if original_path else None
        _, _, report = replayer.replay_original_and_patched(
            tx_hash=malicious_tx,
            contract_address=contract_address,
            patched_bytecode=patched_bytecode,
            original_bytecode=original_bytecode,
            verbose=False,
            is_attack_tx=True,
        )
        return report
    except Exception as exc:
        return {"classification": "inconclusive", "error": str(exc)}


def _resolve_patch_hex(dfhl_src: Path, path_in_dfhl: str) -> Optional[Path]:
    normalized = path_in_dfhl.strip().lstrip("./")
    if normalized.startswith("src/"):
        normalized = normalized[len("src/") :]
    base_dir = (dfhl_src / normalized).resolve()
    direct = base_dir / "patch.hex"
    if direct.exists():
        return direct

    nested = list(base_dir.glob("**/patch.hex"))
    if nested:
        return nested[0]
    return None


def _eligible_contracts(
    dataset_info: Dict[str, Any], dfhl_src: Path
) -> List[Dict[str, Any]]:
    eligible: List[Dict[str, Any]] = []
    for contract_id, info in dataset_info.items():
        if not isinstance(info, dict):
            continue
        path_in_dfhl = info.get("path_in_dfhl")
        mal_tx = info.get("malicious_tx_address")
        contract_addr = info.get("vulnerable_contract_address")
        if not isinstance(path_in_dfhl, str):
            continue
        if not _is_tx_hash(mal_tx):
            continue
        if not (isinstance(contract_addr, str) and contract_addr.startswith("0x")):
            continue
        patch_hex = _resolve_patch_hex(dfhl_src, path_in_dfhl)
        if patch_hex is None:
            continue
        eligible.append(
            {
                "id": contract_id,
                "path_in_dfhl": path_in_dfhl,
                "malicious_tx": mal_tx,
                "contract_address": contract_addr,
                "patch_hex": str(patch_hex),
            }
        )
    return eligible


def _run_cmd(cmd: List[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        text=True,
        capture_output=True,
        check=False,
    )


def _run_pondereplay(
    pondereplay_bin: str, subcommand_and_args: List[str], cwd: Path
) -> subprocess.CompletedProcess:
    primary_cmd = shlex.split(pondereplay_bin) + subcommand_and_args
    try:
        return _run_cmd(primary_cmd, cwd=cwd)
    except FileNotFoundError:
        fallback_cmd = [sys.executable, "-m", "pondereplay.cli"] + subcommand_and_args
        return _run_cmd(fallback_cmd, cwd=cwd)


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _select_contracts(
    eligible: List[Dict[str, Any]],
    n_contracts: int,
    seed: int,
    explicit_ids: Optional[List[str]],
) -> List[Dict[str, Any]]:
    if explicit_ids:
        by_id = {item["id"]: item for item in eligible}
        missing = [cid for cid in explicit_ids if cid not in by_id]
        if missing:
            raise ValueError(
                "Requested contract IDs are not eligible: " + ", ".join(sorted(missing))
            )
        return [by_id[cid] for cid in explicit_ids]

    if len(eligible) < n_contracts:
        raise ValueError(
            f"Not enough eligible contracts ({len(eligible)}) for requested {n_contracts}"
        )

    rng = random.Random(seed)
    return rng.sample(eligible, n_contracts)


def _load_tx_list(path: Path) -> List[str]:
    with path.open("r", encoding="utf-8") as f:
        payload = json.load(f)
    txs = payload.get("tx_hashes", []) if isinstance(payload, dict) else []
    return [tx for tx in txs if _is_tx_hash(tx)]


def _tx_selector_from_input(input_data: Optional[str]) -> Optional[str]:
    if not isinstance(input_data, str):
        return None
    if not input_data.startswith("0x"):
        return None
    if len(input_data) < 10:
        return None
    return input_data[:10].lower()


def _normalize_selector(raw_selector: str) -> str:
    s = raw_selector.strip().lower()
    if not s.startswith("0x"):
        s = f"0x{s}"
    if len(s) != 10:
        raise ValueError(f"Invalid selector '{raw_selector}': expected 4-byte hex")
    int(s[2:], 16)
    return s


def _selector_from_function_signature(signature: str) -> str:
    sig = signature.strip()
    if "(" not in sig or not sig.endswith(")"):
        raise ValueError(
            f"Invalid function signature '{signature}'. Expected e.g. transfer(address,uint256)"
        )
    selector_bytes = function_signature_to_4byte_selector(sig)
    return "0x" + selector_bytes.hex()


def _resolve_target_selectors(
    patched_function_signatures: Optional[List[str]],
    patched_selectors: Optional[List[str]],
    malicious_selector: Optional[str],
) -> List[str]:
    resolved: List[str] = []
    seen = set()

    for sig in patched_function_signatures or []:
        sel = _selector_from_function_signature(sig)
        if sel not in seen:
            resolved.append(sel)
            seen.add(sel)

    for raw_sel in patched_selectors or []:
        sel = _normalize_selector(raw_sel)
        if sel not in seen:
            resolved.append(sel)
            seen.add(sel)

    if not resolved and malicious_selector:
        resolved.append(malicious_selector)

    return resolved


def _fetch_tx_selector(
    rpc_url: str,
    tx_hash: str,
    timeout_sec: float = 8.0,
) -> Optional[str]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionByHash",
        "params": [tx_hash],
    }
    try:
        resp = requests.post(rpc_url, json=payload, timeout=timeout_sec)
        resp.raise_for_status()
        data = resp.json()
        tx_obj = data.get("result") if isinstance(data, dict) else None
        input_data = tx_obj.get("input") if isinstance(tx_obj, dict) else None
        return _tx_selector_from_input(input_data)
    except Exception:
        return None


def _sample_for_contract(
    rpc_url: str,
    tx_hashes: List[str],
    malicious_tx: str,
    benign_count: int,
    min_selector_matches: int,
    selector_scan_limit: int,
    target_selectors: Optional[List[str]],
    rng: random.Random,
) -> Tuple[List[str], List[str], Dict[str, Any]]:
    cleaned = []
    seen = set()
    malicious_lower = malicious_tx.lower()
    for tx in tx_hashes:
        low = tx.lower()
        if low == malicious_lower:
            continue
        if low in seen:
            continue
        seen.add(low)
        cleaned.append(tx)

    if len(cleaned) < benign_count:
        raise ValueError(
            f"Only {len(cleaned)} benign txs available, need {benign_count}."
        )

    mal_selector = _fetch_tx_selector(rpc_url=rpc_url, tx_hash=malicious_tx)
    selector_targets = _resolve_target_selectors(
        patched_function_signatures=None,
        patched_selectors=target_selectors,
        malicious_selector=mal_selector,
    )
    target_set = {s.lower() for s in selector_targets}
    if not target_set:
        sampled = rng.sample(cleaned, benign_count)
        quality = {
            "selection_mode": "random_fallback",
            "reason": "no target selector available",
            "malicious_selector": mal_selector,
            "target_selectors": selector_targets,
            "selector_scan_limit": selector_scan_limit,
            "selector_match_target": min_selector_matches,
            "selector_match_count": 0,
        }
        return sampled, sampled + [malicious_tx], quality

    shuffled = cleaned[:]
    rng.shuffle(shuffled)
    scan_size = min(len(shuffled), max(benign_count, selector_scan_limit))
    scanned = shuffled[:scan_size]

    selector_map: Dict[str, Optional[str]] = {}
    same_selector_pool: List[str] = []
    different_selector_pool: List[str] = []
    unknown_selector_pool: List[str] = []
    for tx in scanned:
        selector = _fetch_tx_selector(rpc_url=rpc_url, tx_hash=tx)
        selector_map[tx.lower()] = selector
        if selector is None:
            unknown_selector_pool.append(tx)
        elif selector in target_set:
            same_selector_pool.append(tx)
        else:
            different_selector_pool.append(tx)

    selected: List[str] = []
    target_same = min(min_selector_matches, benign_count)
    if len(same_selector_pool) >= target_same:
        selected.extend(rng.sample(same_selector_pool, target_same))
    else:
        selected.extend(same_selector_pool)

    remaining_needed = benign_count - len(selected)
    if remaining_needed > 0:
        filler_pool = different_selector_pool + unknown_selector_pool
        if len(filler_pool) >= remaining_needed:
            selected.extend(rng.sample(filler_pool, remaining_needed))
        else:
            selected.extend(filler_pool)

    if len(selected) < benign_count:
        selected_lower = {tx.lower() for tx in selected}
        remaining_all = [tx for tx in cleaned if tx.lower() not in selected_lower]
        selected.extend(rng.sample(remaining_all, benign_count - len(selected)))

    sampled = selected[:benign_count]
    sampled_selector_matches = sum(
        1 for tx in sampled if selector_map.get(tx.lower()) in target_set
    )
    quality = {
        "selection_mode": "selector_aware",
        "malicious_selector": mal_selector,
        "target_selectors": selector_targets,
        "selector_scan_limit": selector_scan_limit,
        "selector_scanned": scan_size,
        "selector_match_target": min_selector_matches,
        "selector_match_candidates": len(same_selector_pool),
        "selector_match_count": sampled_selector_matches,
        "selector_match_ratio": sampled_selector_matches / benign_count,
    }
    final_txs = sampled + [malicious_tx]
    return sampled, final_txs, quality


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run DFHL experiment with PonDeReplay."
    )
    parser.add_argument(
        "--dataset-info",
        default=str(DEFAULT_DATASET_INFO),
        help="Path to dataset-info.json",
    )
    parser.add_argument(
        "--dfhl-src",
        default=str(DEFAULT_DFHL_SRC),
        help="Path to dfhl-invariants src directory",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="Output directory for experiment artifacts",
    )
    parser.add_argument(
        "--contracts",
        type=int,
        default=5,
        help="Number of contracts to run",
    )
    parser.add_argument(
        "--benign-per-contract",
        type=int,
        default=10,
        help="Random benign tx count per contract",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=DEFAULT_SEED,
        help="Random seed for reproducibility",
    )
    parser.add_argument(
        "--contract-ids",
        nargs="+",
        default=None,
        help="Optional explicit dataset contract IDs to run",
    )
    parser.add_argument(
        "--network",
        default="mainnet",
        choices=["mainnet", "sepolia", "holesky"],
        help="Etherscan network for tx history",
    )
    parser.add_argument(
        "--pondereplay-bin",
        default="pondereplay",
        help="Pondereplay CLI binary name/path",
    )
    parser.add_argument(
        "--min-selector-matches",
        type=int,
        default=5,
        help="Minimum benign txs to target with malicious selector match",
    )
    parser.add_argument(
        "--selector-scan-limit",
        type=int,
        default=400,
        help="Max benign txs to inspect for selector-aware sampling",
    )
    parser.add_argument(
        "--min-selector-quality-pass",
        type=int,
        default=1,
        help=(
            "Report-only quality threshold: minimum selector matches in sampled "
            "benign txs required to avoid warning status"
        ),
    )
    parser.add_argument(
        "--patched-function",
        action="append",
        default=[],
        help=(
            "Function signature to target, e.g. transfer(address,uint256). "
            "Repeat flag for multiple functions."
        ),
    )
    parser.add_argument(
        "--patched-selector",
        action="append",
        default=[],
        help=(
            "4-byte function selector to target, e.g. 0xa9059cbb. "
            "Repeat flag for multiple selectors."
        ),
    )
    args = parser.parse_args()

    dataset_info_path = Path(args.dataset_info).resolve()
    dfhl_src_path = Path(args.dfhl_src).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if "ETH_RPC_URL" not in os.environ:
        print("ETH_RPC_URL must be set in environment.", file=sys.stderr)
        return 1
    if "ETHERSCAN_API_KEY" not in os.environ:
        print("ETHERSCAN_API_KEY must be set in environment.", file=sys.stderr)
        return 1

    dataset_info = _load_dataset_info(dataset_info_path)
    eligible = _eligible_contracts(dataset_info, dfhl_src_path)
    selected = _select_contracts(
        eligible=eligible,
        n_contracts=args.contracts,
        seed=args.seed,
        explicit_ids=args.contract_ids,
    )

    metadata = {
        "dataset_info": str(dataset_info_path),
        "dfhl_src": str(dfhl_src_path),
        "contracts_requested": args.contracts,
        "benign_per_contract": args.benign_per_contract,
        "seed": args.seed,
        "network": args.network,
        "selected_contract_ids": [x["id"] for x in selected],
        "min_selector_matches_target": args.min_selector_matches,
        "min_selector_quality_pass": args.min_selector_quality_pass,
        "patched_functions": args.patched_function,
        "patched_selectors": args.patched_selector,
    }
    _write_json(output_dir / "selected_contracts.json", metadata)

    run_summary: Dict[str, Any] = {
        "meta": metadata,
        "contracts": [],
        "totals": {
            "contracts": 0,
            "contracts_succeeded": 0,
            "contracts_failed": 0,
            "benign_total": 0,
            "benign_passed": 0,
            "benign_failed": 0,
            "attack_tx_failed_as_expected_count": 0,
        },
    }

    global_rng = random.Random(args.seed)
    repo_root = Path(__file__).resolve().parents[1]

    explicit_target_selectors = _resolve_target_selectors(
        patched_function_signatures=args.patched_function,
        patched_selectors=args.patched_selector,
        malicious_selector=None,
    )

    for c in selected:
        cid = c["id"]
        contract_dir = output_dir / cid
        contract_dir.mkdir(parents=True, exist_ok=True)

        txlist_raw_path = contract_dir / "txlist_raw.json"
        txlist_args = [
            "tx-list",
            "--rpc-url",
            os.environ["ETH_RPC_URL"],
            "--contract-address",
            c["contract_address"],
            "--etherscan-api-key",
            os.environ["ETHERSCAN_API_KEY"],
            "--etherscan-network",
            args.network,
            "--output",
            str(txlist_raw_path),
        ]
        txlist_proc = _run_pondereplay(
            pondereplay_bin=args.pondereplay_bin,
            subcommand_and_args=txlist_args,
            cwd=repo_root,
        )
        _write_text(contract_dir / "txlist.stdout.log", txlist_proc.stdout)
        _write_text(contract_dir / "txlist.stderr.log", txlist_proc.stderr)
        if txlist_proc.returncode != 0:
            run_summary["contracts"].append(
                {
                    "id": cid,
                    "status": "error",
                    "stage": "tx-list",
                    "contract_address": c["contract_address"],
                    "malicious_tx": c["malicious_tx"],
                    "error": "tx-list command failed",
                }
            )
            run_summary["totals"]["contracts"] += 1
            run_summary["totals"]["contracts_failed"] += 1
            continue

        tx_hashes = _load_tx_list(txlist_raw_path)
        try:
            benign_sampled, final_txs, selection_quality = _sample_for_contract(
                rpc_url=os.environ["ETH_RPC_URL"],
                tx_hashes=tx_hashes,
                malicious_tx=c["malicious_tx"],
                benign_count=args.benign_per_contract,
                min_selector_matches=args.min_selector_matches,
                selector_scan_limit=args.selector_scan_limit,
                target_selectors=explicit_target_selectors,
                rng=global_rng,
            )
        except ValueError as exc:
            run_summary["contracts"].append(
                {
                    "id": cid,
                    "status": "error",
                    "stage": "sampling",
                    "contract_address": c["contract_address"],
                    "malicious_tx": c["malicious_tx"],
                    "error": str(exc),
                    "tx_history_count": len(tx_hashes),
                }
            )
            run_summary["totals"]["contracts"] += 1
            run_summary["totals"]["contracts_failed"] += 1
            continue

        replay_input = {
            "contract_id": cid,
            "contract_address": c["contract_address"],
            "malicious_tx": c["malicious_tx"],
            "benign_sampled": benign_sampled,
            "tx_hashes": final_txs,
            "patch_hex_path": c["patch_hex"],
            "selection_quality": selection_quality,
        }
        txs_path = contract_dir / "txs.json"
        _write_json(txs_path, replay_input["tx_hashes"])
        _write_json(contract_dir / "replay_input.json", replay_input)

        replay_args = [
            "replay-history",
            "--rpc-url",
            os.environ["ETH_RPC_URL"],
            "--contract-address",
            c["contract_address"],
            "--tx-list-file",
            str(txs_path),
            "--bytecode-file",
            c["patch_hex"],
            "--attack-tx",
            c["malicious_tx"],
            "--output",
            "json",
        ]
        replay_proc = _run_pondereplay(
            pondereplay_bin=args.pondereplay_bin,
            subcommand_and_args=replay_args,
            cwd=repo_root,
        )
        _write_text(contract_dir / "replay.stdout.log", replay_proc.stdout)
        _write_text(contract_dir / "replay.stderr.log", replay_proc.stderr)

        run_summary["totals"]["contracts"] += 1
        if replay_proc.returncode != 0:
            run_summary["contracts"].append(
                {
                    "id": cid,
                    "status": "error",
                    "stage": "replay-history",
                    "contract_address": c["contract_address"],
                    "malicious_tx": c["malicious_tx"],
                    "benign_sampled": benign_sampled,
                    "error": "replay-history command failed",
                }
            )
            run_summary["totals"]["contracts_failed"] += 1
            continue

        try:
            replay_result = json.loads(replay_proc.stdout.strip())
        except json.JSONDecodeError:
            run_summary["contracts"].append(
                {
                    "id": cid,
                    "status": "error",
                    "stage": "parse-replay-output",
                    "contract_address": c["contract_address"],
                    "malicious_tx": c["malicious_tx"],
                    "benign_sampled": benign_sampled,
                    "error": "Could not parse replay-history JSON output",
                }
            )
            run_summary["totals"]["contracts_failed"] += 1
            continue

        _write_json(contract_dir / "replay-result.json", replay_result)

        patch_classification = _classify_attack_patch(
            rpc_url=os.environ["ETH_RPC_URL"],
            malicious_tx=c["malicious_tx"],
            contract_address=c["contract_address"],
            patch_hex=Path(c["patch_hex"]),
        )
        if patch_classification:
            _write_json(
                contract_dir / "patch-classification.json", patch_classification
            )

        failed_txs = {tx.lower() for tx in replay_result.get("failed_txs", [])}
        benign_failed = sum(1 for tx in benign_sampled if tx.lower() in failed_txs)
        benign_passed = len(benign_sampled) - benign_failed
        attack_failed_as_expected = bool(
            replay_result.get("attack_tx_failed_as_expected", False)
        )

        run_summary["contracts"].append(
            {
                "id": cid,
                "status": (
                    "ok"
                    if selection_quality.get("selector_match_count", 0)
                    >= args.min_selector_quality_pass
                    else "ok_with_warning"
                ),
                "contract_address": c["contract_address"],
                "malicious_tx": c["malicious_tx"],
                "patch_hex_path": c["patch_hex"],
                "benign_sampled": benign_sampled,
                "selection_quality": selection_quality,
                "warnings": (
                    []
                    if selection_quality.get("selector_match_count", 0)
                    >= args.min_selector_quality_pass
                    else [
                        (
                            "Low selector coverage: sampled benign txs may not "
                            "exercise patched entrypoint reliably."
                        )
                    ]
                ),
                "replay_result": replay_result,
                "patch_classification": (
                    patch_classification.get("classification")
                    if patch_classification
                    else None
                ),
                "patch_classification_report": patch_classification,
                "metrics": {
                    "benign_total": len(benign_sampled),
                    "benign_passed": benign_passed,
                    "benign_failed": benign_failed,
                    "attack_tx_failed_as_expected": attack_failed_as_expected,
                },
            }
        )
        run_summary["totals"]["contracts_succeeded"] += 1
        run_summary["totals"]["benign_total"] += len(benign_sampled)
        run_summary["totals"]["benign_passed"] += benign_passed
        run_summary["totals"]["benign_failed"] += benign_failed
        if attack_failed_as_expected:
            run_summary["totals"]["attack_tx_failed_as_expected_count"] += 1

    _write_json(output_dir / "summary.json", run_summary)

    print(f"Experiment completed. Output: {output_dir}")
    print(f"Selected contracts: {', '.join(metadata['selected_contract_ids'])}")
    print(
        "Contracts OK/failed: "
        f"{run_summary['totals']['contracts_succeeded']}/"
        f"{run_summary['totals']['contracts_failed']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""
Run patch verification with state comparison for a set of benign txs plus the attack tx,
and write <out_prefix>_report.json + <out_prefix>_report.md.

Generic over cases. Example (Nimbus):

    set -a && . ./.env && set +a
    python scripts/run_state_report.py \
      --label 202109_Nimbus \
      --contract 0xA0Ff0e694275023f4986dC3CA12A6eb5D6056C62 \
      --attack-tx 0x5908622ce9670fdcd7954aa098aadb3e13882f198b795c6fea5ee6fc2c802d3c \
      --benign 0xad4757...,0x30e1a8...,0x71b139...,0x9f41c6... \
      --bytecode-dir /home/.../dfhl-invariants/src/202109_Nimbus/bytecode \
      --out-prefix nimbus
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path

from web3 import Web3

from pondereplay import TransactionReplayer

REPO = Path(__file__).resolve().parents[1]


def _read_hex(path: Path) -> str:
    return path.read_text().strip()


def summarize(report: dict, orig, patched) -> dict:
    sc = report.get("state_comparison") or {}
    cr = sc.get("chain_reproduction") or {}
    fs = sc.get("failed_subcalls") or {}
    test = sc.get("test") or {}
    return {
        "classification": report.get("classification"),
        "original_success": orig.success,
        "patched_success": patched.success,
        "patched_error": patched.error,
        "state_available": sc.get("available"),
        "state_equivalent": sc.get("state_equivalent"),
        "test_critical_divergences": test.get("critical_divergence_count"),
        "live_status": sc.get("live_status"),
        "original_status": sc.get("original_status"),
        "patched_status": sc.get("patched_status"),
        "reproduces_chain": sc.get("reproduces_chain"),
        "onchain_revert_gas_induced": sc.get("onchain_revert_gas_induced"),
        "chain_mismatches": cr.get("chain_mismatch_count"),
        "tolerated_drift": cr.get("tolerated_drift_count"),
        "max_relative_drift": cr.get("max_relative_drift"),
        "failed_subcalls_match_repro": (sc.get("failed_subcalls_match") or {}).get(
            "reproduction_check"
        ),
        "context_faithful": sc.get("context_faithful"),
        "gas_limit_potentially_confounded": sc.get("gas_limit_potentially_confounded"),
        "failed_subcalls": {
            "original": fs.get("original"),
            "patched": fs.get("patched"),
            "live": fs.get("live"),
        },
    }


def write_outputs(results: list, meta: dict, json_out: Path, md_out: Path) -> None:
    json_out.write_text(json.dumps({"meta": meta, "results": results}, indent=2))

    lines = [
        f"# {meta['label']} patch verification — state comparison report\n",
        f"- Generated: {meta['generated']}",
        f"- Contract (patched): `{meta['contract']}`",
        f"- Attack tx: `{meta['attack_tx']}`",
        "- Archive replay via Anvil; `--compare-state` enabled\n",
        "## Legend\n",
        "Runs compared: **L** = live (real on-chain), **O** = original-bytecode replay, "
        "**P** = patched-bytecode replay. Each column says which runs it compares: "
        "`(O→P)` = the patch test, `(O→L)` = the reproduction check, `(L/O/P)` = each run "
        "separately. Read left→right: identity, then **replay validity (O→L)** — if the "
        "replay is too far from live the rest is moot — then the **patch's effect (O→P)**, "
        "then the verdict.\n",
        "- **tx status (L/O/P)**: top-level outcome (`success`/`reverted`) of each run.",
        "- **reproduces chain (O→L)**: did the original replay reproduce the real on-chain "
        "tx structurally (status / accounts touched / code)? `no` ⇒ `inconclusive`.",
        "- **O→L struct/drift**: original vs live — *structural* mismatches (fail "
        "`reproduces chain`) `/` *tolerated* storage drift (address/numeric/opaque "
        "within ≤10%; informational).",
        "- **max drift (O→L)**: worst relative numeric storage error in the reproduction check.",
        "- **patch effect (O→P)**: original replay vs. patched replay — `preserved` (the "
        "patch changed nothing) or `changed` (the patch altered the state effect). Benign: "
        "`preserved` is good. Attack: `changed` means the exploit was neutralized.",
        "- **O→P mismatches**: count of storage/log/balance fields that differ between the "
        "original and patched replay (the substance behind `changed`; for benign txs this "
        "is what to inspect).",
        "- **failed subcalls (L/O/P)**: inner calls that reverted in each run; P > O at "
        "equal top-level status signals an exploit blocked in a swallowed sub-call.",
        "- **classification**: the verdict (`preserved` / `needs_inspection` / "
        "`effective_patch` / `ineffective_patch` / `inconclusive`).",
        "- `—` / `None` ⇒ not measured (no state capture).\n",
        "## Summary\n",
        "| tx | kind | tx status (L/O/P) | reproduces chain (O→L) | O→L struct/drift "
        "| max drift (O→L) | patch effect (O→P) | O→P mismatches | failed subcalls (L/O/P) | classification |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]

    def _effect(v):
        return {True: "preserved", False: "changed"}.get(v, "—")

    def _reproduces(v):
        return {True: "yes", False: "no"}.get(v, "—")

    def _st(v):
        return {1: "success", 0: "reverted"}.get(v, "—")

    def _statuses(s):
        return (
            f"{_st(s.get('live_status'))}/{_st(s.get('original_status'))}"
            f"/{_st(s.get('patched_status'))}"
        )

    def _n(v):
        return "—" if v is None else v

    for r in results:
        s = r.get("summary") or {}
        fs = s.get("failed_subcalls") or {}
        if r.get("error"):
            lines.append(
                f"| `{r['tx'][:10]}…` | {r['kind']} | - | - | - | - | - | - | - | ERROR |"
            )
            continue
        lines.append(
            f"| `{r['tx'][:10]}…` | {r['kind']} "
            f"| {_statuses(s)} "
            f"| {_reproduces(s.get('reproduces_chain'))} "
            f"| {_n(s.get('chain_mismatches'))}/{_n(s.get('tolerated_drift'))} "
            f"| {_n(s.get('max_relative_drift'))} "
            f"| {_effect(s.get('state_equivalent'))} "
            f"| {_n(s.get('test_critical_divergences'))} "
            f"| {_n(fs.get('live'))}/{_n(fs.get('original'))}/{_n(fs.get('patched'))} "
            f"| **{s.get('classification')}** |"
        )

    lines.append("\n## Per-tx detail\n")
    for r in results:
        lines.append(f"### `{r['tx']}` ({r['kind']})\n")
        if r.get("error"):
            lines.append(f"- **error:** {r['error']}\n")
            continue
        s = r["summary"]
        lines.append(f"- classification: **{s['classification']}**")
        lines.append(f"- tx status (live/orig/patch): **{_statuses(s)}**")
        if s.get("patched_error"):
            lines.append(f"- patched error: `{s['patched_error']}`")
        lines.append(
            f"- patch effect (patched vs original): "
            f"**{_effect(s['state_equivalent'])}** "
            f"(state mismatches={_n(s['test_critical_divergences'])})"
        )
        lines.append(
            f"- reproduces chain (replay vs live): **{_reproduces(s['reproduces_chain'])}** "
            f"(chain mismatches={_n(s['chain_mismatches'])}, "
            f"tolerated drift={_n(s['tolerated_drift'])}, "
            f"max relative drift={_n(s.get('max_relative_drift'))})"
        )
        if s.get("onchain_revert_gas_induced"):
            lines.append(
                "- ⛽ on-chain revert was **gas/OOG-induced**: the live tx reverted but "
                "the gas-bumped replay completes — reproduction mismatch is a gas artifact, "
                "not behavioral. Revert-preservation can't be observed under the bump."
            )
        fs = s["failed_subcalls"]
        lines.append(
            f"- failed subcalls (live/orig/patch): "
            f"{_n(fs.get('live'))}/{_n(fs.get('original'))}/{_n(fs.get('patched'))}"
        )
        lines.append(f"- elapsed: {r.get('elapsed_sec')}s\n")

    md_out.write_text("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label")
    ap.add_argument("--contract")
    ap.add_argument("--attack-tx")
    ap.add_argument("--benign", help="comma-separated tx hashes")
    ap.add_argument("--bytecode-dir")
    ap.add_argument("--out-prefix", required=True)
    ap.add_argument("--patch-name", default="patch.hex")
    ap.add_argument("--original-name", default="original.hex")
    ap.add_argument(
        "--strict-anvil",
        action="store_true",
        help="Force strict Anvil block-context alignment (timestamp-sensitive cases)",
    )
    # Auto-derive everything from a dfhl-invariants case's analysis.json.
    ap.add_argument("--dfhl-case", help="e.g. 202201_Anyswap")
    ap.add_argument(
        "--dfhl-root", default="/home/sofia/Documents/Deffensive/dfhl-invariants"
    )
    ap.add_argument("--num-benign", type=int, default=5)
    args = ap.parse_args()

    rpc = os.environ.get("ETH_RPC_URL")
    if not rpc:
        print("ETH_RPC_URL not set", file=sys.stderr)
        return 1
    w3 = Web3(Web3.HTTPProvider(rpc))

    if args.dfhl_case:
        root = Path(args.dfhl_root)
        analysis = json.load(open(root / "replay" / args.dfhl_case / "analysis.json"))
        args.label = args.label or args.dfhl_case
        args.contract = analysis["contract_address"]
        args.attack_tx = analysis["malicious_tx"]
        args.bytecode_dir = args.bytecode_dir or str(
            root / "src" / args.dfhl_case / "bytecode"
        )
        attack_block = next(
            (
                t.get("block_number")
                for t in analysis["tx_results"]
                if t["tx_hash"].lower() == args.attack_tx.lower()
            ),
            None,
        )
        picked = []
        for t in analysis["tx_results"]:
            if t.get("is_malicious") or t.get("onchain_reverted"):
                continue
            if attack_block and (t.get("block_number") or 0) >= attack_block:
                continue
            picked.append(t["tx_hash"])
            if len(picked) >= args.num_benign:
                break
        args.benign = ",".join(picked)
        print(f"[dfhl] {args.dfhl_case}: contract={args.contract}")
        print(f"[dfhl] attack={args.attack_tx}")
        print(f"[dfhl] benign={picked}", flush=True)

    for req in ("label", "contract", "attack_tx", "benign", "bytecode_dir"):
        if not getattr(args, req):
            ap.error(f"--{req.replace('_','-')} is required (or use --dfhl-case)")

    bdir = Path(args.bytecode_dir)
    patched_bc = _read_hex(bdir / args.patch_name)
    original_bc = _read_hex(bdir / args.original_name)

    benign = [h.strip() for h in args.benign.split(",") if h.strip()]
    targets = [(h, "benign", False) for h in benign] + [
        (args.attack_tx, "attack", True)
    ]

    json_out = REPO / f"{args.out_prefix}_report.json"
    md_out = REPO / f"{args.out_prefix}_report.md"
    meta = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "label": args.label,
        "count": len(targets),
        "contract": args.contract,
        "attack_tx": args.attack_tx,
    }

    replayer = TransactionReplayer(
        rpc,
        prefer_anvil_when_escalated=True,
        compare_state=True,
        strict_anvil_context=args.strict_anvil,
    )
    meta["strict_anvil"] = args.strict_anvil

    results: list = []
    for i, (txh, kind, is_attack) in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {kind} {txh} ...", flush=True)
        t0 = time.time()
        rec: dict = {"tx": txh, "kind": kind}
        try:
            try:
                rec["block"] = int(w3.eth.get_transaction(txh)["blockNumber"])
                rec["onchain_status"] = int(
                    w3.eth.get_transaction_receipt(txh)["status"]
                )
            except Exception:
                pass
            orig, patched, report = replayer.replay_original_and_patched(
                tx_hash=txh,
                contract_address=args.contract,
                patched_bytecode=patched_bc,
                original_bytecode=original_bc,
                is_attack_tx=is_attack,
            )
            rec["summary"] = summarize(report, orig, patched)
            rec["report"] = report
            print(
                f"    -> {rec['summary']['classification']} "
                f"(equiv={rec['summary']['state_equivalent']}, "
                f"reproduces_chain={rec['summary']['reproduces_chain']})",
                flush=True,
            )
        except Exception as e:
            rec["error"] = str(e)
            rec["traceback"] = traceback.format_exc()
            print(f"    -> ERROR: {e}", flush=True)
        rec["elapsed_sec"] = round(time.time() - t0, 1)
        results.append(rec)
        write_outputs(results, meta, json_out, md_out)

    print(f"Done. Wrote {json_out.name} and {md_out.name}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

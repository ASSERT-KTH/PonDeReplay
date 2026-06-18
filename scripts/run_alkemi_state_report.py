#!/usr/bin/env python3
"""
Run AlkemiEarn patch verification with state comparison for a sample of benign txs
plus the attack tx, and write alkemi_report.json + alkemi_report.md.

Usage:
    set -a && . ./.env && set +a
    python scripts/run_alkemi_state_report.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

from web3 import Web3

from pondereplay import TransactionReplayer

REPO = Path(__file__).resolve().parents[1]
BYTECODE = Path(
    "/home/sofia/Documents/Deffensive/dfhl-invariants/src/202603_AlkemiEarn/bytecode"
)
IMPL = "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7"  # patch applies here (delegatecall)
ATTACK = "0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d"

BENIGN = [
    "0xff7cd2c9eb97bf6454d65285ad5f888657a0f628c9f5f53e1fe7540c4b9eb3fa",
    "0xb25ba9f3926b110239fca7b3819280ade969e19e2787abc755fcbf885c658c02",
    "0xf27ed45e83b8207809b411dd3ea35641d04b433a6868a043219d38782facf966",
    "0x30d27207ae96929dd379361ed62dadf7c35c69b23f31317d706137d281b9c51c",
    "0x1a961e196aaa8fc716679f7c69b41f4e05a72941b263f38420561a9de0a6e923",
]

JSON_OUT = REPO / "alkemi_report.json"
MD_OUT = REPO / "alkemi_report.md"


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
        "reproduces_chain": sc.get("reproduces_chain"),
        "chain_mismatches": cr.get("chain_mismatch_count"),
        "tolerated_drift": cr.get("tolerated_drift_count"),
        "context_faithful": sc.get("context_faithful"),
        "gas_limit_potentially_confounded": sc.get("gas_limit_potentially_confounded"),
        "failed_subcalls": {
            "original": fs.get("original"),
            "patched": fs.get("patched"),
            "live": fs.get("live"),
        },
    }


def write_outputs(results: list, meta: dict) -> None:
    JSON_OUT.write_text(json.dumps({"meta": meta, "results": results}, indent=2))

    lines = []
    lines.append("# AlkemiEarn patch verification — state comparison report\n")
    lines.append(f"- Generated: {meta['generated']}")
    lines.append(f"- Implementation (patched): `{IMPL}`")
    lines.append(f"- Attack tx: `{ATTACK}`")
    lines.append(f"- RPC archive replay via Anvil; `--compare-state` enabled\n")

    lines.append("## Summary\n")
    lines.append(
        "| tx | kind | classification | live status | patch effect | reproduces chain "
        "| chain mismatches/tolerated drift | failed subcalls (orig/patch/live) |"
    )
    lines.append("|---|---|---|---|---|---|---|---|")
    _ls = {1: "success", 0: "reverted"}
    _eff = {True: "preserved", False: "changed"}
    _rc = {True: "yes", False: "no"}
    for r in results:
        s = r.get("summary") or {}
        fs = s.get("failed_subcalls") or {}
        if r.get("error"):
            lines.append(
                f"| `{r['tx'][:10]}…` | {r['kind']} | ERROR | - | - | - | - | - |"
            )
            continue
        lines.append(
            f"| `{r['tx'][:10]}…` | {r['kind']} | **{s.get('classification')}** "
            f"| {_ls.get(s.get('live_status'), '—')} "
            f"| {_eff.get(s.get('state_equivalent'), '—')} "
            f"| {_rc.get(s.get('reproduces_chain'), '—')} "
            f"| {s.get('chain_mismatches')}/{s.get('tolerated_drift')} "
            f"| {fs.get('original')}/{fs.get('patched')}/{fs.get('live')} |"
        )

    lines.append("\n## Per-tx detail\n")
    for r in results:
        lines.append(f"### `{r['tx']}` ({r['kind']})\n")
        if r.get("error"):
            lines.append(f"- **error:** {r['error']}\n")
            continue
        s = r["summary"]
        lines.append(f"- classification: **{s['classification']}**")
        lines.append(
            f"- live tx status (on-chain): "
            f"{_ls.get(s.get('live_status'), '—')}"
        )
        lines.append(
            f"- replay top-level status: original={s['original_success']}; "
            f"patched={s['patched_success']}"
        )
        if s.get("patched_error"):
            lines.append(f"- patched error: `{s['patched_error']}`")
        lines.append(
            f"- state test (patched vs original): equivalent={s['state_equivalent']}, "
            f"critical divergences={s['test_critical_divergences']}"
        )
        lines.append(
            f"- reproduces chain (replay vs live): {s['reproduces_chain']}, "
            f"chain mismatches={s['chain_mismatches']}, "
            f"tolerated drift={s['tolerated_drift']}"
        )
        lines.append(f"- failed subcalls: {s['failed_subcalls']}")
        lines.append(f"- elapsed: {r.get('elapsed_sec')}s\n")

    MD_OUT.write_text("\n".join(lines) + "\n")


def main() -> int:
    rpc = os.environ.get("ETH_RPC_URL")
    if not rpc:
        print("ETH_RPC_URL not set", file=sys.stderr)
        return 1
    w3 = Web3(Web3.HTTPProvider(rpc))

    patched_bc = _read_hex(BYTECODE / "patch.hex")
    original_bc = _read_hex(BYTECODE / "original.hex")

    targets = [(h, "benign", False) for h in BENIGN] + [(ATTACK, "attack", True)]
    results: list = []
    meta = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "count": len(targets),
        "implementation": IMPL,
        "attack_tx": ATTACK,
    }

    replayer = TransactionReplayer(
        rpc,
        prefer_anvil_when_escalated=True,
        compare_state=True,
    )

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
                contract_address=IMPL,
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
        # Durable incremental write after every tx.
        write_outputs(results, meta)

    print(f"Done. Wrote {JSON_OUT.name} and {MD_OUT.name}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

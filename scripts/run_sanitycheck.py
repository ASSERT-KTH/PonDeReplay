#!/usr/bin/env python3
"""
Sanity-check sweep before the full dfhl-invariants rerun.

Runs the *improved* state-comparison replay (TransactionReplayer(compare_state=True),
patched-vs-original behavioural equivalence) over every dfhl case, using:
  - up to 5 RANDOMLY sampled benign txs per case (when available), drawn from the
    case's existing dfhl-invariants/replay/<case>/analysis.json (non-malicious,
    non-reverted, mined before the attack block), and
  - the malicious tx.

Outputs, written under <out-dir> (default: sanitycheck/):
  - <case>/report.md + <case>/report.json   (per-case, same format as the root *_report.* files)
  - summary.md + summary.json               (aggregate, new-semantics columns)

This reuses scripts/run_state_report.py as the engine (summarize + write_outputs),
so per-case reports are identical in shape to the existing nimbus_report.md etc.

Example:
    set -a && . ./.env && set +a
    # smoke-test one case first:
    python scripts/run_sanitycheck.py --cases 202109_Nimbus
    # then the full sweep:
    python scripts/run_sanitycheck.py
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import traceback
from pathlib import Path

from web3 import Web3

from pondereplay import TransactionReplayer

# run_state_report.py lives in this same dir; reuse its engine.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_state_report as rsr  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
DEFAULT_DFHL_ROOT = Path("/home/sofia/Documents/Deffensive/dfhl-invariants")
DEFAULT_OUT_DIR = REPO / "sanitycheck"
DEFAULT_SEED = 42

# Cases known to be timestamp/context-sensitive — run these with strict Anvil alignment.
# (Extend if a case shows spurious replay-invalid results.)
DEFAULT_STRICT_CASES: set[str] = set()


def _eligible_benign(analysis: dict) -> list[str]:
    """Benign pool = non-malicious, non-reverted txs mined strictly before the attack block."""
    mal = (analysis.get("malicious_tx") or "").lower()
    trs = analysis.get("tx_results", []) or []
    attack_block = next(
        (t.get("block_number") for t in trs if t["tx_hash"].lower() == mal), None
    )
    pool: list[str] = []
    for t in trs:
        if t.get("is_malicious") or t.get("onchain_reverted"):
            continue
        if attack_block and (t.get("block_number") or 0) >= attack_block:
            continue
        pool.append(t["tx_hash"])
    return pool


def _attack_verdict(classification: str | None) -> str:
    return {
        "effective_patch": "✓ blocked",
        "ineffective_patch": "✗ NOT blocked",
        "inconclusive": "⚠ inconclusive",
        "unfaithful_replay": "⚠ unfaithful",
    }.get(classification or "", "ERROR")


def run_case(
    case: str,
    *,
    dfhl_root: Path,
    out_dir: Path,
    num_benign: int,
    rng: random.Random,
    rpc: str,
    w3: Web3,
    strict: bool,
) -> dict:
    """Replay one case (benign sample + attack); write per-case report; return aggregate row."""
    analysis_path = dfhl_root / "replay" / case / "analysis.json"
    analysis = json.load(open(analysis_path))
    contract = analysis["contract_address"]
    attack_tx = analysis["malicious_tx"]
    bdir = dfhl_root / "src" / case / "bytecode"
    patched_bc = rsr._read_hex(bdir / "patch.hex")
    original_bc = rsr._read_hex(bdir / "original.hex")

    pool = _eligible_benign(analysis)
    take = min(num_benign, len(pool))
    benign = rng.sample(pool, take) if take else []

    targets = [(h, "benign", False) for h in benign] + [(attack_tx, "attack", True)]
    print(
        f"\n=== {case} === contract={contract} | benign={take}/{len(pool)} | "
        f"attack={attack_tx[:12]}… | strict={strict}",
        flush=True,
    )

    case_dir = out_dir / case
    case_dir.mkdir(parents=True, exist_ok=True)
    meta = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "label": case,
        "count": len(targets),
        "contract": contract,
        "attack_tx": attack_tx,
        "strict_anvil": strict,
        "benign_sampled": benign,
        "benign_pool_size": len(pool),
        "num_benign_requested": num_benign,
    }

    replayer = TransactionReplayer(
        rpc,
        prefer_anvil_when_escalated=True,
        compare_state=True,
        strict_anvil_context=strict,
    )

    results: list = []
    for i, (txh, kind, is_attack) in enumerate(targets, 1):
        print(f"  [{i}/{len(targets)}] {kind} {txh} ...", flush=True)
        t0 = time.time()
        rec: dict = {"tx": txh, "kind": kind}
        try:
            try:
                rec["block"] = int(w3.eth.get_transaction(txh)["blockNumber"])
                rec["onchain_status"] = int(w3.eth.get_transaction_receipt(txh)["status"])
            except Exception:
                pass
            orig, patched, report = replayer.replay_original_and_patched(
                tx_hash=txh,
                contract_address=contract,
                patched_bytecode=patched_bc,
                original_bytecode=original_bc,
                is_attack_tx=is_attack,
            )
            rec["summary"] = rsr.summarize(report, orig, patched)
            rec["report"] = report
            print(
                f"      -> {rec['summary']['classification']} "
                f"(equiv={rec['summary']['state_equivalent']}, "
                f"reproduces_chain={rec['summary']['reproduces_chain']})",
                flush=True,
            )
        except Exception as e:
            rec["error"] = str(e)
            rec["traceback"] = traceback.format_exc()
            print(f"      -> ERROR: {e}", flush=True)
        rec["elapsed_sec"] = round(time.time() - t0, 1)
        results.append(rec)
        # Write incrementally so a crash mid-case still leaves a partial report.
        rsr.write_outputs(results, meta, case_dir / "report.json", case_dir / "report.md")

    # ---- build aggregate row ----
    benign_recs = [r for r in results if r.get("kind") == "benign"]
    attack_rec = next((r for r in results if r.get("kind") == "attack"), None)

    def _cls(r):
        if not r or r.get("error"):
            return None
        return (r.get("summary") or {}).get("classification")

    benign_changed = sum(1 for r in benign_recs if _cls(r) == "needs_inspection")
    benign_preserved = sum(1 for r in benign_recs if _cls(r) == "preserved")
    inconclusive = sum(
        1 for r in results if _cls(r) in ("inconclusive", "unfaithful_replay")
    )
    errors = sum(1 for r in results if r.get("error"))
    attack_cls = _cls(attack_rec)
    attack_summary = (attack_rec.get("summary") if attack_rec else {}) or {}

    return {
        "case": case,
        "contract": contract,
        "attack_tx": attack_tx,
        "tx_count": len(results),
        "benign_count": len(benign_recs),
        "benign_preserved": benign_preserved,
        "benign_changed": benign_changed,
        "inconclusive": inconclusive,
        "errors": errors,
        "attack_classification": attack_cls,
        "attack_verdict": _attack_verdict(attack_cls) if attack_rec else "ERROR",
        "attack_error": attack_rec.get("error") if attack_rec else "no attack tx",
        "attack_summary": attack_summary,
    }


def _write_summary(rows: list[dict], out_dir: Path, meta: dict) -> None:
    total_tx = sum(r["tx_count"] for r in rows)
    blocked = sum(1 for r in rows if r["attack_classification"] == "effective_patch")
    not_blocked = sum(1 for r in rows if r["attack_classification"] == "ineffective_patch")
    attack_inconcl = sum(
        1 for r in rows if r["attack_classification"] in ("inconclusive", "unfaithful_replay")
    )
    attack_err = sum(1 for r in rows if r["attack_verdict"] == "ERROR")
    benign_changed = sum(r["benign_changed"] for r in rows)
    inconclusive = sum(r["inconclusive"] for r in rows)
    errors = sum(r["errors"] for r in rows)

    (out_dir / "summary.json").write_text(
        json.dumps({"meta": meta, "totals": {
            "cases": len(rows), "transactions": total_tx,
            "attack_blocked": blocked, "attack_not_blocked": not_blocked,
            "attack_inconclusive": attack_inconcl, "attack_error": attack_err,
            "benign_changed": benign_changed, "inconclusive_txs": inconclusive,
            "errored_txs": errors,
        }, "cases": rows}, indent=2)
    )

    L: list[str] = [
        "# PonDeReplay dfhl sanity check — state-comparison sweep\n",
        f"- Generated: {meta['generated']}",
        f"- Benign source: random sample (seed {meta['seed']}) of up to "
        f"{meta['num_benign']} benign txs per case from dfhl analysis.json + the malicious tx",
        "- Engine: `TransactionReplayer(compare_state=True)` — patched-vs-original "
        "behavioural equivalence (see docs/state-comparison.md)\n",
        f"- Cases analyzed: {len(rows)}",
        f"- Transactions: {total_tx}",
        f"- Attack blocked (effective_patch): {blocked}",
        f"- Attack NOT blocked (ineffective_patch): {not_blocked}",
        f"- Attack inconclusive (replay not faithful): {attack_inconcl}",
        f"- Attack errored: {attack_err}",
        f"- Benign changed (needs_inspection — patch altered a benign tx): {benign_changed}",
        f"- Inconclusive txs (replay didn't reproduce chain): {inconclusive}",
        f"- Errored txs: {errors}\n",
        "## Legend\n",
        "- **Attack verdict**: `✓ blocked` = `effective_patch` (exploit neutralized), "
        "`✗ NOT blocked` = `ineffective_patch` (exploit still lands), "
        "`⚠ inconclusive` = replay didn't faithfully reproduce the exploit.",
        "- **❌ Benign changed**: benign txs the patch altered (`needs_inspection`) — "
        "regression or mislabeled-malicious; inspect.",
        "- **🔍 Inconclusive**: txs whose original replay didn't reproduce chain "
        "(`inconclusive`/`unfaithful_replay`); the comparison can't judge them.\n",
        "## Per-case overview\n",
        "| Case | Txs | Benign | Attack verdict | ❌ Benign changed | 🔍 Inconclusive |",
        "|------|-----|--------|----------------|-------------------|-----------------|",
    ]
    for r in rows:
        L.append(
            f"| {r['case']} | {r['tx_count']} | {r['benign_count']} "
            f"| {r['attack_verdict']} | {r['benign_changed']} | {r['inconclusive']} |"
        )

    L.append("\n## Attack tx verdicts\n")
    for r in rows:
        s = r["attack_summary"]
        L.append(f"### {r['case']} — {r['attack_verdict']}")
        L.append(f"- attack tx: `{r['attack_tx']}`")
        L.append(f"- classification: `{r['attack_classification']}`")
        if r.get("attack_error") and r["attack_verdict"] == "ERROR":
            L.append(f"- error: {r['attack_error']}")
        else:
            pe = {True: "preserved", False: "changed"}.get(s.get("state_equivalent"), "—")
            rc = {True: "yes", False: "no"}.get(s.get("reproduces_chain"), "—")
            ls = {1: "success", 0: "reverted"}.get(s.get("live_status"), "—")
            fs = s.get("failed_subcalls") or {}
            L.append(f"- live tx status (on-chain): {ls}")
            L.append(
                f"- patch effect (patched vs original): **{pe}** "
                f"(state mismatches={s.get('test_critical_divergences')})"
            )
            L.append(
                f"- reproduces chain (replay vs live): **{rc}** "
                f"(chain mismatches={s.get('chain_mismatches')}, "
                f"tolerated drift={s.get('tolerated_drift')})"
            )
            if s.get("patched_error"):
                L.append(f"- patched error: `{s['patched_error']}`")
            L.append(
                "- failed subcalls (live/orig/patch): "
                f"{fs.get('live')}/{fs.get('original')}/{fs.get('patched')}"
            )
        L.append("")

    (out_dir / "summary.md").write_text("\n".join(L) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cases", nargs="+", default=None,
                    help="Subset of dfhl case ids to run (default: all). Use for a one-case smoke test.")
    ap.add_argument("--dfhl-root", type=Path, default=DEFAULT_DFHL_ROOT)
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    ap.add_argument("--num-benign", type=int, default=5, help="Max benign txs per case (default 5).")
    ap.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Seed for random benign sampling.")
    ap.add_argument("--strict-cases", nargs="+", default=None,
                    help="Case ids to replay with strict Anvil context (timestamp-sensitive).")
    ap.add_argument("--skip-existing", action="store_true",
                    help="Skip cases that already have <out-dir>/<case>/report.json.")
    args = ap.parse_args()

    rpc = os.environ.get("ETH_RPC_URL")
    if not rpc:
        print("ETH_RPC_URL not set (do: set -a && . ./.env && set +a)", file=sys.stderr)
        return 1
    w3 = Web3(Web3.HTTPProvider(rpc))

    replay_dir = args.dfhl_root / "replay"
    all_cases = sorted(d.name for d in replay_dir.glob("*/") if (d / "analysis.json").exists())
    cases = args.cases if args.cases else all_cases
    missing = [c for c in cases if c not in all_cases]
    if missing:
        ap.error("Unknown/ineligible cases (no analysis.json): " + ", ".join(missing))

    strict_cases = set(args.strict_cases) if args.strict_cases else DEFAULT_STRICT_CASES
    args.out_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "dfhl_root": str(args.dfhl_root),
        "num_benign": args.num_benign,
        "seed": args.seed,
        "cases_requested": cases,
        "strict_cases": sorted(strict_cases),
    }

    rows: list[dict] = []
    for case in cases:
        if args.skip_existing and (args.out_dir / case / "report.json").exists():
            print(f"=== {case} === skip (report.json exists)", flush=True)
            continue
        # Per-case rng so a fixed --cases subset reproduces regardless of order.
        rng = random.Random(f"{args.seed}:{case}")
        try:
            row = run_case(
                case, dfhl_root=args.dfhl_root, out_dir=args.out_dir,
                num_benign=args.num_benign, rng=rng, rpc=rpc, w3=w3,
                strict=case in strict_cases,
            )
        except Exception as e:
            print(f"  -> CASE ERROR: {e}", flush=True)
            row = {
                "case": case, "contract": None, "attack_tx": None, "tx_count": 0,
                "benign_count": 0, "benign_preserved": 0, "benign_changed": 0,
                "inconclusive": 0, "errors": 1, "attack_classification": None,
                "attack_verdict": "ERROR", "attack_error": str(e), "attack_summary": {},
            }
        rows.append(row)
        _write_summary(rows, args.out_dir, meta)  # incremental aggregate

    print(f"\nDone. Wrote {args.out_dir}/summary.md (+ summary.json) and per-case reports.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

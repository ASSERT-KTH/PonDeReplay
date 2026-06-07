# Block-timestamp dependence in PonDeReplay

**Date:** 2026-05-28
**Scope:** Why historical transaction replays can disagree with on-chain behaviour
because of `block.timestamp`, what PonDeReplay already does about it, and the
mitigations available to a patch-verification workflow.

This document is a companion to the dfhl-invariants experiment under
`dfhl-invariants/results/pondereplay/`. Quantitative evidence cited below is
taken directly from that run.

---

## 1. The problem in one sentence

PonDeReplay's fast path executes a historical transaction with `eth_call`
against the state at block **\(N-1\)**. The EVM sees the **timestamp of block
\(N-1\)**, not the timestamp of the source block \(N\) where the transaction
actually executed. Any contract logic that reads `block.timestamp` therefore
observes a value that is **\(\sim 12\,\text{s}\) earlier** than what it saw on
chain (Ethereum mainnet's average block time post-Merge).

For most calls this is harmless. For time-sensitive contract logic it can
flip the result of the call, and therefore the verdict of the replay.

---

## 2. Why a 12-second drift can matter

Contracts that read `block.timestamp` typically use it for one of these
patterns:

| Pattern | Example | Failure mode under N-1 replay |
|---------|---------|-------------------------------|
| **Deadline check** (`require(deadline >= block.timestamp)`) | Uniswap router, lending liquidations | Looser at N-1 (earlier ts) → tx that should have hit `EXPIRED` passes |
| **Cooldown / rate limit** (`require(lastAction + window <= block.timestamp)`) | Anti-bot caps, vesting, staking unlock | Stricter at N-1 → tx that should pass reverts |
| **Mint / sale window** (`block.timestamp >= start && < end`) | NFT phases, presale gates | Either side: false negatives or false positives near the edges |
| **Oracle staleness** (`block.timestamp - oracle.updatedAt < maxAge`) | Chainlink-style feeds, Compound, AlkemiEarn | At N-1 a stale price may still pass freshness; or fresh one may look stale |
| **Auction tick / vesting schedule** | bonding curves, vesting | Tier crossing near boundary changes |
| **PRNG seeded with `block.timestamp`** | weak RNG NFTs | Different number altogether → different code path |
| **Same-block sandwich / MEV setup** | flash loan + attack tx in the same block | At N-1 the attack contract doesn't even have code |

Two things make this worse for patch verification specifically:

1. **The point of the replay is to see whether the patch's new guard fires.**
   If the guard is conditioned on `block.timestamp` (oracle freshness, time
   lock, anti-MEV cooldown), running 12 s in the past can hide the guard
   altogether and produce a `malicious_not_blocked` false negative.
2. **A patched contract often reads timestamp during `require` checks added
   by the patch itself.** The original bytecode might not care about
   timestamp, but the patched one does, so the variance is asymmetric: original
   passes fine, patch silently misbehaves.

---

## 3. Why `eth_call` cannot just be told a different timestamp

The `eth_call` JSON-RPC method:

- Accepts `state_override` (used by PonDeReplay to inject the patched
  bytecode and any same-block contract creations),
- Accepts a `blockOverrides` field on some clients (geth `>=1.13`, anvil
  recent builds) that can override `block.number`, `block.timestamp`,
  `block.coinbase`, `block.basefee`, etc.

In practice:

- Most public mainnet RPC providers (Dwellir, Alchemy free tier, Infura free
  tier, etc.) **do not expose `blockOverrides`**. Trying to use it returns
  "method not found" or silently ignores the field.
- Even when the provider supports it, it overrides the block context *for the
  duration of the call only*. It does not let earlier same-block transactions
  execute at the right timestamp.

That is why PonDeReplay's strict path is a local **Anvil fork**, not a
souped-up `eth_call`: only a local node can mine blocks with a chosen
timestamp and run prior txs against the patched state in order.

---

## 4. What PonDeReplay already does

### 4.1 Preflight warning

`pondereplay/preflight.py` records a `time/context mismatch risk` warning for
any transaction whose `tx_index > 0` or whose contract was created in the
same block as the tx. The signal is exposed on the result as
`diagnostics.warnings`.

Concrete evidence from the dfhl-invariants run:

```
202301_QTN          warnings = ["Potential time/context mismatch risk:
                                 replay at block-1 may alter time-dependent checks"]
202406_JokInTheBox  warnings = ["Potential time/context mismatch risk:
                                 replay at block-1 may alter time-dependent checks"]
```

These are exactly the two cases the experiment classified `malicious_not_blocked`.

### 4.2 Auto-strict escalation

`TransactionReplayer._should_auto_strict_escalate` fires when **the local fast
replay reverted but the on-chain receipt shows success**, or when the local
error mentions `timestamp` / `deadline` / `time`. When it fires, the replayer
forks via Anvil and replays in **strict block context**:

- `evm_setNextBlockTimestamp` to the **source block's** timestamp before each
  prior tx and again before the target tx (`sequential_same_timestamp`
  strategy in `anvil_replay.py`).
- Best-effort `anvil_setNextBlockBaseFeePerGas` and coinbase alignment.

The experiment used this path 42 times across 131 patch replays (32%) and
3 times on the original side. All 42 strict replays applied the source
timestamp successfully:

```
== Replay strategies (per variant) ==
original : {'fast_eth_call': 128, 'sequential_same_timestamp': 3}
patch    : {'fast_eth_call':  92, 'sequential_same_timestamp': 39}

Timestamp-apply failures: 0
Strict replays with timestamp drift (source != local): 0
```

### 4.3 Gas correction during strict replay (`bump_gas_for_patch`)

Strict replay frequently uses more gas than the source tx (patched bytecode
adds checks). PonDeReplay's `bump_gas_for_patch` re-estimates gas inside
Anvil before sending the target tx, so the replay does not OOG against the
source-tx gas limit. Enabling this option closed the last 2 OOG artifacts in
the dfhl run (BEC and OMP), bringing the original-side faithfulness to **100%
of expected behaviour matches chain**:

```
Before:  21/24 sound, 2 inconclusive (OOG)
After:   21/24 sound, 0 inconclusive
         orig_local_passed: 127/131 (the remaining 4 also reverted on chain)
         chain vs original-replay mismatches: 0
```

---

## 5. Where the current mitigations still fall short

| Failure mode | Status | Notes |
|--------------|--------|-------|
| Same-block contract creation | **Handled** | `same_block_code_override` injects bytecode of contracts created earlier in the block; strict mode actually mines those txs |
| Deadline / cooldown that *succeeds* on chain but *reverts* in fast replay | **Handled** | Auto-strict triggers and re-runs with source timestamp |
| Deadline / cooldown that *succeeds* on chain and *also succeeds* in fast replay despite needing timestamp alignment | **Not handled automatically** — auto-strict only fires on a mismatch, so a false PASS goes undetected (see QTN, JokInTheBox) |
| Provider lacks `blockOverrides` | Worked around | strict path uses local Anvil instead |
| Anvil refusing source timestamp because head is already past it | Detected | `_set_next_timestamp_seconds` surfaces the rejection in `timestamp_error` instead of silently mining the wrong timestamp |
| Cross-block state where the patch reads `block.timestamp` *and* a value that depends on multiple historical blocks (oracle aggregator, TWAP) | Best-effort | Strict mode aligns the immediate block's timestamp but cannot replay the entire historical chain of upstream oracles |
| Timestamp-conditioned external calls (e.g. ERC-4337 paymaster, off-chain validation pings) | **Out of scope** | Replay cannot bring back off-chain components |

The dfhl run shows the limitation in row 3 directly: QTN and JokInTheBox
malicious txs reach the patched bytecode under fast `eth_call`, the patched
guard does **not** revert (presumably because the timestamp check at N-1 is
on the wrong side of the threshold), and because the original also passes,
auto-strict never fires. Result: both cases land in `malicious_not_blocked`
even though forcing strict mode wouldn't necessarily save them — they need
*more* than timestamp alignment.

---

## 6. Concrete mitigations for the user

The recommendations are ordered from cheapest to most expensive in time/RPC budget.

### 6.1 Always enable `--bump-gas-for-patch`

It is almost free and removes the OOG-artifact class entirely. The fix is
already in `scripts/run_dfhl_full_experiment.py` — use:

```bash
python scripts/run_dfhl_full_experiment.py \
    --bump-gas-for-patch \
    --skip-existing \
    --verbose
```

Validated in this experiment: BEC and OMP moved from `inconclusive` to
`sound` after applying it.

### 6.2 Treat preflight `time/context mismatch risk` warnings as a hard signal

A practical rule: **never trust a fast `eth_call` replay that carries a
`time/context mismatch risk` warning and produces a `malicious_not_blocked`
verdict**. Re-run such transactions with `--strict-anvil` and, if the result
still says `not_blocked`, flag the case for manual review (the patch is
probably actually flawed, but you have eliminated the timestamp confound).

`scripts/run_dfhl_full_experiment.py` now exposes `--strict-anvil` exactly
for this purpose.

### 6.3 Force strict mode for an enumerated allowlist

If you know that a case is timestamp-sensitive (deadlines, oracle freshness,
mint windows), do not wait for auto-strict: run with `--strict-anvil` from
the start. For the dfhl dataset, candidate cases are anything whose
`modified_functions` involves:

- `liquidateBorrow`, `liquidate*` (oracle freshness)
- `earn`, `harvest`, `rebalance` (cooldowns)
- `swap`, `addLiquidity`, `removeLiquidity` (deadline parameter)
- `mint`, `claim`, `whitelistMint` (phase gates)
- `unstake`, `withdraw` after a lock period

The same flag can be passed per-case via `--only <case_id>` so you only pay
the Anvil cost where it matters.

### 6.4 Compare-patch with both variants in the same strict context

For the *decision* "is the patch effective on the attack tx", use
`pondereplay compare-patch --attack-tx ...` (already integrated in
`scripts/run_alkemi_experiment.sh`). That command runs original and patch
with identical preflight + same strict escalation rules, which removes the
asymmetry where one variant escalates and the other doesn't. The dfhl
script uses `replay-history` for speed; for headline patch-effectiveness
claims, `compare-patch` is more rigorous.

### 6.5 Add a "timestamp-sensitive" annotation to dataset-info.json

Right now the only way to flag a tx as timestamp-sensitive is the preflight
warning. Adding an explicit boolean (or a list of `block.timestamp` reads
detected by static analysis on the patched bytecode) to `dataset-info.json`
would let the experiment script automatically promote those cases to strict
mode without paying the cost everywhere.

Suggested shape:

```json
"202301_QTN": {
  ...
  "patch_uses_block_timestamp": true,
  "patch_deadline_param": false,
  "patch_oracle_freshness": false
}
```

The script can then opt in with something like:

```python
strict = info.get("patch_uses_block_timestamp", False) \
      or info.get("patch_oracle_freshness", False) \
      or info.get("patch_deadline_param", False)
```

### 6.6 As a last-resort safety net: detect "no_change & malicious & warning"

The current classifier treats `malicious + both succeed` as
`malicious_not_blocked`. We could split that bucket: when the preflight
warning is `time/context mismatch risk`, classify as
`malicious_not_blocked_pending_strict_review` and require a strict re-run
before reporting. This avoids labelling a case as a real false negative when
the underlying problem is the replay context, not the patch.

This would be ~10 lines in `_classify_tx`; we have the warning surfaced
already.

---

## 7. Summary

- `eth_call` at \(N-1\) sees a `block.timestamp` that is ~12 s earlier than the
  source block's. That can change `require` outcomes for deadline / cooldown
  / freshness / phase logic.
- PonDeReplay detects this risk at preflight (`time/context mismatch risk`
  warning), and auto-escalates to a local Anvil fork that mines with the
  source block's timestamp — but only when the fast replay reverts while the
  chain succeeded.
- The dfhl experiment shows the system works for the visible cases (42 of 131
  patched replays escalated successfully, 0 timestamp-apply failures), and
  that the residual `malicious_not_blocked` verdicts (QTN, JokInTheBox)
  carry the timestamp warning but require a different signal — a forced
  strict re-run or dataset-level annotation — to be re-examined.
- Combined with `--bump-gas-for-patch`, the replay reproduces every
  on-chain outcome of the 131 sampled txs (0 mismatches with chain).

The cheapest robustness wins are: enable `--bump-gas-for-patch`
unconditionally, treat the preflight time-risk warning as a hard signal,
and add an explicit `patch_uses_block_timestamp` annotation to the dataset
so timestamp-sensitive cases run strict from the start.

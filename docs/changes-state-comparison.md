# PonDeReplay: comparing transaction *effects*, not just status

**Audience:** project supervisor. **Status:** implemented on branch `claude-improve-tx-replay`
(2026-06). For the field-level reference see [`comparison-definitions.md`](comparison-definitions.md);
for the soundness design see [`state-comparison.md`](state-comparison.md).

---

## 1. What changed, in one sentence

PonDeReplay used to judge a patch by the transaction's **top-level revert/success**. It now
compares the transaction's full **state effect** — storage writes, emitted logs, balance
moves, contract code, *and* status — between the original and the patched contract, and
validates that comparison against the real chain.

## 2. Why the old signal was not enough

Revert/success is **necessary but not sufficient** for both questions we ask:

- **Benign (pre-attack) txs — "does the patch preserve behavior?"** A tx can still *succeed*
  under the patch while writing a different storage value, emitting a different event, or
  moving a different amount of tokens. Status alone would call that "preserved" — wrongly.
- **Attack txs — "does the patch stop the exploit?"** Some exploits wrap the vulnerable call
  in `try/catch` or an unchecked low-level `call`. The patch can make the **inner** call
  revert while the attacker **swallows** it and the top-level tx still returns success.
  Status alone calls that `ineffective_patch` — a **false negative**.

State comparison resolves both.

## 3. The mechanism: three executions, two comparisons

For each transaction we capture the state effect (via `prestateTracer`, `diffMode`) of **three**
executions, all forking the same block *N−1*:

| | meaning |
|---|---|
| **L** | the real on-chain transaction (ground truth) |
| **O** | the **original** (unpatched) bytecode, replayed locally on Anvil |
| **P** | the **patched** bytecode, replayed in the *identical* harness context |

From these we run two comparisons:

1. **Reproduction check — O vs L** (`reproduction_check` in code; reported as
   `reproduces_chain`). *Did our replay reproduce reality?* The patch never existed on-chain,
   so the real tx ran the original bytecode — O should structurally match L if the harness is
   faithful. **If `reproduces_chain` is false, the result is `inconclusive` and we discard
   it.**
2. **Preservation test — O vs P** (`preservation_test` in code; `state_equivalent`). *Did the
   patch change what the tx does?* This is the **decisive** signal. Both runs share the same
   fork and context, so harness artifacts cancel and any surviving difference is attributable
   to the patch.

### Why this is sound (the key argument)

The naive comparison would be *patched-replay vs. live chain* — but that **conflates** the
patch's effect with our harness's own imperfections (approximated `block.timestamp`, gas
bumping, tx ordering). Instead we compare the **two replays** in an identical context, which
**cancels every bytecode-independent artifact**, and use live only to validate O. By
transitivity:

> if **O ≈ L** (reproduces chain) and **P ≈ O** (patch test), then **P ≈ L** — the patched
> contract behaves like reality.

## 4. Critical values vs. drift — and why "drift" is sound

This is the heart of the change. **Whether a difference is *critical* or tolerable *drift* is
not a property of the field — it is decided by which comparison it appears in.**

| field | in the **preservation test (O→P)** | in the **reproduction check (O→L)** |
|---|---|---|
| status, account-scope, code create/destruct, CREATE-nonce (*structural*) | **critical** | **critical** |
| storage values, logs, non-gas balances, return data (*value-level*) | **critical** | **tolerated drift** |
| gas, coinbase reward, base-fee, sender nonce, revert text | normalized / loose | normalized / loose |

- In the **same-context preservation test**, value differences are **critical** — the two
  replays share context, so a surviving difference is genuinely the patch's doing.
- In the **cross-context reproduction check**, value differences are **drift** — a local fork
  legitimately differs from real chain on value-bearing quantities, and that difference is
  *independent of the bytecode*, so it cancels in the test and must not fail validity.

**Concrete evidence (AlkemiEarn attack tx).** When we replay the prior-tx sequence locally,
interest-accrual indices advance slightly differently than on real chain. We observed **21
interest-index storage slots + 1 derived amount** differing between O and L — but by a relative
magnitude of ~**3.7×10⁻¹²**, while the exploit itself reproduced perfectly. Counting that as a
validity failure would false-flag every faithful replay. It is tolerated as **drift** precisely
because the same-context preservation test cancels it. The *structural* facts (same accounts
code, same status) confirmed the replay was faithful.

So: the reproduction check is deliberately **structural-only** today — it tolerates all
value drift and fails only on structural divergence. **Planned calibration** (§8) adds
bounded numeric tolerance and richer reporting without making subcall count decisive.

## 5. The verdicts

The two comparisons compose into kind-specific labels (opposite polarity for benign vs. attack):

**Benign tx** — we want the effect *preserved*:
- `preserved` — replay reproduces chain **and** the patch changed nothing.
- `needs_inspection` — the patch **changed** a benign tx (different state effect, or it now
  reverts); flag for manual review (could be a regression or a mislabeled malicious tx).
- `inconclusive` — replay did not reproduce chain; we cannot judge.

**Attack tx** — we want the exploit's effect *gone*:
- `effective_patch` — exploit blocked: top-level reverts, **or** its state effect is absent
  under the patch (this is the swallowed-sub-call case the old logic missed).
- `ineffective_patch` — exploit still lands unchanged.
- `inconclusive` — replay did not reproduce the exploit.

## 6. What the report shows

Each tx gets a row ordered by relevance (L = live, O = original replay, P = patched replay):

```
tx | kind | tx status (L/O/P) | reproduces chain (O→L) | O→L struct/drift
   | patch effect (O→P) | O→P mismatches | failed subcalls (L/O/P) | classification
```

Validity (O→L) is read first — if the replay doesn't reproduce chain, the rest is moot — then
the patch's effect (O→P, including a count of differing fields), then the verdict. The full
per-execution state diffs are persisted in the JSON for manual cross-checking / the appendix.

## 7. Honest limitations

- **Performance:** state diffs are only produced by the Anvil-indexed tier, so `--compare-state`
  forces that tier (the fast `eth_call` path cannot produce them).
- **Unbounded drift tolerance (being addressed — see §8):** the reproduction check currently
  tolerates *all* value-level differences unconditionally. Calibrated storage comparison
  (10% numeric bound, exact addresses) is planned but not yet implemented.
- **Gas confound:** a patch can legitimately change the gas limit, which can perturb
  `gasleft()`-dependent control flow; such txs are tagged `gas_limit_potentially_confounded`.
- **Context faithfulness:** if the patched code reads block context the harness only
  approximates, a divergence there is context-induced, not patch-induced, and is flagged
  separately rather than counted as a behavioral change.

## 8. Planned calibration (agreed design, not yet implemented)

Closes the unbounded-drift gap on the **reproduction check (O→L)** only. The
**preservation test (O→P)** stays **exact** on value-level fields — for benign txs, any
storage/log/balance difference is **critical** (`needs_inspection`), because both replays
share the same fork and there is no harness drift to cancel.

**Failed subcall count** mismatches are reported in both comparisons but **never critical**.

### What fails each comparison

| Check | Fails (`reproduces_chain` / `state_equivalent` = false) | Reported only (never fails) |
|---|---|---|
| **Reproduction check (O→L)** | Structural list below; storage **address** mismatch; storage **numeric** mismatch **> 10%**; bool `0↔1`; opaque/hash words (exact) | Numeric storage within **≤ 10%** (`value_drift`); **failed subcall count** mismatch |
| **Preservation test (O→P)** | Structural list; **any** value-level mismatch (storage, logs, balances, return data) — **exact**, no numeric tolerance | **Failed subcall count** mismatch |

For **benign** txs, O→P equivalence means the patch changed **nothing** — even a 1-wei or
single-slot numeric nudge is critical. For **attack** txs, O→P divergence (any critical
value or structural change) is the desired signal that the exploit effect is gone.

### Structural checklist (critical in **both** comparisons)

1. Different success/revert status
2. Different set of accounts touched (excluding coinbase + sender gas artifacts)
3. Contract created/destroyed on one side only
4. Different CREATE-nonce (non-sender)

### Storage slot rules

**Reproduction check (O→L) only** — calibrated:

| Slot kind | Detection | Match rule | On mismatch |
|---|---|---|---|
| **Address** | Top 12 bytes zero, lower 20 bytes = address | Exact | **Critical** (fail) |
| **Bool** | Value is `0` or `1` only | Exact | **Critical** (fail) |
| **Opaque / hash** | Full word used, not address-shaped | Exact | **Critical** (fail) |
| **Numeric** | Everything else (`uint256`) | ≤ **10%** relative error | **Drift** if within tolerance (report `relative_error`, do **not** fail); **critical** if above |

Relative error: `|a − b| / max(|a|, |b|, 1)` (avoids division-by-zero).

**Preservation test (O→P)** — exact (current behaviour, unchanged): any storage slot
difference is **critical**, regardless of magnitude or slot kind.

### Failed subcall count (both comparisons)

Already captured per run (`failed_subcalls` in `StateCapture`). Planned: emit a
`failed_subcalls` divergence with severity **`loose`** when counts differ between the
two sides being compared. **Never critical** — corroborating signal only (e.g. swallowed
inner revert). For attack txs in the both-succeed case, effectiveness still comes from
O→P **value-level** divergence (exact), not from subcall count alone.

### Report additions

- `max_relative_drift` — worst numeric slot error in the **reproduction check** (O→L)
- `failed_subcalls_match` — `yes` / `no` / `unavailable` (per comparison pair)
- Per-divergence `relative_error` on calibrated O→L storage slots
- Separate counts: `critical_divergence_count`, `value_drift_count`, `loose_count`

### Configuration

Default `numeric_drift_tolerance = 0.10` for the reproduction check only; overridable
via API/CLI when implemented. Not applied to the preservation test.
</content>

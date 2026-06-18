# Transaction replay comparison

**Status:** implemented (2026-06). This is the single reference for how PonDeReplay
compares transaction replays — state effects, verdicts, drift tolerance, and
`block.timestamp` handling.

---

## 1. What we compare

PonDeReplay no longer judges a patch by top-level **revert/success alone**. It compares
the transaction's full **state effect** — storage writes, emitted logs, balance moves,
contract code changes, and status — between three executions and two comparison pairs.

**Why status alone is not enough**

- **Benign txs:** a tx can still succeed under the patch while writing different storage,
  emitting different events, or moving different token amounts. Status would wrongly call
  that "preserved."
- **Attack txs:** exploits often wrap the vulnerable call in `try/catch` or an unchecked
  low-level `call`. The patch can make the **inner** call revert while the attacker
  swallows it and the top-level tx still succeeds. Status alone calls that
  `ineffective_patch` — a false negative.

State comparison resolves both cases.

---

## 2. Three executions, two comparisons

For each transaction we capture the state effect (via `prestateTracer`, `diffMode: true`)
for **three** executions, all forking block *N−1*:

| Label | Capture key | Meaning |
|---|---|---|
| **L** | `live` | the real on-chain transaction (ground truth) |
| **O** | `original_replay` | unpatched bytecode, replayed locally on Anvil |
| **P** | `patched_replay` | patched bytecode, replayed in the **identical** harness context |

From these we run **two** comparisons. Whether a difference is *critical* or tolerable
*drift* is **not** a property of the field — it depends on **which comparison** you are
running.

### Reproduction check — O vs L (`reproduces_chain`)

*Did our replay reproduce reality?* The patch never existed on-chain, so the real tx ran
original bytecode — O should match L if the harness is faithful.

- If `reproduces_chain` is **not affirmatively true** — the check failed, or the live
  capture was unavailable so it could not run — the result is **`inconclusive`** and we
  discard the patch verdict. (Exception: a `diverged` same-context state change still yields
  `needs_inspection` / `effective_patch`, since that is attributable to the patch
  regardless of reproduction.)
- Value-level differences between a local fork and real chain are mostly **drift**
  (harness infidelity), not replay failure — see §4.
- Load-bearing only in the **both-succeed** branch, where state is the only signal. A
  clean top-level status flip (original succeeds, patched reverts) is decided by status
  alone.

### Preservation test — O vs P (`state_equivalent`)

*Did the patch change what the tx does?* This is the **decisive** signal. Both runs share
the same fork, prior txs, tier, and block context. Every harness artifact that does not
depend on bytecode **cancels**. Any surviving difference is attributable to the patch.

- `state_equivalent == true` → the patch changed nothing the tx does.
- `state_equivalent == false` → the patch changed the state effect.

### Soundness (transitivity)

Comparing patched-replay directly against live chain is **unsound** — it conflates the
patch's effect with harness imperfections (approximated `block.timestamp`, gas bumping,
tx ordering). Instead:

> if **O ≈ L** (reproduces chain) and **P ≈ O** (preservation test), then **P ≈ L** —
> the patched contract behaves like reality.

---

## 3. Verdicts

The two comparisons compose into kind-specific labels (opposite polarity for benign vs.
attack):

**Benign tx** — we want the effect *preserved*:

| Verdict | Condition |
|---|---|
| `preserved` | replay reproduces chain **and** the patch changed nothing |
| `needs_inspection` | the patch **changed** a benign tx (different state effect, or it now reverts) |
| `inconclusive` | reproduction not confirmed — the check failed, **or** the live capture was unavailable so it could not be verified |

**Attack tx** — we want the exploit's effect *gone*:

| Verdict | Condition |
|---|---|
| `effective_patch` | top-level reverts under patch, **or** its state effect is absent (swallowed sub-call case) |
| `ineffective_patch` | exploit still lands unchanged |
| `inconclusive` | replay did not reproduce the exploit |

Plus `unfaithful_replay` when same-block setup was not honoured by both runs.

---

## 4. Critical values vs drift

### Always critical — in both comparisons (structural)

These mark "a different execution happened" and are robust to accrual drift:

| Field | Why structural |
|---|---|
| **Execution status** (success/revert) | base preservation/effectiveness signal |
| **Account scope** (account touched in exactly one run) | real path difference; coinbase and sender gas artifacts excluded |
| **Code create/destruct** | contract deployed or self-destructed in only one run |
| **CREATE-nonce** (contract's own nonce delta) | reflects how many contracts it deployed |

### Critical only in the preservation test (value-level, same-context)

Tolerated as drift in the reproduction check, but decisive in O→P:

| Field | What it captures |
|---|---|
| **Storage diff** (`slot → final value`, no-op writes dropped) | balances, ownership, allowances, accounting |
| **Logs / events** (ordered `address, topics[], data`) | token transfers and protocol effects |
| **Non-gas ETH balance deltas** | internal value transfers |
| **Return data** | ABI return of the entry call |

### Drift — reproduction check only

The same value-level fields compared **O vs L** are recorded as `value_drift` and **never
fail** the reproduction check — but they are *calibrated*, not blanket-tolerated, so a
large divergence still fails (see §5):

- **Storage** — calibrated per slot kind (bool/address/numeric/opaque), ≤ 10% tolerated.
- **Logs** — a difference confined to log *data* (accrued amounts; same address + topics +
  order) is drift; a different *set/order of events* is **critical** (a different execution
  path emitted them).
- **Non-sender ETH balances** — same 10% numeric tolerance as storage; a wildly different
  value moved on chain than in the replay is **critical**.
- **Sender ETH balance / return data** — remain `value_drift`. The sender's non-gas delta
  carries gas-normalization residue that never fully cancels across the local-fork vs live
  gas regime (it *does* cancel in O→P); return data is not yet populated.

**Why tolerating drift is sound:** drift is harness infidelity between the local fork and
real chain — independent of bytecode. In the preservation test both replays share the
same fork, so this drift is identical in O and P and **cancels**. Counting it as a
reproduction failure would false-flag every faithful replay.

**Concrete evidence (AlkemiEarn attack tx):** replaying the prior-tx sequence locally
advances interest-accrual indices slightly differently than on real chain — 21
interest-index storage slots + 1 derived amount, relative drift ≈ **3.7×10⁻¹²**, while
the exploit reproduced perfectly. Structural facts (same accounts, same status) confirmed
faithfulness.

### Normalized / loose (never decisive alone)

| Dimension | Handling | Severity |
|---|---|---|
| **Gas** | coinbase dropped; sender balance normalized by `gasUsed × effectiveGasPrice`; base-fee burn dropped | `loose` |
| **Sender nonce**, **revert reason text** | recorded, never decisive | `loose` |
| **Failed subcall count** | reported in both comparisons; corroborating signal only (e.g. swallowed inner revert) | `loose` |

A tx whose patched run got a gas-limit bump is tagged
`gas_limit_potentially_confounded`.

---

## 5. Calibrated reproduction check

The reproduction check (O→L) applies **calibrated storage rules** so unbounded drift
tolerance does not hide real structural failures. The preservation test (O→P) stays
**exact** on all value-level fields.

| Check | Fails when | Reported only (never fails) |
|---|---|---|
| **Reproduction check (O→L)** | structural list; storage **bool** `0↔1`; address/numeric/opaque storage mismatch **> 10%**; **event** set/order mismatch; **non-sender balance** mismatch **> 10%** | storage/non-sender-balance within **≤ 10%** (`value_drift`); log *data*-only drift; sender non-gas balance; failed subcall count mismatch |
| **Preservation test (O→P)** | structural list; **any** value-level mismatch — **exact**, no numeric tolerance | failed subcall count mismatch |

### Storage slot rules (reproduction check only)

| Slot kind | Detection | Match rule | On mismatch |
|---|---|---|---|
| **Address** | top 12 bytes zero, lower 20 non-zero | ≤ **10%** relative error (most address swaps are ≫10%, but two addresses sharing high bytes can fall within tolerance — a known soft spot of word-level relative error) | **drift** if within tolerance; **critical** if above |
| **Bool** | value is `0` or `1` only | exact | **critical** |
| **Opaque / packed** | full word used, not address-shaped (interest indices, hashes) | ≤ **10%** relative error | **drift** if within tolerance; **critical** if above |
| **Numeric** | everything else (`uint256`) | ≤ **10%** relative error | **drift** if within tolerance; **critical** if above |

Relative error: `|a − b| / max(|a|, |b|, 1)`.

Default `numeric_drift_tolerance = 0.10` in `state_compare.reproduction_check`. Not
applied to the preservation test. For benign txs, even a 1-wei nudge in O→P is critical.

### Report additions

- `max_relative_drift` — worst numeric slot error in the reproduction check
- `failed_subcalls_match` — `yes` / `no` / `unavailable` per comparison pair
- per-divergence `relative_error` on calibrated O→L storage slots
- separate counts: `critical_divergence_count`, `value_drift_count`, `loose_count`

---

## 6. Block timestamp dependence

Timestamp handling is a first-class part of replay comparison because **`block.timestamp`
is an execution input**, not an effect — and getting it wrong can flip `require` outcomes
and corrupt both comparisons.

### The problem

The fast path executes a historical transaction with `eth_call` against state at block
**N−1**. The EVM sees the **timestamp of block N−1**, not the source block **N** where
the transaction actually ran — roughly **~12 s earlier** on post-Merge Ethereum mainnet.

Any contract logic that reads `block.timestamp` therefore observes a different value than
on chain. For most calls this is harmless; for time-sensitive logic it can flip the
result entirely.

| Pattern | Example | Failure mode at N−1 replay |
|---|---|---|
| **Deadline check** | Uniswap router, liquidations | looser at N−1 → tx that should hit `EXPIRED` passes |
| **Cooldown / rate limit** | vesting, staking unlock | stricter at N−1 → tx that should pass reverts |
| **Mint / sale window** | NFT phases, presale gates | false positives or negatives near edges |
| **Oracle staleness** | Chainlink feeds, Compound, AlkemiEarn | stale price may pass freshness or vice versa |
| **PRNG seeded with timestamp** | weak RNG NFTs | different code path altogether |

**Why this matters for patch verification specifically:**

1. **Patch guards often read `block.timestamp`.** Oracle freshness checks, time locks,
   and anti-MEV cooldowns added by a patch can fire differently at N−1, hiding or
   fabricating a behavioral change.
2. **The asymmetry is real.** Original bytecode might not care about timestamp; the
   patched bytecode does — so O and P can diverge for context reasons, not patch reasons.
3. **Auto-escalation has a blind spot.** Escalation triggers when the fast replay
   **reverts** but chain succeeded, or when the error mentions `timestamp` / `deadline` /
   `time`. A case where **both** fast replay and chain succeed despite wrong timestamp
   (e.g. QTN, JokInTheBox in the dfhl run) is not caught automatically.

### Why `eth_call` cannot simply override timestamp

Most public RPC providers do not expose `blockOverrides`. Even when they do, overrides
apply only for the duration of one call — they do not replay earlier same-block
transactions at the right timestamp. Only a **local Anvil fork** can mine blocks with a
chosen timestamp and run prior txs in order.

### How PonDeReplay solves it

Timestamp mitigation operates at **three layers**: replay execution, comparison severity,
and operator flags.

#### Layer 1 — Preflight detection

`preflight.py` emits a `time/context mismatch risk` warning when `tx_index > 0` or the
contract was created in the same block as the tx. Exposed as `diagnostics.warnings`.
Treat this as a hard signal: do not trust a fast `eth_call` verdict on timestamp-sensitive
cases without strict replay.

#### Layer 2 — Strict Anvil replay (`sequential_same_timestamp`)

When escalation fires (auto or `--strict-anvil`), PonDeReplay forks via Anvil and replays
with **`sequential_same_timestamp`** (`anvil_replay.py`):

1. Fork at block N−1.
2. Replay each prior tx in the source block **in order** with automine on.
3. Before **each** mine, call `evm_setNextBlockTimestamp` / `anvil_setNextBlockTimestamp`
   with the **source block's timestamp** (normalized to Unix seconds — Anvil rejects
   millisecond values).
4. Inject patched bytecode, replay the target tx with the same timestamp.
5. Best-effort align `baseFeePerGas` and coinbase.

If Anvil refuses the source timestamp (head already past it), `_set_next_timestamp_seconds`
surfaces the rejection in `timestamp_error` instead of silently mining the wrong time.

After replay, diagnostics record:

- `source_block_timestamp` / `local_block_timestamp`
- `time_context_mismatch` — local ≠ source
- `context_unfaithful` — timestamp mismatch or same-block batch failure
- `timestamp_applied`, `timestamp_error`, `replay_strategy`

A replay is marked faithful only when local status matches chain **and**
`context_unfaithful` is false.

#### Layer 3 — Comparison-aware handling

Timestamp affects **how divergences are scored**, not just whether replay runs:

| Mechanism | Role |
|---|---|
| **`context_faithful` flag** | Set from replay diagnostics. When false, value-level mismatches in the preservation test are downgraded to **`context_induced`** — reported separately, not counted as patch-induced behavioral change. |
| **Context-gated fields** | Storage slots and log fields derived from `block.timestamp` / block number (interest accumulators, TWAP snapshots, freshness timestamps) are critical only when context is faithful. |
| **Reproduction check drift** | Cross-context O→L value differences from accrual over the replayed prior-tx sequence are drift regardless of timestamp — they cancel in O→P. |
| **Gas bump (`--bump-gas-for-patch`, default on)** | Patched bytecode often needs more gas; re-estimation inside Anvil prevents OOG artifacts that would masquerade as timestamp or revert failures. |

Infidelity-cancellation in the preservation test holds only when the harness imperfection
is **independent of bytecode**. If the patched code reads `block.timestamp` that the
harness only approximates, the divergence is context-induced — we do not claim a behavioral
change we cannot attribute to the bytecode.

### Operator guidance

| Action | When |
|---|---|
| `--bump-gas-for-patch` (default on) | Always — removes OOG false negatives on patched bytecode |
| `--strict-anvil` | Timestamp-sensitive cases: deadlines, oracle freshness, phase gates, or any tx with preflight time/context warning |
| `--auto-strict-on-mismatch` (default on) | Escalate when fast replay disagrees with chain or error mentions time/deadline |
| `--compare-state` | Forces Anvil tier — required for state comparison (fast `eth_call` produces no state diff) |

**Residual limitation:** strict mode aligns the immediate block's timestamp but cannot
replay the entire historical chain of upstream oracles. Timestamp-conditioned off-chain
components (paymasters, off-chain validation) are out of scope.

---

## 7. What the report shows

Each tx gets a row ordered by relevance (L = live, O = original replay, P = patched replay):

```
tx | kind | tx status (L/O/P) | reproduces chain (O→L) | O→L struct/drift
   | patch effect (O→P) | O→P mismatches | failed subcalls (L/O/P) | classification
```

Read validity (O→L) first — if the replay doesn't reproduce chain, the rest is moot — then
the patch's effect (O→P), then the verdict. Full per-execution state diffs are persisted
in the JSON for manual cross-checking.

### Severity → effect

| Severity | Counts toward `state_equivalent`? | Where it arises |
|---|---|---|
| `critical` | **yes** | structural always; value-level in preservation test |
| `value_drift` | no | value-level in reproduction check |
| `context_induced` | no | value-level in preservation test under unfaithful context |
| `loose` | no | gas, coinbase, sender nonce, failed subcalls |

---

## 8. Limitations

- **Performance:** state diffs require the Anvil-indexed tier; `--compare-state` forces it.
- **Address calibration in O→L:** uses word-level relative error, so two distinct
  addresses that share high bytes can fall within the 10% band and be tolerated as drift.
  Only weakens the reproduction check; the preservation test (O→P) stays exact.
- **Sender balance & return data in O→L:** still informational drift (sender carries
  gas-normalization residue; return data is not yet populated in captures).
- **Gas confound:** differing gas limits can perturb `gasleft()`-dependent control flow;
  tagged `gas_limit_potentially_confounded`.
- **Silent timestamp false passes:** fast replay and chain both succeed at wrong timestamp
  — requires `--strict-anvil` or dataset annotation, not auto-escalation alone.
- **Return data:** defined as critical but not currently populated in captures, so never
  compared yet.

---

## 9. Implementation map

| Module | Role |
|---|---|
| `state_diff.py` | fetch + normalize `prestateTracer` diffMode capture |
| `state_compare.py` | `reproduction_check(O, L)`, `preservation_test(O, P)`, calibrated storage |
| `anvil_replay.py` | `sequential_same_timestamp`, timestamp normalization, context diagnostics |
| `replayer.py` | wires captures, builds comparison report, auto-strict escalation |
| `classifier.py` | kind-specific verdicts from status + state axes |
| `preflight.py` | time/context mismatch risk warnings |

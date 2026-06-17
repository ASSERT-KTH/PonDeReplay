# Sound state comparison for behavioral-preservation replay

Status: design (written 2026-06). Implementation tracked separately.

## Motivation

For attack txs, "did it revert under the patch?" is enough — a patch is *effective*
if the exploit transaction now fails. For **behavioral preservation** we replay txs
that occurred *before* the attack and ask a harder question: does the patched contract
still do the **same thing** to blockchain state as the unpatched contract did?

A pre-attack tx that still *succeeds* under the patch is necessary but **not
sufficient**. The patch could change a stored value, emit a different event, move a
different amount of tokens, and still return success. So preservation must be judged on
the **state effect** of the tx — storage writes, logs, balance moves — not just its
revert status.

## The soundness principle: compare replays, reproduce chain on live

The naive comparison is *patched-replay vs. live chain*. It is **unsound** because it
conflates two unrelated things:

1. the **patch's** effect on state, and
2. the **harness's** own infidelity (approximated `block.timestamp`, gas bumping,
   same-block tx ordering, base-fee/coinbase alignment).

Instead, the primary comparison is between the **two replays**, run in the *identical*
harness context, and the **live chain is used only as a validity oracle** on the
original-bytecode replay:

> **Primary:** `patched_replay` vs. `original_replay` (same fork, same prior txs, same
> tier, same block context).
> **Oracle:** `original_replay` vs. `live` — is the harness faithful for this tx at all?

### Why this is sound (transitivity)

Let `≈` mean "state-equivalent after canonicalization" (defined below).

- If `original_replay ≈ live`, the harness reproduces this tx faithfully.
- If `patched_replay ≈ original_replay`, the patched bytecode changes nothing.
- Therefore `patched_replay ≈ live`: **behavior is preserved relative to reality.**

Comparing the two replays cancels every source of infidelity that is *independent of the
bytecode* — exactly the harness artifacts above. This is strictly at least as sound as
patched-vs-live, and it cleanly separates "the patch changed behavior" from "our replay
isn't perfect."

### Verdict taxonomy

| `reproduces_chain` (structural) | `patched ≈ original` (preservation test) | Verdict |
|---|---|---|
| false | — | **inconclusive** — replay did not reproduce chain; surface, do not count |
| true | yes | **preserved** (status-equivalent *and* state-equivalent) |
| true | no | **needs_inspection** — patch changed a benign tx; flag for manual review |

> **Empirical correction (validated on the AlkemiEarn attack tx, 2026-06).** The original
> design used *exact state equality vs live chain* for the reproduction check. In practice
> that fails even on faithful replays: comparing the local Anvil fork against real chain
> surfaces **benign value drift** — interest-accrual indices that advance slightly
> differently over the replayed prior-tx sequence, and the amounts derived from them
> (observed: 21 interest-index storage slots + 1 derived WETH `Transfer` amount, differing
> by a relative ~3.7×10⁻¹², while the exploit reproduced perfectly; balances matched after
> gas normalization). These are exactly the artifacts the **same-context** patched-vs-
> original test cancels — but the cross-context live comparison cannot.
>
> The fix is a **structural reproduction check** (`reproduction_check`, `structural_only=True`):
> value-level fields (storage/logs/balances/return data) are downgraded to `value_drift`
> (tolerated), so the check fails only on **structural** divergence — status mismatch,
> **account-scope** (a contract touched in only one execution), code create/destruct, or
> CREATE-nonce. Those are exactly the markers of "the exploit didn't actually run" (the
> AlkemiEarn false-negative class) and are robust to drift: accrual touches the *same*
> accounts in both runs, only the values differ. The reproduction check is **load-bearing
> only in the both-succeed branch** (where state is the only signal); a clean top-level
> status flip is decided by status alone, so it can never turn a clean `effective_patch`
> into `inconclusive`. The decisive state signal remains the preservation test (`patched ≈
> original`). The full value-level live diff is still persisted in `chain_reproduction`.

## What gets compared (the `≈` relation)

For each of the three executions, capture via the `prestateTracer` with
`tracerConfig.diffMode = true` (confirmed available on the project RPC for both
`debug_traceTransaction` and `debug_traceCall`, and on local Anvil):

- **status** and **return data**
- **logs**: ordered list of `(address, topics[], data)`
- **storage diff** per account: `slot -> (old, new)`
- **balance / nonce / code** diff per account

### Account scope = union, never intersection

The accounts to compare are the **union** of accounts touched by `original ∪ patched`
(and `∪ live` for the oracle). An account modified on one side but absent on the other
**is a divergence** — intersecting would hide exactly the differences we are looking
for.

### Canonicalization (applied before equality)

1. Sort accounts; sort slots within each account.
2. Drop **no-op writes** (`old == new`): compare net diff only.
3. Token balances and internal ETH transfers need **no special handling** — ERC-20
   balances are storage on the token contract, and value-bearing `CALL`s appear as
   balance diffs. They fall out of the storage/balance diff automatically.

### Divergence categories (for the structured report)

- `status_divergence` / `return_data_divergence`
- `storage_divergence` (account, slot, original-value, patched-value)
- `log_divergence` (missing / extra / changed event)
- `balance_divergence` (non-gas ETH delta differs)
- `account_scope_divergence` (account touched on one side only)

## Field-by-field comparison spec

Each observable field falls into one **tolerance class**. A field's class decides whether
a mismatch produces a divergence verdict, is silently normalized, or is merely recorded.

| Tolerance class | Effect of a mismatch |
|---|---|
| **critical** | Counts as a divergence (`needs_inspection` for benign; "effect changed" evidence for attack). |
| **normalized** | Transformed before comparison (e.g. gas-adjusted); only the *residual* is critical. |
| **context-gated** | Critical **only when** the replay context is faithful. If `context_unfaithful` (e.g. approximated `block.timestamp`), a mismatch is downgraded to *context-induced* and reported separately, not counted as a behavioral change. |
| **loose** | Recorded and reported for inspection, but **never** causes a divergence verdict on its own. |

### The fields

| Field | Class | Rationale / handling |
|---|---|---|
| **Execution status** (success/revert) | **critical** | The base preservation/effectiveness signal. For attack txs note the sub-call case: top-level status alone is insufficient — see the attack-tx section. |
| **Top-level return data** | **critical** | ABI return of the entry call. Context-gate only the part that encodes `block.timestamp`/`number` if a function returns it. |
| **Revert reason** (when both revert) | **loose** | Same status is what matters; differing revert strings are informational (decoded message can shift between bytecodes). |
| **Storage diff** — ordinary slots | **critical** | The heart of the state effect (balances, ownership, allowances, accounting). Per `(account, slot)` after dropping no-op writes. |
| **Storage diff** — time/block-derived slots | **context-gated** | `lastUpdateTimestamp`, interest/index accumulators, TWAP snapshots, etc. Equal only when the source block timestamp is reproduced (strict Anvil); under approximate context, a mismatch here is context-induced. |
| **Logs / events** (emitter, topics, data, order) | **critical** | Event identity + ordered payload. Token transfers and most protocol effects surface here. |
| **Logs** — timestamp/gas-bearing data fields | **context-gated** | Event data carrying `block.timestamp` or gas figures is gated like the storage equivalents. |
| **ETH balance** — sender, gas portion | **normalized** | Subtract `gasUsed × effectiveGasPrice` before comparing; the gas portion is expected to differ when the patch changes gas. |
| **ETH balance** — sender, non-gas portion | **critical** | The value the sender actually sent/received minus gas. A real economic effect. |
| **ETH balance** — other accounts (value transfers) | **critical** | Internal `CALL` value moves; the substance of fund flows. |
| **ETH balance** — coinbase / miner | **loose** | Block reward + priority fee; an artifact of gas and block production, not contract behavior. Dropped from the account set. |
| **Base-fee burn** | **loose** | Derived from gas; excluded. |
| **Account scope** (touched-on-one-side-only) | **critical** | A real divergence — except gas-only accounts (coinbase), which are excluded first. |
| **Code change** (selfdestruct, deploy) | **critical** | Contract created/destroyed is a first-class state effect. |
| **Created-contract address** | **normalized** | Derived from `sender + nonce`; the literal address may shift with ordering. Compare the *fact* of creation plus the created code/storage, with the address normalized (positional/placeholder), not the raw bytes. |
| **Nonce** — sender | **loose** | Always `+1` for a successful tx; deterministic, carries no behavioral signal. |
| **Nonce** — contracts that `CREATE` | **critical** | Reflects how many contracts were deployed; part of the effect. |
| **Gas used** | **loose** | Patches legitimately change gas. Reported separately, never a divergence. |
| **Block context** (timestamp, number, baseFee, coinbase) | **loose (input, not effect)** | These are *inputs* to execution, not effects. Tracked to set the `context_unfaithful` flag that governs the context-gated fields above; never compared as outcomes. |

### Decision summary

- **Always critical:** status, return data, ordinary storage diffs, logs, non-gas ETH
  transfers, account scope, code (de)creation, CREATE-nonce.
- **Normalized then critical on the residual:** sender ETH balance (minus gas), created
  addresses (minus position).
- **Context-gated** (critical only when context is faithful): time/block-derived storage
  slots and log fields.
- **Loose / informational only:** gas used, coinbase & base-fee balances, sender nonce,
  revert reason text, block context inputs.

These classes are the same for benign and attack txs; only the **polarity** of the verdict
differs (benign wants critical fields *equal*; attack wants the exploit's critical effect
*absent* — see the attack-tx section).

## Gas is a non-sound dimension — handled explicitly

A patch legitimately changes gas, which perturbs state. Gas-derived state is therefore
**excluded from the equivalence test** (otherwise every patched tx false-flags):

- Drop the **coinbase/miner** account (block reward + priority fee).
- Normalize the **sender's** ETH balance by `gasUsed × effectiveGasPrice`; compare only
  the non-gas portion of the sender's balance delta.
- Drop **base-fee burn**.
- `gas_used` delta is reported **separately, as informational** — never a divergence.

### Gas-limit policy (project decision)

`bump_gas_for_patch` is **on by default** and is kept that way. A differing gas *limit*
between the two runs can change `gasleft()`-dependent control flow, so it is a potential
confound. We do **not** force equal limits; instead:

- gas-derived state is normalized out as above, and
- any tx whose patched run was gas-bumped relative to the original run is tagged
  **`gas_limit_potentially_confounded`** in the output, so a `needs_inspection` verdict
  on such a tx is read with that caveat rather than silently trusted.

## Mechanism constraints

- **Identical tier across the pair.** Both halves must use the same replay tier
  (Anvil-indexed), the same fork point, and the same prior txs. Never `eth_call` for one
  and Anvil for the other.
- **The fast `eth_call` tier cannot produce state diffs.** It returns only the top-level
  return value. Enabling state comparison therefore **forces the Anvil-indexed tier** for
  these txs — a real performance cost, stated rather than hidden. (`debug_traceCall` with
  a code `stateOverride` + diffMode is a possible lighter path at block N−1, but it
  inherits the same context-faithfulness limits as `eth_call` and is not used as the
  default.)

## Honesty caveat for `needs_inspection`

Infidelity-cancellation holds only when the harness imperfection is **independent of the
bytecode**. If the patched code reads `block.timestamp` / block context that the harness
only approximates, a divergence there is *context-induced*, not *patch-induced*. Such
divergences are tagged with the existing `context_unfaithful` flag and reported
separately from deterministic ones — we do not claim a behavioral change we cannot
attribute to the bytecode.

## Output

The live state diff is the validity oracle **and** is persisted in the result JSON
(alongside the original and patched diffs and the structured divergence report), so
runs can be cross-checked manually and used in the paper's appendix.

## Attack txs: state comparison fixes the sub-call-revert blind spot

For attack txs the current rule calls a patch *effective* only when the **top-level** tx
flips success → revert under the patch. That misses a common exploit shape: the attacker
contract wraps the vulnerable call in `try/catch` (or a low-level `call` whose return it
ignores). When the patch makes the **inner** call revert, the attacker **swallows** it
and the top-level tx still returns `status = 1`. Status-only classification then labels
this `ineffective_patch` — a **false negative**, because the patch did stop the exploit.

State comparison resolves this directly: the signal for attack txs is the **mirror image**
of the benign case.

| Tx kind | Patch worked ⇔ |
|---|---|
| Benign (preservation) | patched state **==** original state (divergence is *bad*) |
| Attack (effectiveness) | patched state **≠** original state — the exploit's effect is *absent* (divergence is *good*) |

The reproduction check is even more important here: `reproduces_chain` (structural) together
with `original_replay.success` confirms the harness **actually reproduces the exploit**
before we trust an "effect is gone" conclusion.
This is exactly the AlkemiEarn false-negative class, where the exploit path never ran at all
(see `docs/recap.md`); without it, "no malicious effect under patch" is indistinguishable
from "no exploit ever executed."

Corroborating (cheap) signal: a caught inner revert appears as an `error` on a subcall
node in the `callTracer` trace while top-level `status = 1`. `trace.py` already walks the
call tree, so "did a subcall on the patched contract revert even though the tx succeeded?"
is available as a hint, but the sound ground truth remains the state diff.

### Attack-tx verdict table

| status-faithful (`original.success`) | patched state vs original (test) | top-level patched revert | verdict |
|---|---|---|---|
| — | — | **yes** | `effective_patch` (status alone decides) |
| no | — | no | `inconclusive` (exploit not reproduced) |
| yes | equal (attack still lands) | no | `ineffective_patch` |
| yes | neutralized (effect absent) | no | **`effective_patch`** — sub-call blocked (new; was a false `ineffective_patch`) |

A clean top-level status flip (original succeeds, patched reverts) is decided by status
alone. The same-context **test** is load-bearing only for the both-succeed (sub-call) row.
The live-state diff is a diagnostic throughout (see the empirical correction above).

## Classifier integration

This extends `pondereplay/classifier.py` rather than adding a parallel verdict. The state
axis composes onto the existing status axis, **with opposite polarity for benign vs.
attack txs**:

Replay validity is checked via `reproduces_chain` (structural reproduction check) and
`original_replay.success`; the same-context **preservation test** (`state_equivalent`:
patched ≈ original) supplies the decisive state signal. The live-state diff is persisted
in `chain_reproduction` for inspection (see the empirical correction above).

**Benign tx** (preservation — want state *equal*):
- status-unfaithful original → `inconclusive` (never reaches the both-succeed branch)
- both succeed **and** test state-equivalent → `preserved` (true preservation)
- both succeed **but** test diverges → **`needs_inspection`** (flag for review)

**Attack tx** (effectiveness — want exploit effect *gone*):
- status-unfaithful original → `inconclusive` (exploit not faithfully reproduced)
- top-level reverts under patch → `effective_patch` (status alone; unchanged)
- top-level succeeds but test state ≠ original (exploit effect neutralized) →
  `effective_patch` (new; previously a false `ineffective_patch`)
- top-level succeeds and test state == original (exploit still lands) →
  `ineffective_patch`

## Implementation sketch (modules)

- `state_diff.py` — fetch + normalize a prestate diffMode diff into a canonical
  structure (per-account storage/balance/nonce/code; drop no-ops).
- `state_compare.py` — `compare(...)` → structured divergence report +
  `state_equivalent: bool`; `preservation_test(original, patched)` for the decisive
  signal; `reproduction_check(original, live)` for the structural oracle
  (`reproduces_chain`).
- Capture wiring in `anvil_replay.py` — after mining each replay, call
  `debug_traceTransaction(prestateTracer, diffMode)` on the local node; store on
  `ReplayResult.state_changes`.
- Live capture in `replayer.py` — one `debug_traceTransaction` against the source RPC.
- `classifier.py` — kind-specific labels (benign: `preserved`/`needs_inspection`; attack: `effective_patch`/`ineffective_patch`) and compose the two axes.
- Surface in `ReplayResult.to_dict()` and the `compare-patch` / experiment outputs.

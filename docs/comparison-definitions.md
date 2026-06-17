# What PonDeReplay compares now — definitions

Status: reference (2026-06). Consolidates the *operational* definitions behind the
state-effect comparison. The soundness argument and full field table live in
[`state-comparison.md`](state-comparison.md); this file answers three questions directly:

1. **How do we compare now** (beyond revert/success)?
2. **Which values are critical** (a mismatch changes the verdict)?
3. **Which values are *drift*** (a mismatch is tolerated), and *why that is sound*?

All labels below are the ones the code actually emits (`pondereplay/classifier.py`).

---

## 1. How we compare now

We stop trusting top-level **status** (success/revert) as the whole answer and instead
compare the transaction's **state effect**: the storage it wrote, the logs it emitted,
the balances it moved, and the contracts it created or destroyed.

We capture that effect with a `prestateTracer` diff (`diffMode: true`) for **three**
executions of the same tx, all forking the same block *N−1*:

| Capture | What it is |
|---|---|
| `original_replay` | the unpatched contract, replayed locally on Anvil |
| `patched_replay`  | the patched contract, replayed in the **identical** harness context |
| `live`            | the real on-chain execution (validity oracle only) |

From these we run **two** comparisons. This is the key idea — *critical vs. drift is not a
property of a field; it is decided by which of these two comparisons you are running.*

### The TEST — `patched_replay` vs. `original_replay` (the decisive signal)

Both runs share the *same* fork, the *same* prior txs, and the *same* (possibly
approximate) block context. Every source of harness infidelity that does not depend on
the bytecode — approximated `block.timestamp`, gas bumping, tx ordering — is **identical
in both runs and therefore cancels**. So any surviving difference is attributable to the
patch. Here **value-level fields are critical**.

- `state_equivalent == True`  → the patch changed nothing the tx does.
- `state_equivalent == False` → the patch changed the state effect.

### The REPRODUCTION CHECK — `original_replay` vs. `live` (validity oracle only)

Did the harness reproduce reality for this tx *at all*? This comparison crosses contexts
(local fork vs. real chain), so it legitimately surfaces benign **drift** (see §3). We
therefore make the reproduction check **structural only**: value-level fields are downgraded to
`value_drift` and never fail it. Only structural divergence fails the reproduction check
(`reproduces_chain == False`).

> The reproduction check is **load-bearing only in the both-succeed branch**, where state is the only
> signal. A clean top-level status flip (original succeeds, patched reverts) is decided by
> status alone and can never be turned into `inconclusive` by the reproduction check.

### Soundness (transitivity)

If `original_replay ≈ live` (reproduction check passes) **and** `patched_replay ≈ original_replay`
(test equivalent), then `patched_replay ≈ live`: **behavior is preserved relative to
reality.** Comparing the two replays cancels harness artifacts; the live reproduction check confirms the
replay was faithful in the first place.

### Verdicts (exactly as `classifier.py` emits them)

**Benign tx** (we want the effect *preserved*):

| original.success | reproduction check (structural) | test (`state_equivalent`) | verdict |
|---|---|---|---|
| no | — | — | `inconclusive` (replay didn't reproduce the tx) |
| yes | failed | — | `inconclusive` |
| yes | ok | equal | **`preserved`** |
| yes | ok | diverged | **`needs_inspection`** (patch changed a benign tx) |
| yes (patched now reverts) | — | — | `needs_inspection` (or `inconclusive` if patched OOG) |

**Attack tx** (we want the exploit effect *gone*):

| original.success | top-level patched revert | test (`state_equivalent`) | verdict |
|---|---|---|---|
| no | — | — | `inconclusive` (exploit not reproduced) |
| yes | yes | — | **`effective_patch`** (status alone; OOG-on-patch → `inconclusive`) |
| yes | no | diverged + reproduction check ok | **`effective_patch`** (sub-call blocked, effect gone) |
| yes | no | diverged + reproduction check failed | `inconclusive` |
| yes | no | equal | **`ineffective_patch`** (exploit still lands) |

Plus `unfaithful_replay` when the same-block setup wasn't honoured by both runs.

> **Naming note:** earlier drafts (and the README/memory) referred to a label
> `behavior_diverged`. The code does **not** emit that — the benign "patch changed the
> effect" outcome is **`needs_inspection`**. Use the table above.

---

## 2. Critical values

A **critical** mismatch flips `state_equivalent` (in the test) / `reproduces_chain` (in the
reproduction check). Severity `CRITICAL` in `state_compare.py`.

### Always critical — in both the test and the reproduction check (structural)

These are *path/shape* differences: they mark "a different execution happened," and they
are **robust to drift** because accrual touches the *same* accounts/slots in both runs and
only the values move.

| Field | Why it's structural |
|---|---|
| **Execution status** (success/revert) | the base preservation/effectiveness signal |
| **Account scope** (an account touched in *exactly one* run) | a real path difference; gas-only accounts (coinbase) and the sender are excluded first |
| **Code create/destruct** | a contract deployed or self-destructed in only one run |
| **CREATE-nonce** (a contract's own nonce delta) | reflects how many contracts it deployed |

### Critical only in the TEST (value-level, same-context)

Tolerated as drift in the reproduction check, but decisive in the same-context test:

| Field | What it captures |
|---|---|
| **Storage diff** (`slot → final value`, no-op writes dropped) | balances, ownership, allowances, accounting — the heart of the effect |
| **Logs / events** (ordered `address, topics[], data`) | token transfers and most protocol effects |
| **Non-gas ETH balance deltas** (other accounts; sender after gas-normalization) | internal value transfers; the substance of fund flows |
| **Return data** | *defined as critical, but see Review finding 3 — not currently populated, so never compared* |

---

## 3. Drift values (and why tolerating them is sound)

**Drift** = a value-level difference that is *real* but *not attributable to the patch*.
It appears only in the cross-context **reproduction check** (replay vs. live), where it is recorded as
`value_drift` and never fails validity. Severity `VALUE_DRIFT` in `state_compare.py`.

### What drifts

The same value-level fields as above — **storage, logs, non-gas balances, return data** —
*when compared replay-vs-live*. The canonical example, validated on the **AlkemiEarn**
attack tx: replaying the prior-tx sequence locally advances **interest-accrual indices**
slightly differently than the real chain did, and the amounts derived from them move too
(observed: 21 interest-index storage slots + 1 derived WETH `Transfer` amount, relative
drift ≈ **3.7 × 10⁻¹²**; the exploit itself reproduced perfectly and balances matched after
gas normalization).

### Why tolerating it is sound

Drift is a difference between the *local fork* and the *real chain* — i.e. **harness
infidelity, independent of the bytecode**. The decisive signal (the TEST) compares two
replays in the *same* fork, so this drift is byte-for-byte identical in both and
**cancels**. The reproduction check only needs to answer a coarser question — "did the replay reproduce
the *structure* of reality?" — so it tolerates value drift and fails only on structural
divergence. Counting drift as a reproduction check failure would false-flag every faithful replay (it
did, before this fix).

### Two more non-sound dimensions, handled explicitly

| Dimension | Handling | Severity |
|---|---|---|
| **Gas** (a patch legitimately changes it) | coinbase account dropped; sender balance normalized by `gasUsed × effectiveGasPrice`; base-fee burn dropped; `gas_used` reported as info only | `LOOSE` / excluded |
| **Time/block-derived state** | gated by `context_faithful`; under an approximate context a mismatch is `context_induced`, not `critical` | `CONTEXT_INDUCED` |
| **Sender nonce** (+1 always), **revert reason text**, **coinbase/base-fee balance** | recorded, never decisive | `LOOSE` |

A tx whose patched run got a gas-limit bump relative to the original is tagged
`gas_limit_potentially_confounded`, so a `needs_inspection` verdict on it is read with that
caveat.

---

## Severity → effect, at a glance

| Severity | Counts toward `state_equivalent`? | Where it arises |
|---|---|---|
| `CRITICAL` | **yes** | structural always; value-level in the test |
| `VALUE_DRIFT` | no | value-level in the reproduction check (tolerated harness drift) |
| `CONTEXT_INDUCED` | no | value-level in the test under an unfaithful context |
| `LOOSE` | no | gas, coinbase, base-fee, sender nonce, revert text |

## Report terminology (what a reader sees)

| Internal | Report term |
|---|---|
| test `state_equivalent` | **patch effect**: `preserved` / `changed` |
| `reproduces_chain` | **reproduces chain**: `yes` / `no` |
| reproduction check structural divergences | **chain mismatches** |
| reproduction check value drift | **tolerated drift** |
| `failed_subcalls` (live/orig/patch) | inner reverts per run (sub-call exploit hint) |

`—` / `None` means *not measured* (no state capture); `0` means *measured zero*.
</content>
</invoke>

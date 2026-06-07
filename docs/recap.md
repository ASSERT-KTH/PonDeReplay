# PonDeReplay — AlkemiEarn faithful replay recap

Summary of the replay faithfulness problem, how it was fixed, and how to run things correctly (written May 2026).

---

## The problem we hit

Replaying the AlkemiEarn attack tx `0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d` with **patched** bytecode sometimes looked identical to **original** (both “success”), while a Foundry PoC showed the patch reverts with `Cannot liquidate own position`.

That was a **false negative**: the replay did not actually execute the real attack path.

---

## Root cause

PonDeReplay’s default replay uses `eth_call` at **block N−1** (state before the tx’s block).

For this attack:

| Item | Value |
|------|--------|
| Block | 24626979 |
| Attack tx index | 3 |
| `tx.to` (attack contract) | `0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B` |
| Deploy of `tx.to` | Same block, **tx index 2** |

At block **24626978**, `tx.to` has **no code**. A naive `eth_call` therefore does nothing useful and can return success without running the exploit.

The patch lives on the **implementation** (`liquidateBorrow`), not on the attack contract — but the setup bug hid everything.

---

## How it was solved (in the codebase)

### 1. Preflight (`pondereplay/preflight.py`)

Before replay, for each tx we check:

- Block number and **transaction index**
- Whether `tx.to` had code at N−1 vs N
- **Same-block contract creations** before this tx (scan block receipts)
- Optional trace-based hints (`--with-trace`; off by default)

Outputs: `same_block_setup_required`, `escalate_replay`, `faithfulness`, warnings.

### 2. Tiered replay (`pondereplay/replayer.py`)

| Tier | When | Mode name |
|------|------|-----------|
| Fast | No same-block issue | `eth_call` at N−1 |
| Faithful (default escalation) | `escalate_replay` | `eth_call_same_block_override` — inject bytecode for contracts created earlier in the block |
| Heavy | `--use-anvil` | `anvil_indexed` — fork, replay prior txs in block, then target tx |

### 3. Patch comparison (`compare-patch` + `pondereplay/classifier.py`)

Runs original vs patched with the same escalation rules and classifies:

- `effective_patch` — attack blocked under patch, benign OK
- `ineffective_patch`, `unfaithful_replay`, `inconclusive`

### 4. Batch / history (`replay-history`, `batch-replay`)

Each tx in a list goes through the **same** `replay_transaction()` path: preflight + auto same-block override when needed.

**Not** wired in batch CLI: `--use-anvil` (only on single `replay` / `compare-patch`).

Reports include `unfaithful_replay_txs` when replay still ends with `faithfulness: unfaithful`.

### 5. Bugs fixed during debugging

- **Anvil HexBytes:** `eth_sendTransaction` failed with `Object of type HexBytes is not JSON serializable`. Fixed in `anvil_replay.py` by normalizing fields to `0x` hex strings.
- **CLI messaging:** Verbose mode always printed `✅ Replay completed` even on failure. Now `✅ Replay succeeded` / `❌ Replay failed`; exit code 1 when `success: false`.

---

## AlkemiEarn addresses (remember these)

| Role | Address |
|------|---------|
| Proxy (user-facing) | `0x4822D9172e5b76b9Db37B75f5552F9988F98a888` |
| **Implementation (patch here)** | `0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7` |
| Attack contract (`tx.to`) | `0xE408b52AEfB27A2FB4f1cD760A76DAa4BF23794B` |

Bytecode: `dfhl-invariants/src/202603_AlkemiEarn/bytecode/original.hex` and `patch.hex`.

**Always pass `--contract-address` = implementation** when patching `original.hex` / `patch.hex`. Proxy bytecode is tiny (~2 KB); implementation logic is ~24 KB.

---

## Commands to use tomorrow

From repo root; RPC comes from `.env` (`ETH_RPC_URL`) — no need for `--rpc-url "$ETH_RPC_URL"` if `.env` is loaded (CLI calls `load_dotenv()`).

### Single attack tx — patch vs original (best for “does the patch work?”)

```bash
python -m pondereplay.cli compare-patch \
  --tx-hash 0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d \
  --contract-address 0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7 \
  --original-bytecode /path/to/original.hex \
  --patch-bytecode /path/to/patch.hex \
  --attack-tx
```

Expect classification **`effective_patch`** when faithful.

### Single tx — manual replay

```bash
# Original (exploit should succeed)
python -m pondereplay.cli replay \
  --tx-hash 0xa17001eb... \
  --contract-address 0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7 \
  --bytecode-file /path/to/original.hex \
  -v

# Patch (exploit should revert)
python -m pondereplay.cli replay \
  --tx-hash 0xa17001eb... \
  --contract-address 0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7 \
  --bytecode-file /path/to/patch.hex \
  -v
```

Same-block override is automatic; add `--use-anvil` only if you need full in-block tx ordering on a local fork.

### History list (many txs)

```bash
python -m pondereplay.cli replay-history \
  --contract-address 0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7 \
  --tx-list-file /path/to/tx_hashes.json \
  --bytecode-file /path/to/patch.hex \
  --attack-tx 0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d \
  --output json \
  -v
```

- **`patch.hex`** → want attack in `failed_txs`, `attack_tx_failed_as_expected: true`
- **`original.hex`** → attack should **pass**; `attack_tx_failed_as_expected` will be false (that flag means “patch blocked attack”)

---

## How to read the output

| Message | Meaning |
|---------|---------|
| `Faithfulness (preflight): unfaithful` | Block N−1 replay would be wrong; tool will escalate |
| `diagnostics.faithfulness: faithful` | Escalated path (override or Anvil) — setup is correct |
| `replay_mode: eth_call_same_block_override` | Used same-block bytecode injection |
| `replay_mode: anvil_indexed` | Used Anvil fork + prior txs in block |
| `replay_mode` contains `_strict` | Used strict Anvil block-context alignment (timestamp/baseFee/coinbase best-effort) |
| `replay_mode` contains `_auto_strict` | Auto-escalated because replay looked inconsistent with chain behavior |
| JSON `"success": false` | Simulated tx reverted or tooling error — check `error` |
| `diagnostics.revert_message` | Decoded revert: `Error(string)` (e.g. `borrower is solvent`), trace errors (`out of gas`), or Alkemi `Error` codes |
| `diagnostics.gas_bumped_for_patch` | Only when `--bump-gas-for-patch` is set; otherwise source tx gas is used |
| `local_failure_reason` | `out_of_gas` vs `patch_guard` vs `revert_other` — distinguishes false "blocked" from patch logic |
| `Revert:` in `-v` stderr | Same decoded message on failed replay |
| `✅ Replay succeeded` / exit 0 | Replay simulation succeeded |

**Do not** treat “Replay completed” (old CLI) or exit 0 from a wrapper script as success without reading JSON `success`.

---

## Mental model

1. **Preflight** detects “contract didn’t exist at N−1 but exists at N”.
2. **Escalation** applies same-block code overrides (or Anvil if requested).
3. **Patch** must target the address whose code actually runs (`implementation` for proxy patterns).
4. **`compare-patch`** is the right tool for patch effectiveness; **`replay-history`** is for many txs with one bytecode variant.

For historically successful txs that replay as revert (often time-sensitive logic), PonDeReplay now auto-escalates to strict Anvil context by default (`--auto-strict-on-mismatch`). You can disable with `--no-auto-strict-on-mismatch`.

Anvil strict replay uses **sequential_same_timestamp**: replay each prior tx in order with automine on, set **next block timestamp to source block time (seconds)** before each mine, then run target. This reproduces state + time without the ms timestamp bug or wrong per-block drift.

---

## Running the Alkemi experiment

**Do not** use plain `run_dfhl_experiment.py` alone for Alkemi: Etherscan `tx-list` on the **implementation** returns almost no txs (users call the **proxy**). Use the dedicated script or the commands below.

```bash
cd ~/Documents/Deffensive/PonDeReplay
./scripts/run_alkemi_experiment.sh
```

Outputs: `experiment_runs/alkemi_faithful/202603_AlkemiEarn/` (`replay-result.json`, `patch-classification.json`, `summary.json`).

Requires `ETH_RPC_URL` in `.env`. Does **not** need Etherscan for the full 54-tx list (uses `dfhl-invariants/.../tx_hashes.json`).

Latest run (May 2026): **`effective_patch`**, 50/54 passed under patch, attack tx blocked (`attack_tx_failed_as_expected: true`). Four failures: attack + 3 txs that also fail on-chain or are unrelated `0xdeadbeef` probes.

---

## Key files

- `pondereplay/preflight.py` — detection
- `scripts/run_alkemi_experiment.sh` — Alkemi full-history experiment
- `pondereplay/replayer.py` — tiered replay
- `pondereplay/anvil_replay.py` — Anvil backend
- `pondereplay/classifier.py` — patch outcome labels
- `pondereplay/cli.py` — `replay`, `compare-patch`, `replay-history`
- `experiment_runs/alkemi_earn_to_attack/` — example run artifacts

# PonDeReplay

Replay Ethereum transactions with patched contract bytecode. Built for verifying
security patches by re-executing historical transactions against fixed code while
preserving as much on-chain context as possible.

## Overview

PonDeReplay lets you:

1. **Replay historical transactions** on pre-transaction state (block \(N-1\))
2. **Patch contract bytecode** via `eth_call` state overrides or a local Anvil fork
3. **Verify patches** — block the attack tx while benign history still passes
4. **Sanity-check the replay itself** — original bytecode must reproduce chain behaviour before patch results are trusted

### Typical workflow

1. Replay with **original** bytecode (`on_original`) — confirm success/revert matches the chain
2. Replay with **patch** bytecode — attack should revert; benign txs should still succeed
3. Use **`compare-patch`** for a single attack tx, or **`replay-history`** / the DFHL experiment script for many txs

## Installation

### Prerequisites

- Python 3.9+
- Ethereum RPC endpoint (`ETH_RPC_URL`)
- [Foundry](https://book.getfoundry.sh/) (`anvil`) — optional but recommended for same-block setup and timestamp-sensitive replays

### From source

```bash
git clone https://github.com/Deffensive/PonDeReplay.git
cd PonDeReplay
pip install -e ".[dev]"
```

### Configuration

```bash
cp .env.example .env
# Edit .env — at minimum:
export ETH_RPC_URL="https://api-ethereum-mainnet.n.dwellir.com/YOUR_API_KEY"
export ETHERSCAN_API_KEY="..."   # optional; needed for tx-list / replay-history via Etherscan
```

## Quick start (single transaction)

**Patch replay** (gas bump on Anvil is **on by default** when `--bytecode-file` is set):

```bash
pondereplay replay \
  --tx-hash 0xYOUR_TX \
  --contract-address 0xCONTRACT \
  --bytecode-file ./patch.hex \
  -v
```

**Original bytecode sanity replay** (omit `--bytecode-file`, or pass `original.hex`):

```bash
pondereplay replay \
  --tx-hash 0xYOUR_TX \
  --contract-address 0xCONTRACT \
  -v
```

> Replays execute on state at block **\(N-1\)** (the block before the original tx).

### Attack tx: original vs patch

```bash
pondereplay compare-patch \
  --tx-hash 0xATTACK_TX \
  --contract-address 0xCONTRACT \
  --bytecode-file ./patch.hex \
  --original-bytecode-file ./original.hex \
  --attack-tx \
  -v
```

Expect classification `effective_patch` when the attack reverts under patch but succeeded under original.

## Commands

| Command | Purpose |
|---------|---------|
| `replay` | Single tx with optional patched bytecode |
| `compare-patch` | Original + patch on one tx, with classification |
| `sanity-check` | Original bytecode only; compare to chain receipt |
| `replay-history` | Batch replay from Etherscan or a tx list file |
| `tx-list` | Export contract tx history from Etherscan to JSON |
| `batch-replay` | Scan blocks for txs to an address (slow; prefer `tx-list`) |
| `trace-analyze` | Inspect a transaction trace |

```bash
pondereplay --help
pondereplay replay --help
```

## Faithful replay

PonDeReplay uses a **tiered** strategy:

| Tier | When | Mode |
|------|------|------|
| Fast | No same-block setup issue | `eth_call` at \(N-1\) |
| Same-block override | Contract created earlier in block \(N\) | `eth_call_same_block_override` |
| Anvil strict | Timestamp / context mismatch or `--strict-anvil` | `anvil_indexed_strict` |

**Preflight** runs before each replay: block index, same-block contract creations, time/context warnings, and whether escalation is needed.

Useful flags:

| Flag | When to use |
|------|-------------|
| `--use-anvil` | Prefer Anvil when same-block setup is required |
| `--strict-anvil` | Force timestamp-aligned Anvil replay |
| `--bump-gas-for-patch` | Re-estimate gas on Anvil ( **default on** when patch bytecode is provided; use `--no-bump-gas-for-patch` to disable) |
| `--auto-strict-on-mismatch` | Escalate when fast replay disagrees with chain (default: on) |

See [docs/timestamp-dependence.md](docs/timestamp-dependence.md) for why `block.timestamp` matters and how strict Anvil mitigates it.

## History replay

```bash
pondereplay replay-history \
  --contract-address 0xCONTRACT \
  --tx-list-file txs.json \
  --bytecode-file patch.hex \
  --attack-tx 0xATTACK... \
  --output json \
  -v
```

`tx-list-file` accepts one hash per line, or JSON `["0x...", ...]` / `{"tx_hashes": [...]}`.

Without `--bytecode-file`, each tx is replayed with on-chain bytecode at its own \(N-1\).

## DFHL experiment (batch original + patch)

For the [dfhl-invariants](https://github.com/Deffensive/dfhl-invariants) dataset:

```bash
python scripts/run_dfhl_full_experiment.py \
  --verbose \
  --skip-existing
```

For each case this:

1. Replays all txs from `dfhl-invariants/src/<case>/txs/` on **original** and **patch**
2. Writes results under `dfhl-invariants/results/pondereplay/<case>/{original,patch}/`
3. Produces `soundness.json` with per-tx **`on_original`** sanity (does original replay match chain?) and patch verdicts

Options:

```bash
--only 202603_AlkemiEarn 202210_Uerii   # subset of cases
--limit-tx 20                            # cap txs per case
--bump-gas-for-original                  # also bump gas on original variant
--reclassify-only                        # rebuild soundness from saved replays
--strict-anvil                           # force strict Anvil for all replays
```

AlkemiEarn-specific script and notes: [docs/recap.md](docs/recap.md).

```bash
./scripts/run_alkemi_experiment.sh
```

## Reading output

JSON results include execution outcome fields (independent of replay machinery success):

```json
{
  "onchain_reverted": false,
  "local_reverted": true,
  "revert_message": "execution reverted: only governance can call earn()",
  "local_failure_reason": "revert_other",
  "faithful_to_chain": true,
  "replay_mode": "anvil_indexed_strict_patched",
  "diagnostics": {
    "faithfulness": "faithful",
    "warnings": []
  }
}
```

| Field | Meaning |
|-------|---------|
| `onchain_reverted` | Did the tx revert on chain? |
| `local_reverted` | Did the local replay revert? |
| `faithful_to_chain` | Does local status match chain? (replay sanity) |
| `local_failure_reason` | `out_of_gas`, `patch_guard`, `revert_other` |
| `diagnostics.faithfulness` | `faithful`, `approximate`, or `unfaithful` |

**`on_original` (experiment soundness):** per-tx check that original-bytecode replay matches chain before attributing failures to the patch.

## Supported bytecode formats

- Raw hex (`0x6080…` or without prefix)
- Foundry / Hardhat / Truffle JSON artifacts
- Raw `.bin` files

## Python API

```python
from pondereplay import TransactionReplayer

replayer = TransactionReplayer(
    "https://api-ethereum-mainnet.n.dwellir.com/YOUR_KEY",
    bump_gas_for_patch=True,
)

result = replayer.replay_transaction(
    tx_hash="0x...",
    contract_address="0x...",
    new_bytecode="0x...",
    verbose=True,
)

orig, patched, report = replayer.replay_original_and_patched(
    tx_hash="0x...",
    contract_address="0x...",
    patched_bytecode="0x...",
    original_bytecode="0x...",
    is_attack_tx=True,
)
print(report["classification"])
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/
pytest tests/ --cov=pondereplay --cov-report=html
black pondereplay/ tests/
```

## License

MIT — see [LICENSE](LICENSE).

## Contributing

Issues and PRs welcome.

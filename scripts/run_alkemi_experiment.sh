#!/usr/bin/env bash
# AlkemiEarn replay experiment (faithful settings: impl patch + full tx_hashes.json).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck source=/dev/null
  source .env
  set +a
fi

: "${ETH_RPC_URL:?Set ETH_RPC_URL in .env}"

DFHL_SRC="${DFHL_SRC:-$REPO_ROOT/../dfhl-invariants/src/202603_AlkemiEarn}"
OUT="${OUT:-$REPO_ROOT/experiment_runs/alkemi_faithful}"
CID=202603_AlkemiEarn
DIR="$OUT/$CID"
TXLIST="$DFHL_SRC/tx_hashes.json"
PATCH="$DFHL_SRC/bytecode/patch.hex"
ORIG="$DFHL_SRC/bytecode/original.hex"
IMPL=0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7
PROXY=0x4822D9172e5b76b9Db37B75f5552F9988F98a888
ATTACK=0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d
CLI="${CLI:-$REPO_ROOT/.venv/bin/python -m pondereplay.cli}"

mkdir -p "$DIR"
cp "$TXLIST" "$DIR/txs.json"

cat >"$DIR/replay_input.json" <<EOF
{
  "contract_id": "$CID",
  "contract_address": "$IMPL",
  "proxy_address": "$PROXY",
  "malicious_tx": "$ATTACK",
  "tx_hashes_source": "$TXLIST",
  "patch_hex_path": "$PATCH",
  "original_hex_path": "$ORIG"
}
EOF

echo "==> compare-patch (attack tx)"
$CLI compare-patch \
  --tx-hash "$ATTACK" \
  --contract-address "$IMPL" \
  --bytecode-file "$PATCH" \
  --original-bytecode-file "$ORIG" \
  --attack-tx \
  --output json \
  >"$DIR/patch-classification.json" \
  2>"$DIR/patch-classification.stderr.log"

echo "==> replay-history (patch on ${#txs[@]:-54} txs; no -v on stdout)"
$CLI replay-history \
  --contract-address "$IMPL" \
  --tx-list-file "$DIR/txs.json" \
  --bytecode-file "$PATCH" \
  --attack-tx "$ATTACK" \
  --bump-gas-for-patch \
  --output json \
  >"$DIR/replay-result.json" \
  2>"$DIR/replay.stderr.log"

python3 - "$DIR" <<'PY'
import json, sys
from pathlib import Path
d = Path(sys.argv[1])
replay = json.loads(d.joinpath("replay-result.json").read_text())
patch = json.loads(d.joinpath("patch-classification.json").read_text())
summary = {
    "contract_id": "202603_AlkemiEarn",
    "contract_address": "0x85A948Fd70B2b415bdA93324581fb5FfF1293DF7",
    "proxy_address": "0x4822D9172e5b76b9Db37B75f5552F9988F98a888",
    "malicious_tx": "0xa17001eb39f867b8bed850de9107018a2d2503f95f15e4dceb7d68fff5ef6d9d",
    "patch_classification": patch.get("classification"),
    "replay_result": replay,
}
d.parent.joinpath("summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print("classification:", patch.get("classification"))
print("replay: passed=%s failed=%s attack_blocked=%s" % (
    replay["passed"], replay["failed"], replay.get("attack_tx_failed_as_expected")))
PY

echo "Done. Artifacts: $DIR"

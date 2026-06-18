"""
Canonical representation of a transaction's state effect.

Parses a ``prestateTracer`` (``diffMode: true``) result plus receipt logs into a
normalized, JSON-serializable structure that two replays can be compared on.

See ``docs/tx-replay-comparison.md`` for the comparison design and field tolerance
classes. This module only *captures and canonicalizes*; comparison lives in
``state_compare.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

ZERO_WORD = "0x" + "00" * 32


def _to_int(value: Any) -> Optional[int]:
    """Parse a hex/int value to int; None stays None."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if v == "" or v == "0x":
            return 0
        return int(v, 16) if v.startswith(("0x", "0X")) else int(v)
    return None


def _norm_word(value: Any) -> str:
    """Normalize a storage value to a lowercase 0x-prefixed 32-byte word."""
    n = _to_int(value)
    if n is None:
        return ZERO_WORD
    return "0x" + format(n & ((1 << 256) - 1), "064x")


def _norm_code(value: Any) -> str:
    if value is None:
        return "0x"
    s = str(value).lower()
    return s if s.startswith("0x") else "0x" + s


def _norm_addr(value: Any) -> str:
    if value is None:
        return ""
    s = str(value).lower()
    return s if s.startswith("0x") else "0x" + s


@dataclass
class AccountDiff:
    """Net change to a single account, with no-op storage writes already dropped."""

    address: str
    balance_old: Optional[int] = None
    balance_new: Optional[int] = None
    nonce_old: Optional[int] = None
    nonce_new: Optional[int] = None
    code_old: Optional[str] = None
    code_new: Optional[str] = None
    # slot (32-byte hex) -> (old, new) words; only slots where old != new
    storage: Dict[str, Tuple[str, str]] = field(default_factory=dict)

    @property
    def balance_delta(self) -> int:
        return (self.balance_new or 0) - (self.balance_old or 0)

    def is_empty(self) -> bool:
        return (
            not self.storage
            and self.balance_delta == 0
            and (self.nonce_old or 0) == (self.nonce_new or 0)
            and (self.code_old or "0x") == (self.code_new or "0x")
        )

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"address": self.address}
        if self.balance_delta != 0:
            out["balance_old"] = self.balance_old
            out["balance_new"] = self.balance_new
        if (self.nonce_old or 0) != (self.nonce_new or 0):
            out["nonce_old"] = self.nonce_old
            out["nonce_new"] = self.nonce_new
        if (self.code_old or "0x") != (self.code_new or "0x"):
            out["code_old"] = self.code_old
            out["code_new"] = self.code_new
        if self.storage:
            out["storage"] = {
                slot: {"old": old, "new": new}
                for slot, (old, new) in sorted(self.storage.items())
            }
        return out

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AccountDiff":
        storage = {
            slot: (v["old"], v["new"]) for slot, v in (d.get("storage") or {}).items()
        }
        return cls(
            address=_norm_addr(d.get("address")),
            balance_old=d.get("balance_old"),
            balance_new=d.get("balance_new"),
            nonce_old=d.get("nonce_old"),
            nonce_new=d.get("nonce_new"),
            code_old=d.get("code_old"),
            code_new=d.get("code_new"),
            storage=storage,
        )


@dataclass
class LogEntry:
    address: str
    topics: List[str]
    data: str

    def key(self) -> Tuple[str, Tuple[str, ...], str]:
        return (self.address, tuple(self.topics), self.data)

    def to_dict(self) -> Dict[str, Any]:
        return {"address": self.address, "topics": self.topics, "data": self.data}


@dataclass
class StateCapture:
    """Everything observable about one execution's effect on chain state."""

    status: Optional[int] = None
    return_data: Optional[str] = None
    gas_used: Optional[int] = None
    gas_cost_wei: Optional[int] = None  # gasUsed * effectiveGasPrice
    sender: Optional[str] = None
    coinbase: Optional[str] = None
    accounts: Dict[str, AccountDiff] = field(default_factory=dict)
    logs: List[LogEntry] = field(default_factory=list)
    # Non-root call frames that halted with an error (revert/OOG/...). A patched run with
    # more failed subcalls than the original — while top-level status is unchanged —
    # signals an exploit blocked in a sub-call the attacker swallowed.
    failed_subcalls: Optional[int] = None

    def touched_addresses(self) -> set:
        return set(self.accounts.keys())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "return_data": self.return_data,
            "gas_used": self.gas_used,
            "gas_cost_wei": self.gas_cost_wei,
            "failed_subcalls": self.failed_subcalls,
            "sender": self.sender,
            "coinbase": self.coinbase,
            "accounts": [
                self.accounts[a].to_dict() for a in sorted(self.accounts.keys())
            ],
            "logs": [log.to_dict() for log in self.logs],
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StateCapture":
        accounts: Dict[str, AccountDiff] = {}
        for raw in d.get("accounts") or []:
            ad = AccountDiff.from_dict(raw)
            accounts[ad.address] = ad
        logs = [
            LogEntry(
                address=_norm_addr(log.get("address")),
                topics=[str(t).lower() for t in (log.get("topics") or [])],
                data=str(log.get("data") or "0x").lower(),
            )
            for log in (d.get("logs") or [])
        ]
        return cls(
            status=d.get("status"),
            return_data=d.get("return_data"),
            gas_used=d.get("gas_used"),
            gas_cost_wei=d.get("gas_cost_wei"),
            sender=_norm_addr(d.get("sender")) if d.get("sender") else None,
            coinbase=_norm_addr(d.get("coinbase")) if d.get("coinbase") else None,
            accounts=accounts,
            logs=logs,
            failed_subcalls=d.get("failed_subcalls"),
        )


def parse_account_diffs(prestate_diff: Dict[str, Any]) -> Dict[str, AccountDiff]:
    """
    Parse a ``prestateTracer`` diffMode result (``{"pre": {...}, "post": {...}}``).

    diffMode semantics (geth/erigon): ``pre`` carries the *full pre-image* of every
    modified account (balance, nonce, code, and the pre-values of written slots), while
    ``post`` carries only the *fields that changed*. So a field is a real change **iff it
    appears in post**. An account present in ``pre`` but absent from ``post`` was deleted
    (selfdestruct) — all its fields go to zero/empty.

    Both replays fork the same block N-1, so ``old`` values are identical across runs by
    construction. No-op storage writes (old == new) are dropped; empty accounts dropped.
    """
    pre = prestate_diff.get("pre", {}) or {}
    post = prestate_diff.get("post", {}) or {}

    accounts: Dict[str, AccountDiff] = {}
    for raw_addr in set(pre.keys()) | set(post.keys()):
        addr = _norm_addr(raw_addr)
        p = pre.get(raw_addr, {}) or {}
        q = post.get(raw_addr, {}) or {}
        diff = AccountDiff(address=addr)

        if raw_addr not in post:
            # Pre-only account. This means either a real selfdestruct OR — on nodes whose
            # diffMode also lists *accessed-but-unmodified* accounts in ``pre`` — a contract
            # that was merely called. A genuine deletion always clears real state (balance
            # or storage); a pure nonce+code pre-image with no balance and no storage is an
            # accessed account, not a deletion. Treating the latter as a deletion produces
            # spurious nonce 1->0 / code->0x divergences that differ across clients (e.g.
            # geth-live vs Anvil), so we skip it. (See docs/tx-replay-comparison.md.)
            has_real_state = (_to_int(p.get("balance")) or 0) > 0 or bool(
                p.get("storage")
            )
            if not has_real_state:
                continue
            diff.balance_old = _to_int(p.get("balance"))
            diff.balance_new = 0
            if p.get("nonce") is not None:
                diff.nonce_old = _to_int(p.get("nonce"))
                diff.nonce_new = 0
            if p.get("code") is not None:
                diff.code_old = _norm_code(p.get("code"))
                diff.code_new = "0x"
            for raw_slot, val in (p.get("storage") or {}).items():
                old = _norm_word(val)
                if old != ZERO_WORD:
                    diff.storage[_norm_word(raw_slot)] = (old, ZERO_WORD)
        else:
            # A field changed only if post lists it; pre supplies the old value.
            if q.get("balance") is not None:
                diff.balance_old = _to_int(p.get("balance")) or 0
                diff.balance_new = _to_int(q.get("balance"))
            if q.get("nonce") is not None:
                diff.nonce_old = _to_int(p.get("nonce")) or 0
                diff.nonce_new = _to_int(q.get("nonce"))
            if q.get("code") is not None:
                diff.code_old = (
                    _norm_code(p.get("code")) if p.get("code") is not None else "0x"
                )
                diff.code_new = _norm_code(q.get("code"))

            p_storage = p.get("storage", {}) or {}
            # Only post's storage keys are changed slots; pre supplies their old values.
            for raw_slot in (q.get("storage", {}) or {}).keys():
                slot = _norm_word(raw_slot)
                old = _norm_word(p_storage.get(raw_slot))
                new = _norm_word((q.get("storage") or {}).get(raw_slot))
                if old != new:
                    diff.storage[slot] = (old, new)

        if not diff.is_empty():
            accounts[addr] = diff
    return accounts


def parse_logs(raw_logs: List[Dict[str, Any]]) -> List[LogEntry]:
    """Normalize receipt/trace logs into ordered LogEntry records."""
    out: List[LogEntry] = []
    for log in raw_logs or []:
        address = _norm_addr(log.get("address"))
        topics = [
            t if str(t).startswith("0x") else "0x" + str(t)
            for t in (log.get("topics") or [])
        ]
        topics = [str(t).lower() for t in topics]
        data = str(log.get("data") or "0x").lower()
        out.append(LogEntry(address=address, topics=topics, data=data))
    return out


def fetch_prestate_diff(rpc_call: Any, tx_hash: str) -> Optional[Dict[str, Any]]:
    """Fetch a prestateTracer diffMode result for ``tx_hash`` via ``rpc_call``."""
    return rpc_call(
        "debug_traceTransaction",
        [tx_hash, {"tracer": "prestateTracer", "tracerConfig": {"diffMode": True}}],
    )


def capture_tx(
    rpc_call: Any,
    tx_hash: str,
    *,
    return_data: Optional[str] = None,
) -> Optional["StateCapture"]:
    """
    Build a StateCapture for ``tx_hash`` from a JSON-RPC endpoint.

    ``rpc_call(method, params) -> result`` must return the raw RPC result (and may
    raise). Best-effort: any failure (tracer unsupported, tx missing) returns None so
    state capture never breaks a replay.
    """
    try:
        diff = fetch_prestate_diff(rpc_call, tx_hash)
        receipt = rpc_call("eth_getTransactionReceipt", [tx_hash])
        if not receipt:
            return None
        block_hash = receipt.get("blockHash")
        block = (
            rpc_call("eth_getBlockByHash", [block_hash, False]) if block_hash else {}
        )
        failed_subcalls: Optional[int] = None
        try:
            from .trace import count_failed_subcalls

            call_trace = rpc_call(
                "debug_traceTransaction",
                [tx_hash, {"tracer": "callTracer", "timeout": "60s"}],
            )
            if isinstance(call_trace, dict):
                failed_subcalls = count_failed_subcalls(call_trace)
        except Exception:
            failed_subcalls = None
        cap = build_capture(
            prestate_diff=diff,
            raw_logs=receipt.get("logs") or [],
            status=_to_int(receipt.get("status")),
            return_data=return_data,
            gas_used=_to_int(receipt.get("gasUsed")),
            effective_gas_price=_to_int(receipt.get("effectiveGasPrice")),
            sender=receipt.get("from"),
            coinbase=(block or {}).get("miner"),
        )
        cap.failed_subcalls = failed_subcalls
        return cap
    except Exception:
        return None


def build_capture(
    *,
    prestate_diff: Optional[Dict[str, Any]],
    raw_logs: Optional[List[Dict[str, Any]]] = None,
    status: Optional[int] = None,
    return_data: Optional[str] = None,
    gas_used: Optional[int] = None,
    effective_gas_price: Optional[int] = None,
    sender: Optional[str] = None,
    coinbase: Optional[str] = None,
    failed_subcalls: Optional[int] = None,
) -> StateCapture:
    """Assemble a StateCapture from a prestate diff + receipt fields."""
    accounts = parse_account_diffs(prestate_diff) if prestate_diff else {}
    gas_cost = None
    if gas_used is not None and effective_gas_price is not None:
        gas_cost = int(gas_used) * int(effective_gas_price)
    return StateCapture(
        status=status,
        return_data=(str(return_data).lower() if return_data is not None else None),
        gas_used=gas_used,
        gas_cost_wei=gas_cost,
        sender=_norm_addr(sender) if sender else None,
        coinbase=_norm_addr(coinbase) if coinbase else None,
        accounts=accounts,
        logs=parse_logs(raw_logs or []),
        failed_subcalls=failed_subcalls,
    )

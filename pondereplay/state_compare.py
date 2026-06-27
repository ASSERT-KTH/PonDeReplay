"""
Compare two state captures for behavioral equivalence.

Used in two places (same engine, see ``docs/tx-replay-comparison.md``):
- **reproduction check**: original-replay vs live chain — did the replay reproduce the
  real on-chain tx? (reported as "reproduces chain")
- **preservation test**: patched-replay vs original-replay — does the patch change behavior?

The verdict polarity (benign wants equivalence, attack wants the exploit effect gone)
lives in ``classifier.py``; this module is neutral and just reports divergences with a
severity per the field tolerance classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .state_diff import AccountDiff, StateCapture, ZERO_WORD, _norm_word

# Severity: only ``critical`` flips equivalence. The others are recorded for inspection.
CRITICAL = "critical"
CONTEXT_INDUCED = "context_induced"  # would be critical but context is unfaithful
VALUE_DRIFT = (
    "value_drift"  # value-level diff tolerated in the cross-context reproduction check
)
LOOSE = "loose"  # informational only (gas, coinbase, sender nonce, failed subcalls)

DEFAULT_NUMERIC_DRIFT_TOLERANCE = 0.10

# Human-readable keys for divergence sides in JSON output.
_SIDE_KEYS = {
    "original_replay": "original",
    "live": "live",
    "patched_replay": "patch",
}


def _side_key(label: str) -> str:
    """Map internal compare label to report field name (original / live / patch)."""
    return _SIDE_KEYS.get(
        label, label.removesuffix("_replay") if label.endswith("_replay") else label
    )


@dataclass
class Divergence:
    category: str
    severity: str
    account: Optional[str] = None
    slot: Optional[str] = None
    a: Any = None
    b: Any = None
    note: Optional[str] = None
    relative_error: Optional[float] = None

    def to_dict(
        self,
        label_a: str = "a",
        label_b: str = "b",
    ) -> Dict[str, Any]:
        out: Dict[str, Any] = {"category": self.category, "severity": self.severity}
        for k in ("account", "slot", "note", "relative_error"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        out[_side_key(label_a)] = self.a
        out[_side_key(label_b)] = self.b
        return out


@dataclass
class ComparisonReport:
    state_equivalent: bool
    divergences: List[Divergence] = field(default_factory=list)
    context_faithful: bool = True
    label_a: str = "a"
    label_b: str = "b"
    max_relative_drift: Optional[float] = None

    @property
    def critical(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == CRITICAL]

    @property
    def context_induced(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == CONTEXT_INDUCED]

    @property
    def value_drift(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == VALUE_DRIFT]

    @property
    def loose(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == LOOSE]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_equivalent": self.state_equivalent,
            "context_faithful": self.context_faithful,
            "compared": [self.label_a, self.label_b],
            "critical_divergence_count": len(self.critical),
            "context_induced_count": len(self.context_induced),
            "value_drift_count": len(self.value_drift),
            "loose_count": len(self.loose),
            "max_relative_drift": self.max_relative_drift,
            "divergences": [
                d.to_dict(self.label_a, self.label_b) for d in self.divergences
            ],
        }


def classify_storage_word(word: str) -> str:
    """
    Classify a 32-byte storage word for calibrated reproduction-check comparison.

    Returns one of ``bool``, ``address``, ``opaque``, ``numeric``.
    """
    w = _norm_word(word)
    n = int(w, 16)
    if n <= 1:
        return "bool"
    # Full-word hashes / packed fields use the high bytes.
    if w[2:26] != "0" * 24:
        return "opaque"
    # Top 12 bytes zero: small integers sit in the low bytes; addresses use bytes 12–31.
    if w[26:42] != "0" * 16:
        return "address"
    return "numeric"


def relative_error(a: int, b: int) -> float:
    """Relative error between two integers; stable at zero."""
    if a == b:
        return 0.0
    denom = max(abs(a), abs(b), 1)
    return abs(a - b) / denom


def within_relative_tolerance(
    a: int, b: int, tolerance: float = DEFAULT_NUMERIC_DRIFT_TOLERANCE
) -> bool:
    return relative_error(a, b) <= tolerance


def _storage_divergence(
    fa: str,
    fb: str,
    *,
    calibrated: bool,
    context_faithful: bool,
    numeric_drift_tolerance: float,
) -> Optional[Tuple[str, Optional[float], Optional[str]]]:
    """
    Severity for a storage slot mismatch.

    Returns ``(severity, relative_error, note)`` or ``None`` if values match.
    """
    if fa == fb:
        return None

    if not calibrated:
        severity = CRITICAL if context_faithful else CONTEXT_INDUCED
        return severity, None, None

    kind = classify_storage_word(fa)
    if kind == "bool":
        return CRITICAL, None, "storage kind=bool requires exact match"

    # Address-shaped words that differ only slightly are usually runtime indices /
    # fixed-point rates mis-tagged by shape; a real owner/admin swap moves the whole
    # 160-bit payload and shows up as a large relative error. Only bool stays exact.
    ia, ib = int(fa, 16), int(fb, 16)
    err = relative_error(ia, ib)
    if within_relative_tolerance(ia, ib, numeric_drift_tolerance):
        return (
            VALUE_DRIFT,
            err,
            f"{kind} within {numeric_drift_tolerance:.0%} tolerance",
        )
    return CRITICAL, err, f"{kind} exceeds {numeric_drift_tolerance:.0%} tolerance"


def _value_severity(structural_only: bool, context_faithful: bool) -> str:
    """
    Default severity for non-storage value-level fields (logs, balances, return data).

    Storage uses :func:`_storage_divergence` when ``structural_only`` is set.
    """
    if structural_only:
        return VALUE_DRIFT
    return CRITICAL if context_faithful else CONTEXT_INDUCED


def _final_storage_value(diff: Optional[AccountDiff], slot: str) -> Optional[str]:
    """Final value of ``slot`` for a capture, or None if untouched (== fork baseline)."""
    if diff is None or slot not in diff.storage:
        return None
    return diff.storage[slot][1]


def _baseline_storage_value(
    a: Optional[AccountDiff], b: Optional[AccountDiff], slot: str
) -> str:
    """Pre-tx value of ``slot`` (identical across runs that fork the same block)."""
    for d in (a, b):
        if d is not None and slot in d.storage:
            return d.storage[slot][0]
    from .state_diff import ZERO_WORD

    return ZERO_WORD


def _failed_subcalls_match(a: Optional[int], b: Optional[int]) -> Optional[bool]:
    if a is None or b is None:
        return None
    return a == b


def compare(
    a: StateCapture,
    b: StateCapture,
    *,
    context_faithful: bool = True,
    structural_only: bool = False,
    numeric_drift_tolerance: float = DEFAULT_NUMERIC_DRIFT_TOLERANCE,
    b_added_storage_loose: bool = False,
    gas_confounded: bool = False,
    label_a: str = "a",
    label_b: str = "b",
) -> ComparisonReport:
    """
    Compare capture ``a`` against ``b`` field-by-field with tolerance classes.

    Both captures must come from runs that fork the same block N-1.

    ``structural_only`` enables the calibrated **reproduction check** (O→L):
    - structural fields and exact bool slots are critical;
    - address/numeric/opaque storage within ``numeric_drift_tolerance`` is ``value_drift``,
      critical beyond it;
    - logs whose event identity (address + topics + order) differs are critical, while a
      data-only difference (accrued amounts) is ``value_drift``;
    - non-sender ETH balance deltas use the same numeric tolerance as storage; the sender's
      non-gas delta stays ``value_drift`` (gas-normalization residue never fully cancels O→L).

    The **preservation test** (O→P, ``structural_only=False``) keeps all value fields
    exact/critical, with two confound-aware exceptions (both downgrade to ``loose``,
    still recorded for inspection):
    - ``b_added_storage_loose``: a slot ``b`` (the patch) writes that ``a`` (original)
      never touches *and* whose pre-tx baseline is zero is patch-introduced state with
      no original analog (e.g. a new cooldown/nonce mapping) — not a behavioral change.
      A nonzero-baseline slot the patch alters while original preserves it stays critical.
    - ``gas_confounded``: when the patched run's gas limit was bumped, the sender's
      gas-normalized balance residue no longer cancels in O→P, so the sender balance
      delta is gas noise rather than a real value movement.

    ``failed_subcalls`` count mismatches are always ``loose`` (reported, never critical).
    """
    divergences: List[Divergence] = []
    value_sev = _value_severity(structural_only, context_faithful)
    max_drift: Optional[float] = None

    # --- status (structural, critical) ---
    if a.status is not None and b.status is not None and a.status != b.status:
        divergences.append(Divergence("status", CRITICAL, a=a.status, b=b.status))

    # --- failed subcalls (loose, never critical) ---
    subcall_match = _failed_subcalls_match(a.failed_subcalls, b.failed_subcalls)
    if subcall_match is False:
        divergences.append(
            Divergence(
                "failed_subcalls",
                LOOSE,
                a=a.failed_subcalls,
                b=b.failed_subcalls,
                note="inner revert count differs",
            )
        )

    # --- return data (value-level) ---
    if (
        a.return_data is not None
        and b.return_data is not None
        and a.return_data != b.return_data
    ):
        divergences.append(
            Divergence("return_data", value_sev, a=a.return_data, b=b.return_data)
        )

    # Accounts excluded from value/scope comparison entirely (gas artifacts).
    coinbases = {c for c in (a.coinbase, b.coinbase) if c}
    sender = a.sender or b.sender

    # --- account scope (structural, critical) ---
    only_in_a = (set(a.accounts) - set(b.accounts)) - coinbases - {sender}
    only_in_b = (set(b.accounts) - set(a.accounts)) - coinbases - {sender}
    for addr in sorted(only_in_a | only_in_b):
        divergences.append(
            Divergence(
                "account_scope",
                CRITICAL,
                account=addr,
                a=(addr in a.accounts),
                b=(addr in b.accounts),
                note="account touched in only one execution",
            )
        )

    all_accounts = (set(a.accounts) | set(b.accounts)) - coinbases
    for addr in sorted(all_accounts):
        da = a.accounts.get(addr)
        db = b.accounts.get(addr)

        # --- storage ---
        slots = set(da.storage if da else {}) | set(db.storage if db else {})
        for slot in sorted(slots):
            base = _baseline_storage_value(da, db, slot)
            fa = _final_storage_value(da, slot) or base
            fb = _final_storage_value(db, slot) or base
            outcome = _storage_divergence(
                fa,
                fb,
                calibrated=structural_only,
                context_faithful=context_faithful,
                numeric_drift_tolerance=numeric_drift_tolerance,
            )
            if outcome is None:
                continue
            severity, err, note = outcome
            # Patch-introduced storage: a slot only the patch writes, with a zero
            # pre-tx baseline, has no analog in the original execution — it is added
            # bookkeeping (new state variable), not an altered original effect.
            if (
                b_added_storage_loose
                and severity == CRITICAL
                and base == ZERO_WORD
                and _final_storage_value(da, slot) is None
                and _final_storage_value(db, slot) is not None
            ):
                severity = LOOSE
                err = None
                note = (
                    "patch-only storage: slot introduced by patch, no original analog"
                )
            if err is not None:
                if max_drift is None or err > max_drift:
                    max_drift = err
            divergences.append(
                Divergence(
                    "storage",
                    severity,
                    account=addr,
                    slot=slot,
                    a=fa,
                    b=fb,
                    note=note,
                    relative_error=err,
                )
            )

        # --- balance (value-level) ---
        delta_a = da.balance_delta if da else 0
        delta_b = db.balance_delta if db else 0
        if addr == sender:
            adj_a = delta_a + (a.gas_cost_wei or 0)
            adj_b = delta_b + (b.gas_cost_wei or 0)
            if adj_a != adj_b:
                # Sender balance stays value-level even in the reproduction check: the
                # gas-normalization residue between the local fork's gas regime and live
                # never fully cancels in O->L (it cancels in O->P, same fork — unless the
                # patched run's gas limit was bumped, which reintroduces the residue).
                bal_sev = value_sev
                note = "sender non-gas balance delta"
                # A gas bump can only introduce a gas-sized residue; bound the
                # downgrade to the gas envelope so a genuinely larger value change to
                # the sender that merely coincides with a bump stays critical.
                if gas_confounded and abs(adj_a - adj_b) <= max(
                    a.gas_cost_wei or 0, b.gas_cost_wei or 0
                ):
                    bal_sev = LOOSE
                    note = "sender balance residue within patch gas-limit bump envelope"
                divergences.append(
                    Divergence(
                        "balance",
                        bal_sev,
                        account=addr,
                        a=adj_a,
                        b=adj_b,
                        note=note,
                    )
                )
        elif delta_a != delta_b:
            bal_sev = value_sev
            bal_err: Optional[float] = None
            if structural_only:
                # Reproduction check: tolerate small accrual drift in a non-sender ETH
                # balance, but a large divergence means a different value moved on chain
                # than in the replay — a real reproduction failure.
                bal_err = relative_error(delta_a, delta_b)
                bal_sev = (
                    VALUE_DRIFT
                    if within_relative_tolerance(
                        delta_a, delta_b, numeric_drift_tolerance
                    )
                    else CRITICAL
                )
                if max_drift is None or bal_err > max_drift:
                    max_drift = bal_err
            divergences.append(
                Divergence(
                    "balance",
                    bal_sev,
                    account=addr,
                    a=delta_a,
                    b=delta_b,
                    relative_error=bal_err,
                )
            )

        # --- nonce ---
        na = (da.nonce_new or 0) - (da.nonce_old or 0) if da else 0
        nb = (db.nonce_new or 0) - (db.nonce_old or 0) if db else 0
        if na != nb:
            severity = LOOSE if addr == sender else CRITICAL
            divergences.append(Divergence("nonce", severity, account=addr, a=na, b=nb))

        # --- code (structural, critical) ---
        ca = (da.code_new if da else None) or "0x"
        cb = (db.code_new if db else None) or "0x"
        if ca != cb:
            divergences.append(Divergence("code", CRITICAL, account=addr, a=ca, b=cb))

    # --- logs ---
    keys_a = [log.key() for log in a.logs]
    keys_b = [log.key() for log in b.logs]
    if keys_a != keys_b:
        log_sev = value_sev
        note = "emitted logs differ (address/topics/data/order)"
        if structural_only:
            # Reproduction check: a different set/order of *events* (address + topics) is a
            # structural reproduction failure (a different execution path emitted them);
            # differences confined to log *data* (e.g. accrued amounts) are tolerated drift
            # like the other value-level O->L fields.
            struct_a = [(log.address, tuple(log.topics)) for log in a.logs]
            struct_b = [(log.address, tuple(log.topics)) for log in b.logs]
            if struct_a != struct_b:
                log_sev = CRITICAL
                note = "emitted events differ (address/topics/count/order)"
            else:
                log_sev = VALUE_DRIFT
                note = "log data differs (amounts only; events match)"
        divergences.append(
            Divergence(
                "logs",
                log_sev,
                a=[log.to_dict() for log in a.logs],
                b=[log.to_dict() for log in b.logs],
                note=note,
            )
        )

    state_equivalent = not any(d.severity == CRITICAL for d in divergences)
    return ComparisonReport(
        state_equivalent=state_equivalent,
        divergences=divergences,
        context_faithful=context_faithful,
        label_a=label_a,
        label_b=label_b,
        max_relative_drift=max_drift,
    )


def reproduction_check(
    original: StateCapture,
    live: StateCapture,
    *,
    context_faithful: bool = True,
    numeric_drift_tolerance: float = DEFAULT_NUMERIC_DRIFT_TOLERANCE,
) -> ComparisonReport:
    """
    Did the original replay reproduce the live on-chain tx (structural + calibrated
    storage)? Reported as ``reproduces_chain``. When this fails, the patch verdict is
    ``inconclusive``.
    """
    return compare(
        original,
        live,
        context_faithful=context_faithful,
        structural_only=True,
        numeric_drift_tolerance=numeric_drift_tolerance,
        label_a="original_replay",
        label_b="live",
    )


def preservation_test(
    original: StateCapture,
    patched: StateCapture,
    *,
    context_faithful: bool = True,
    gas_confounded: bool = False,
) -> ComparisonReport:
    """Preservation/effectiveness test: does the patch change the state effect?

    ``gas_confounded`` (the patched run's gas limit was bumped) downgrades the sender's
    gas-residue balance delta to ``loose``. Patch-introduced storage (slots only the
    patch writes, zero baseline) is always downgraded to ``loose`` here.
    """
    return compare(
        original,
        patched,
        context_faithful=context_faithful,
        b_added_storage_loose=True,
        gas_confounded=gas_confounded,
        label_a="original_replay",
        label_b="patched_replay",
    )

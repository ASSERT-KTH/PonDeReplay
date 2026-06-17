"""
Compare two state captures for behavioral equivalence.

Used in two places (same engine, see ``docs/state-comparison.md``):
- **reproduction check**: original-replay vs live chain — did the replay reproduce the
  real on-chain tx? (reported as "reproduces chain")
- **test**: patched-replay vs original-replay — does the patch change behavior?

The verdict polarity (benign wants equivalence, attack wants the exploit effect gone)
lives in ``classifier.py``; this module is neutral and just reports divergences with a
severity per the field tolerance classes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .state_diff import AccountDiff, StateCapture

# Severity: only ``critical`` flips equivalence. The others are recorded for inspection.
CRITICAL = "critical"
CONTEXT_INDUCED = "context_induced"  # would be critical but context is unfaithful
VALUE_DRIFT = "value_drift"  # value-level diff tolerated in the cross-context reproduction check
LOOSE = "loose"  # informational only (gas, coinbase, sender nonce)


@dataclass
class Divergence:
    category: str
    severity: str
    account: Optional[str] = None
    slot: Optional[str] = None
    a: Any = None
    b: Any = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {"category": self.category, "severity": self.severity}
        for k in ("account", "slot", "note"):
            v = getattr(self, k)
            if v is not None:
                out[k] = v
        out["a"] = self.a
        out["b"] = self.b
        return out


@dataclass
class ComparisonReport:
    state_equivalent: bool
    divergences: List[Divergence] = field(default_factory=list)
    context_faithful: bool = True
    label_a: str = "a"
    label_b: str = "b"

    @property
    def critical(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == CRITICAL]

    @property
    def context_induced(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == CONTEXT_INDUCED]

    @property
    def value_drift(self) -> List[Divergence]:
        return [d for d in self.divergences if d.severity == VALUE_DRIFT]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_equivalent": self.state_equivalent,
            "context_faithful": self.context_faithful,
            "compared": [self.label_a, self.label_b],
            "critical_divergence_count": len(self.critical),
            "context_induced_count": len(self.context_induced),
            "value_drift_count": len(self.value_drift),
            "divergences": [d.to_dict() for d in self.divergences],
        }


def _value_severity(structural_only: bool, context_faithful: bool) -> str:
    """
    Severity for value-level fields (storage, logs, balances, return data).

    - Same-context **test**: critical (context-gated for time/block-derived storage and
      logs). Drift cancels between two replays in one fork, so any remaining diff is real.
    - Cross-context **reproduction check** (replay vs live): downgraded to ``value_drift``.
      Interest accrual over the replayed prior-tx sequence and the amounts derived from it
      differ by tiny amounts that the test cancels but the live comparison cannot. Only
      *structural* divergence (status / account-scope / code) is critical here.
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


def compare(
    a: StateCapture,
    b: StateCapture,
    *,
    context_faithful: bool = True,
    structural_only: bool = False,
    label_a: str = "a",
    label_b: str = "b",
) -> ComparisonReport:
    """
    Compare capture ``a`` against ``b`` field-by-field with tolerance classes.

    Both captures must come from runs that fork the same block N-1.

    ``structural_only`` switches to the **structural** comparison used for the
    cross-context reproduction check (original-replay vs live): value-level fields
    (storage/logs/balances/return data) are downgraded to ``value_drift`` (non-fatal), so
    only *structural* divergence — status mismatch, account-scope (a contract touched in
    only one execution), code create/destruct, and CREATE-nonce — flips
    ``state_equivalent``. The same-context test (``structural_only=False``) keeps value
    fields critical.
    """
    divergences: List[Divergence] = []
    value_sev = _value_severity(structural_only, context_faithful)

    # --- status (structural, critical) ---
    if a.status is not None and b.status is not None and a.status != b.status:
        divergences.append(Divergence("status", CRITICAL, a=a.status, b=b.status))

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
    # An account touched in exactly one execution is a path difference. Accrual touches
    # the same accounts in both runs (only the values drift), so this is robust to drift.
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

        # --- storage (value-level) ---
        slots = set(da.storage if da else {}) | set(db.storage if db else {})
        for slot in sorted(slots):
            base = _baseline_storage_value(da, db, slot)
            fa = _final_storage_value(da, slot) or base
            fb = _final_storage_value(db, slot) or base
            if fa != fb:
                divergences.append(
                    Divergence(
                        "storage", value_sev, account=addr, slot=slot, a=fa, b=fb
                    )
                )

        # --- balance (value-level) ---
        delta_a = da.balance_delta if da else 0
        delta_b = db.balance_delta if db else 0
        if addr == sender:
            # Normalize out gas: compare the value-only (non-gas) portion.
            adj_a = delta_a + (a.gas_cost_wei or 0)
            adj_b = delta_b + (b.gas_cost_wei or 0)
            if adj_a != adj_b:
                divergences.append(
                    Divergence(
                        "balance",
                        value_sev,
                        account=addr,
                        a=adj_a,
                        b=adj_b,
                        note="sender non-gas balance delta",
                    )
                )
        elif delta_a != delta_b:
            divergences.append(
                Divergence("balance", value_sev, account=addr, a=delta_a, b=delta_b)
            )

        # --- nonce ---
        na = (da.nonce_new or 0) - (da.nonce_old or 0) if da else 0
        nb = (db.nonce_new or 0) - (db.nonce_old or 0) if db else 0
        if na != nb:
            # Sender nonce always +1 (loose); CREATE-driven nonce is structural/critical.
            severity = LOOSE if addr == sender else CRITICAL
            divergences.append(Divergence("nonce", severity, account=addr, a=na, b=nb))

        # --- code (structural, critical) ---
        ca = (da.code_new if da else None) or "0x"
        cb = (db.code_new if db else None) or "0x"
        if ca != cb:
            divergences.append(Divergence("code", CRITICAL, account=addr, a=ca, b=cb))

    # --- logs (value-level) ---
    keys_a = [log.key() for log in a.logs]
    keys_b = [log.key() for log in b.logs]
    if keys_a != keys_b:
        divergences.append(
            Divergence(
                "logs",
                value_sev,
                a=[log.to_dict() for log in a.logs],
                b=[log.to_dict() for log in b.logs],
                note="emitted logs differ (address/topics/data/order)",
            )
        )

    state_equivalent = not any(d.severity == CRITICAL for d in divergences)
    return ComparisonReport(
        state_equivalent=state_equivalent,
        divergences=divergences,
        context_faithful=context_faithful,
        label_a=label_a,
        label_b=label_b,
    )


def reproduction_check(
    original: StateCapture,
    live: StateCapture,
    *,
    context_faithful: bool = True,
) -> ComparisonReport:
    """
    Did the original replay reproduce the live on-chain tx *structurally* (status,
    account-scope, code), tolerating value-level drift (accrual)? Reported to users as
    "reproduces chain". When this fails, the patch verdict is ``inconclusive``.
    """
    return compare(
        original,
        live,
        context_faithful=context_faithful,
        structural_only=True,
        label_a="original_replay",
        label_b="live",
    )


def preservation_test(
    original: StateCapture,
    patched: StateCapture,
    *,
    context_faithful: bool = True,
) -> ComparisonReport:
    """Preservation/effectiveness test: does the patch change the state effect?"""
    return compare(
        original,
        patched,
        context_faithful=context_faithful,
        label_a="original_replay",
        label_b="patched_replay",
    )

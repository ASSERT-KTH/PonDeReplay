"""Tests for state diff parsing and behavioral-equivalence comparison."""

from pondereplay.state_diff import (
    ZERO_WORD,
    build_capture,
    parse_account_diffs,
    parse_logs,
)
from pondereplay.state_compare import (
    CRITICAL,
    CONTEXT_INDUCED,
    VALUE_DRIFT,
    compare,
    gate,
)


def _word(n: int) -> str:
    return "0x" + format(n, "064x")


SENDER = "0x1111111111111111111111111111111111111111"
COINBASE = "0x2222222222222222222222222222222222222222"
TOKEN = "0x3333333333333333333333333333333333333333"
SLOT = _word(7)


class TestParseAccountDiffs:
    def test_storage_noop_dropped(self):
        diff = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(5)}}},
        }
        accounts = parse_account_diffs(diff)
        assert accounts == {}

    def test_storage_change_kept(self):
        diff = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        accounts = parse_account_diffs(diff)
        assert TOKEN in accounts
        assert accounts[TOKEN].storage[SLOT] == (_word(5), _word(9))

    def test_created_slot_defaults_old_zero(self):
        diff = {"pre": {}, "post": {TOKEN: {"storage": {SLOT: _word(3)}}}}
        accounts = parse_account_diffs(diff)
        assert accounts[TOKEN].storage[SLOT] == (ZERO_WORD, _word(3))

    def test_balance_delta(self):
        diff = {
            "pre": {SENDER: {"balance": hex(100)}},
            "post": {SENDER: {"balance": hex(40)}},
        }
        accounts = parse_account_diffs(diff)
        assert accounts[SENDER].balance_delta == -60

    def test_pre_image_code_is_not_a_change(self):
        # diffMode puts full pre-image (incl. code/balance) in `pre`; only `post` marks
        # changes. An account whose only real change is storage must not report a code
        # or balance change just because pre carries the pre-image.
        diff = {
            "pre": {
                TOKEN: {
                    "balance": hex(5),
                    "nonce": 1,
                    "code": "0xdeadbeef",
                    "storage": {SLOT: _word(5)},
                }
            },
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        accounts = parse_account_diffs(diff)
        a = accounts[TOKEN]
        assert a.code_new is None and a.code_old is None  # no code change
        assert a.balance_delta == 0  # no balance change
        assert a.storage[SLOT] == (_word(5), _word(9))

    def test_pre_only_accessed_account_dropped(self):
        # Some nodes list accessed-but-unmodified contracts in `pre` (nonce+code, no
        # balance/storage). That is NOT a selfdestruct and must not produce a diff,
        # otherwise the live gate sees spurious cross-client scope/nonce/code divergences.
        diff = {
            "pre": {TOKEN: {"nonce": 1, "code": "0xabcd"}},
            "post": {},
        }
        assert parse_account_diffs(diff) == {}

    def test_pre_only_zero_balance_account_dropped(self):
        # Same artifact but the node included an explicit balance:0x0 — still not a real
        # deletion (no positive balance, no storage), so it must be dropped.
        diff = {
            "pre": {TOKEN: {"nonce": 1, "balance": "0x0", "code": "0xabcd"}},
            "post": {},
        }
        assert parse_account_diffs(diff) == {}

    def test_selfdestruct_zeroes_account(self):
        # Account in pre but absent from post -> deleted.
        diff = {
            "pre": {
                TOKEN: {
                    "balance": hex(9),
                    "code": "0xabcd",
                    "storage": {SLOT: _word(7)},
                }
            },
            "post": {},
        }
        accounts = parse_account_diffs(diff)
        a = accounts[TOKEN]
        assert a.balance_new == 0 and a.balance_old == 9
        assert a.code_new == "0x" and a.code_old == "0xabcd"
        assert a.storage[SLOT] == (_word(7), ZERO_WORD)


class TestParseLogs:
    def test_normalizes_case_and_data(self):
        logs = parse_logs(
            [{"address": TOKEN.upper(), "topics": ["0xABC"], "data": "0xDEAD"}]
        )
        assert logs[0].address == TOKEN
        assert logs[0].topics == ["0xabc"]
        assert logs[0].data == "0xdead"


class TestCompare:
    def _cap(self, diff, **kw):
        return build_capture(prestate_diff=diff, sender=SENDER, coinbase=COINBASE, **kw)

    def test_identical_is_equivalent(self):
        diff = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        rep = compare(self._cap(diff), self._cap(diff))
        assert rep.state_equivalent is True
        assert rep.divergences == []

    def test_storage_divergence_is_critical(self):
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(99)}}},
        }
        rep = compare(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(
            d.category == "storage" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_one_sided_touch_compares_against_baseline(self):
        # b leaves the slot at its baseline (5); a moves it to 9 -> divergence.
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {"pre": {}, "post": {}}
        rep = compare(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False

    def test_storage_divergence_downgraded_when_context_unfaithful(self):
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(99)}}},
        }
        rep = compare(self._cap(a), self._cap(b), context_faithful=False)
        assert rep.state_equivalent is True  # no critical divergence
        assert any(d.severity == CONTEXT_INDUCED for d in rep.divergences)

    def test_coinbase_excluded(self):
        a = {
            "pre": {COINBASE: {"balance": hex(0)}},
            "post": {COINBASE: {"balance": hex(1000)}},
        }
        b = {
            "pre": {COINBASE: {"balance": hex(0)}},
            "post": {COINBASE: {"balance": hex(2000)}},
        }
        rep = compare(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True

    def test_sender_gas_normalized(self):
        # Same value sent (-100), different gas cost -> equivalent after normalization.
        a = {
            "pre": {SENDER: {"balance": hex(1000)}},
            "post": {SENDER: {"balance": hex(880)}},
        }
        b = {
            "pre": {SENDER: {"balance": hex(1000)}},
            "post": {SENDER: {"balance": hex(870)}},
        }
        rep = compare(
            build_capture(
                prestate_diff=a,
                sender=SENDER,
                coinbase=COINBASE,
                gas_used=20,
                effective_gas_price=1,
            ),
            build_capture(
                prestate_diff=b,
                sender=SENDER,
                coinbase=COINBASE,
                gas_used=30,
                effective_gas_price=1,
            ),
        )
        # a: delta -120 + gas 20 = -100 ; b: delta -130 + gas 30 = -100
        assert rep.state_equivalent is True

    def test_sender_non_gas_divergence_is_critical(self):
        a = {
            "pre": {SENDER: {"balance": hex(1000)}},
            "post": {SENDER: {"balance": hex(900)}},
        }
        b = {
            "pre": {SENDER: {"balance": hex(1000)}},
            "post": {SENDER: {"balance": hex(800)}},
        }
        rep = compare(
            build_capture(
                prestate_diff=a,
                sender=SENDER,
                coinbase=COINBASE,
                gas_used=0,
                effective_gas_price=0,
            ),
            build_capture(
                prestate_diff=b,
                sender=SENDER,
                coinbase=COINBASE,
                gas_used=0,
                effective_gas_price=0,
            ),
        )
        assert rep.state_equivalent is False
        assert any(
            d.category == "balance" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_status_divergence(self):
        a = build_capture(prestate_diff={}, status=1)
        b = build_capture(prestate_diff={}, status=0)
        rep = compare(a, b)
        assert rep.state_equivalent is False
        assert any(d.category == "status" for d in rep.divergences)

    def test_log_divergence(self):
        a = build_capture(
            prestate_diff={},
            raw_logs=[{"address": TOKEN, "topics": ["0x1"], "data": "0x"}],
        )
        b = build_capture(
            prestate_diff={},
            raw_logs=[{"address": TOKEN, "topics": ["0x2"], "data": "0x"}],
        )
        rep = compare(a, b)
        assert rep.state_equivalent is False
        assert any(d.category == "logs" for d in rep.divergences)

    def test_sender_nonce_is_loose(self):
        a = {"pre": {SENDER: {"nonce": 5}}, "post": {SENDER: {"nonce": 6}}}
        b = {"pre": {SENDER: {"nonce": 5}}, "post": {SENDER: {"nonce": 6}}}
        rep = compare(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True


class TestStructuralGate:
    def _cap(self, diff, **kw):
        return build_capture(prestate_diff=diff, sender=SENDER, coinbase=COINBASE, **kw)

    def test_gate_tolerates_value_drift(self):
        # Storage/log/balance differences are value_drift in the gate -> faithful.
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(10)}}},  # accrual drift
        }
        rep = gate(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True
        assert any(d.severity == VALUE_DRIFT for d in rep.divergences)

    def test_gate_fails_on_status_mismatch(self):
        rep = gate(
            build_capture(prestate_diff={}, status=1, sender=SENDER),
            build_capture(prestate_diff={}, status=0, sender=SENDER),
        )
        assert rep.state_equivalent is False
        assert any(d.category == "status" for d in rep.critical)

    def test_gate_fails_on_account_scope(self):
        # An extra contract touched in only one execution -> structural divergence.
        other = "0x4444444444444444444444444444444444444444"
        a = {
            "pre": {other: {"storage": {SLOT: _word(0)}}},
            "post": {other: {"storage": {SLOT: _word(1)}}},
        }
        b = {"pre": {}, "post": {}}
        rep = gate(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(d.category == "account_scope" for d in rep.critical)

    def test_gate_fails_on_code_change(self):
        a = {"pre": {TOKEN: {"code": "0xabcd"}}, "post": {TOKEN: {"code": "0xbeef"}}}
        b = {"pre": {}, "post": {}}
        rep = gate(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        # code change shows up (account_scope and/or code), both critical/structural
        assert any(d.category in ("code", "account_scope") for d in rep.critical)

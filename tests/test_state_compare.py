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
    LOOSE,
    VALUE_DRIFT,
    classify_storage_word,
    compare,
    reproduction_check,
    relative_error,
    within_relative_tolerance,
)


def _word(n: int) -> str:
    return "0x" + format(n, "064x")


def _addr_word(addr: str) -> str:
    a = addr.lower().replace("0x", "")
    return "0x" + "0" * 24 + a.zfill(40)[-40:]


def _opaque_word(tail: str = "aa") -> str:
    """32-byte word with non-zero high bytes (hash-like)."""
    t = tail.lower().replace("0x", "")[-62:]
    return "0xab" + "00" * 29 + t.zfill(2)[-2:]


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

    def test_patch_only_new_slot_is_loose(self):
        # Both runs touch the account and agree on the shared slot; the patch writes
        # an extra slot (zero baseline) the original never touches -> new patch state
        # with no original analog, downgraded to loose (mirrors OMPx cooldown mapping).
        NEW_SLOT = _word(8)
        orig = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        patch = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5), NEW_SLOT: ZERO_WORD}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9), NEW_SLOT: _word(123)}}},
        }
        rep = compare(self._cap(orig), self._cap(patch), b_added_storage_loose=True)
        assert rep.state_equivalent is True
        d = next(d for d in rep.divergences if d.slot == NEW_SLOT)
        assert d.severity == LOOSE
        # Without the flag the same write is a critical behavioral change.
        assert compare(self._cap(orig), self._cap(patch)).state_equivalent is False

    def test_patch_modifying_existing_nonzero_slot_stays_critical(self):
        # Nonzero baseline: original preserves it, patch changes it -> the patch
        # altered pre-existing state, which is a real divergence (not new state).
        orig = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(5)}}},
        }
        patch = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        rep = compare(self._cap(orig), self._cap(patch), b_added_storage_loose=True)
        assert rep.state_equivalent is False

    def test_original_only_slot_stays_critical(self):
        # The asymmetric guard must not fire when *original* writes a slot the patch
        # leaves untouched (patch suppressed a write) -> still a real divergence.
        orig = {
            "pre": {TOKEN: {"storage": {SLOT: ZERO_WORD}}},
            "post": {TOKEN: {"storage": {SLOT: _word(123)}}},
        }
        patch = {"pre": {}, "post": {}}
        rep = compare(self._cap(orig), self._cap(patch), b_added_storage_loose=True)
        assert rep.state_equivalent is False

    def _sender_caps(self, post_a, post_b, gas_a, gas_b):
        diffs = (
            {
                "pre": {SENDER: {"balance": hex(1000)}},
                "post": {SENDER: {"balance": hex(post_a)}},
            },
            {
                "pre": {SENDER: {"balance": hex(1000)}},
                "post": {SENDER: {"balance": hex(post_b)}},
            },
        )
        gas = (gas_a, gas_b)
        return [
            build_capture(
                prestate_diff=d,
                sender=SENDER,
                coinbase=COINBASE,
                gas_used=g,
                effective_gas_price=1,
            )
            for d, g in zip(diffs, gas)
        ]

    def test_sender_balance_loose_when_gas_confounded(self):
        # Residue (adj_a=-20 vs adj_b=0 -> 20) sits within the gas envelope
        # (max gas cost 130) -> downgraded to loose when the patch gas was bumped.
        caps = self._sender_caps(post_a=880, post_b=870, gas_a=100, gas_b=130)
        rep = compare(*caps, gas_confounded=True)
        assert rep.state_equivalent is True
        assert any(
            d.category == "balance" and d.severity == LOOSE for d in rep.divergences
        )
        # Without the confound flag the same residue stays critical.
        assert compare(*caps).state_equivalent is False

    def test_large_sender_divergence_stays_critical_despite_gas_confound(self):
        # Residue (adj_a=-20 vs adj_b=-670 -> 650) exceeds the gas envelope
        # (max gas cost 130): a real value change to the sender, not gas noise.
        caps = self._sender_caps(post_a=880, post_b=200, gas_a=100, gas_b=130)
        rep = compare(*caps, gas_confounded=True)
        assert rep.state_equivalent is False
        assert any(
            d.category == "balance" and d.severity == CRITICAL for d in rep.divergences
        )


class TestReproductionCheck:
    def _cap(self, diff, **kw):
        return build_capture(prestate_diff=diff, sender=SENDER, coinbase=COINBASE, **kw)

    def test_reproduction_check_tolerates_small_numeric_drift(self):
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(10)}}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True
        storage = [d for d in rep.divergences if d.category == "storage"]
        assert len(storage) == 1
        assert storage[0].severity == VALUE_DRIFT
        assert storage[0].relative_error is not None
        assert storage[0].relative_error <= 0.10

    def test_reproduction_check_fails_on_large_numeric_drift(self):
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(99)}}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(
            d.category == "storage" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_reproduction_check_tolerates_small_address_shaped_drift(self):
        # Alkemi-style index stored in an address-shaped word.
        index_slot = _word(4)
        wa = "0x00000000000000000000000000000004ecbebd06843bc44a8dd507e67447bae6"
        wb = "0x00000000000000000000000000000004ecbce89660ebea30c715b3454d5427da"
        assert classify_storage_word(wa) == "address"
        a = {
            "pre": {TOKEN: {"storage": {index_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {index_slot: wa}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {index_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {index_slot: wb}}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True
        storage = [d for d in rep.divergences if d.category == "storage"]
        assert len(storage) == 1
        assert storage[0].severity == VALUE_DRIFT

    def test_reproduction_check_fails_on_address_mismatch(self):
        owner_slot = _word(1)
        a = {
            "pre": {TOKEN: {"storage": {owner_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {owner_slot: _addr_word(TOKEN)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {owner_slot: _word(0)}}},
            "post": {
                TOKEN: {"storage": {owner_slot: _addr_word(SENDER)}},
            },
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert classify_storage_word(_addr_word(TOKEN)) == "address"

    def test_reproduction_check_fails_on_bool_flip(self):
        bool_slot = _word(2)
        a = {
            "pre": {TOKEN: {"storage": {bool_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {bool_slot: _word(0)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {bool_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {bool_slot: _word(1)}}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False

    def test_reproduction_check_tolerates_small_opaque_drift(self):
        # Alkemi-style packed accrual index (opaque): small cross-context drift.
        hash_slot = _word(3)
        wa = "0x00f4780800000000000004f7c4e93f3fe669714e7cbeeb8976f563026e74e2b7"
        wb = "0x00f477f300000000000004f7c4e87f9b08f4f7467e7203a81f28b71724bb876c"
        assert classify_storage_word(wa) == "opaque"
        a = {
            "pre": {TOKEN: {"storage": {hash_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {hash_slot: wa}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {hash_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {hash_slot: wb}}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True
        storage = [d for d in rep.divergences if d.category == "storage"]
        assert len(storage) == 1
        assert storage[0].severity == VALUE_DRIFT
        assert storage[0].relative_error is not None
        assert storage[0].relative_error <= 0.10

    def test_reproduction_check_fails_on_large_opaque_drift(self):
        hash_slot = _word(3)
        wa = "0x" + "ab" * 32
        wb = "0x" + "cd" * 32
        assert classify_storage_word(wa) == "opaque"
        a = {
            "pre": {TOKEN: {"storage": {hash_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {hash_slot: wa}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {hash_slot: _word(0)}}},
            "post": {TOKEN: {"storage": {hash_slot: wb}}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(
            d.category == "storage" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_reproduction_check_subcall_mismatch_is_loose(self):
        rep = reproduction_check(
            build_capture(prestate_diff={}, sender=SENDER, failed_subcalls=0),
            build_capture(prestate_diff={}, sender=SENDER, failed_subcalls=1),
        )
        assert rep.state_equivalent is True
        sub = [d for d in rep.divergences if d.category == "failed_subcalls"]
        assert len(sub) == 1
        assert sub[0].severity == LOOSE

    def test_preservation_test_small_numeric_diff_is_critical(self):
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(10)}}},
        }
        rep = compare(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(
            d.category == "storage" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_preservation_test_subcall_mismatch_is_loose(self):
        rep = compare(
            build_capture(prestate_diff={}, sender=SENDER, failed_subcalls=0),
            build_capture(prestate_diff={}, sender=SENDER, failed_subcalls=2),
        )
        assert rep.state_equivalent is True
        assert any(
            d.category == "failed_subcalls" and d.severity == LOOSE
            for d in rep.divergences
        )

    def test_reproduction_check_log_data_only_is_drift(self):
        # Same event identity (address + topics), only the data payload (amount) drifts ->
        # tolerated as value_drift in the reproduction check.
        a = build_capture(
            prestate_diff={},
            sender=SENDER,
            raw_logs=[{"address": TOKEN, "topics": ["0x1"], "data": "0x01"}],
        )
        b = build_capture(
            prestate_diff={},
            sender=SENDER,
            raw_logs=[{"address": TOKEN, "topics": ["0x1"], "data": "0x02"}],
        )
        rep = reproduction_check(a, b)
        assert rep.state_equivalent is True
        logs = [d for d in rep.divergences if d.category == "logs"]
        assert len(logs) == 1 and logs[0].severity == VALUE_DRIFT

    def test_reproduction_check_log_event_mismatch_is_critical(self):
        # Different number / identity of events -> structural reproduction failure.
        a = build_capture(
            prestate_diff={},
            sender=SENDER,
            raw_logs=[
                {"address": TOKEN, "topics": ["0x1"], "data": "0x"},
                {"address": TOKEN, "topics": ["0x2"], "data": "0x"},
            ],
        )
        b = build_capture(
            prestate_diff={},
            sender=SENDER,
            raw_logs=[{"address": TOKEN, "topics": ["0x1"], "data": "0x"}],
        )
        rep = reproduction_check(a, b)
        assert rep.state_equivalent is False
        assert any(
            d.category == "logs" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_reproduction_check_nonsender_balance_small_drift_is_drift(self):
        # A non-sender account whose ETH balance drifts slightly (accrual) -> tolerated.
        a = {
            "pre": {TOKEN: {"balance": hex(1000)}},
            "post": {TOKEN: {"balance": hex(1100)}},
        }
        b = {
            "pre": {TOKEN: {"balance": hex(1000)}},
            "post": {TOKEN: {"balance": hex(1105)}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True
        bal = [d for d in rep.divergences if d.category == "balance"]
        assert len(bal) == 1 and bal[0].severity == VALUE_DRIFT

    def test_reproduction_check_nonsender_balance_large_drift_is_critical(self):
        # A non-sender account moving a wildly different ETH amount -> reproduction failure.
        a = {
            "pre": {TOKEN: {"balance": hex(1000)}},
            "post": {TOKEN: {"balance": hex(1100)}},
        }
        b = {
            "pre": {TOKEN: {"balance": hex(1000)}},
            "post": {TOKEN: {"balance": hex(9000)}},
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(
            d.category == "balance" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_reproduction_check_sender_nongas_balance_stays_drift(self):
        # Sender non-gas balance delta differs (gas-normalization residue across O->L) ->
        # stays value_drift even when large, never fails the reproduction check.
        a = {
            "pre": {SENDER: {"balance": hex(1000)}},
            "post": {SENDER: {"balance": hex(900)}},
        }
        b = {
            "pre": {SENDER: {"balance": hex(1000)}},
            "post": {SENDER: {"balance": hex(1000)}},
        }
        rep = reproduction_check(
            build_capture(
                prestate_diff=a, sender=SENDER, gas_used=0, effective_gas_price=0
            ),
            build_capture(
                prestate_diff=b, sender=SENDER, gas_used=0, effective_gas_price=0
            ),
        )
        assert rep.state_equivalent is True
        bal = [d for d in rep.divergences if d.category == "balance"]
        assert len(bal) == 1 and bal[0].severity == VALUE_DRIFT

    def test_preservation_test_nonsender_balance_small_diff_is_critical(self):
        # In the preservation test even a tiny non-sender balance change is critical.
        a = {
            "pre": {TOKEN: {"balance": hex(1000)}},
            "post": {TOKEN: {"balance": hex(1100)}},
        }
        b = {
            "pre": {TOKEN: {"balance": hex(1000)}},
            "post": {TOKEN: {"balance": hex(1101)}},
        }
        rep = compare(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(
            d.category == "balance" and d.severity == CRITICAL for d in rep.divergences
        )

    def test_relative_error_helpers(self):
        assert relative_error(9, 10) == 0.1
        assert within_relative_tolerance(9, 10, 0.10) is True
        assert within_relative_tolerance(9, 99, 0.10) is False

    def test_reproduction_check_tolerates_value_drift(self):
        # Storage/log/balance differences are value_drift -> reproduces chain.
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(10)}}},  # accrual drift
        }
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is True
        assert any(d.severity == VALUE_DRIFT for d in rep.divergences)

    def test_reproduction_check_fails_on_status_mismatch(self):
        rep = reproduction_check(
            build_capture(prestate_diff={}, status=1, sender=SENDER),
            build_capture(prestate_diff={}, status=0, sender=SENDER),
        )
        assert rep.state_equivalent is False
        assert any(d.category == "status" for d in rep.critical)

    def test_reproduction_check_fails_on_account_scope(self):
        # An extra contract touched in only one execution -> structural divergence.
        other = "0x4444444444444444444444444444444444444444"
        a = {
            "pre": {other: {"storage": {SLOT: _word(0)}}},
            "post": {other: {"storage": {SLOT: _word(1)}}},
        }
        b = {"pre": {}, "post": {}}
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        assert any(d.category == "account_scope" for d in rep.critical)

    def test_reproduction_check_fails_on_code_change(self):
        a = {"pre": {TOKEN: {"code": "0xabcd"}}, "post": {TOKEN: {"code": "0xbeef"}}}
        b = {"pre": {}, "post": {}}
        rep = reproduction_check(self._cap(a), self._cap(b))
        assert rep.state_equivalent is False
        # code change shows up (account_scope and/or code), both critical/structural
        assert any(d.category in ("code", "account_scope") for d in rep.critical)

    def test_divergence_json_uses_side_labels(self):
        a = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(9)}}},
        }
        b = {
            "pre": {TOKEN: {"storage": {SLOT: _word(5)}}},
            "post": {TOKEN: {"storage": {SLOT: _word(10)}}},
        }
        repro = reproduction_check(self._cap(a), self._cap(b))
        d = repro.to_dict()["divergences"][0]
        assert "original" in d and "live" in d
        assert "a" not in d and "b" not in d

        test = compare(
            self._cap(a),
            self._cap(b),
            label_a="original_replay",
            label_b="patched_replay",
        )
        d2 = test.to_dict()["divergences"][0]
        assert "original" in d2 and "patch" in d2

"""Tests for Anvil indexed replay helpers."""

from pondereplay.anvil_replay import normalize_block_timestamp


class TestNormalizeBlockTimestamp:
    def test_seconds_unchanged(self):
        assert normalize_block_timestamp(1710653795) == 1710653795

    def test_milliseconds_converted(self):
        assert normalize_block_timestamp(1710653795000) == 1710653795

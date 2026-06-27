"""Tests for AnvilIndexedReplayer port + fork verification."""

from __future__ import annotations

import socket

import pytest

from pondereplay.anvil_replay import (
    AnvilIndexedReplayer,
    _find_free_port,
)


class TestFreePort:
    def test_picks_free_port(self):
        port = _find_free_port("127.0.0.1", 17545, 17645)
        assert 17545 <= port < 17645

    def test_skips_busy_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(("127.0.0.1", 17646))
            occupied.listen(1)
            port = _find_free_port("127.0.0.1", 17646, 17746)
        assert port != 17646
        assert 17646 < port < 17746

    def test_falls_back_when_range_full(self):
        sockets = []
        try:
            base = 17800
            for p in range(base, base + 3):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(("127.0.0.1", p))
                s.listen(1)
                sockets.append(s)
            port = _find_free_port("127.0.0.1", base, base + 3)
            assert port < base or port >= base + 3
        finally:
            for s in sockets:
                s.close()


class TestAnvilLifecycle:
    def test_auto_port_attribute_defaults(self):
        replayer = AnvilIndexedReplayer("http://example/rpc")
        assert replayer.auto_port is True
        assert replayer.port_range == 100
        assert replayer.port == 8545

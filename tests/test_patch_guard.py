"""Tests for AlkemiEarn liquidateBorrow patch guard preflight."""

from pondereplay.patch_guard import (
    analyze_patch_guard,
    parse_liquidate_borrow_target,
)

LIQUIDATE_INPUT = (
    "e61604cf"
    "00000000000000000000000084238b6459d009ccf0d648a75b717119beee2dd3"
    "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    "0000000000000000000000008125afd067094cd573255f82795339b9fe2a40ab"
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)


class TestParseLiquidateBorrow:
    def test_parses_target(self):
        tx = {
            "to": "0x4822D9172e5b76b9Db37B75f5552F9988F98a888",
            "input": bytes.fromhex(LIQUIDATE_INPUT),
        }
        target = parse_liquidate_borrow_target(tx)
        assert target.lower() == "0x84238b6459d009ccf0d648a75b717119beee2dd3"


class TestPatchGuardIntegration:
    def test_0d518366_borrower_underwater(self):
        import os

        pytest = __import__("pytest")
        rpc = os.environ.get("ETH_RPC_URL")
        if not rpc:
            pytest.skip("ETH_RPC_URL not set")

        from web3 import Web3

        w3 = Web3(Web3.HTTPProvider(rpc))
        if not w3.is_connected():
            pytest.skip("RPC not connected")

        tx = w3.eth.get_transaction(
            "0x0d51836604cfc7b147e4d5eddf0570fedb301dface9055bb7981684b03c1d84a"
        )
        info = analyze_patch_guard(
            w3, tx, fork_block=tx["blockNumber"] - 1
        )
        assert info["patch_guard_applies"] is True
        assert info["patch_guard_would_block"] is False
        assert info["patch_guard_liquidity"] < 0

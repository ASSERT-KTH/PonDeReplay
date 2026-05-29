"""
Transaction trace analysis via debug_traceTransaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from web3 import Web3


KNOWN_SELECTORS = {
    "f2b9fdb8": "supply(address,uint256)",
    "4b8a3529": "borrow(address,uint256)",
    "118e31b7": "getBorrowBalance(address,address)",
    "e61604cf": "liquidateBorrow(address,address,address,uint256)",
    "f3fef3a3": "withdraw(address,uint256)",
    "5c38449e": "flashLoan(address,address[],uint256[],bytes)",
    "f04f2707": "receiveFlashLoan(address[],uint256[],uint256[],bytes)",
}


@dataclass
class TraceCall:
    depth: int
    call_type: str
    from_address: str
    to_address: Optional[str]
    selector: str
    function_name: str
    value: Optional[str]
    gas_used: Optional[str]
    error: Optional[str]
    matches_patched_contract: bool = False


@dataclass
class TraceAnalysis:
    tx_hash: str
    patched_contract_reached: bool
    patched_contract_delegatecall: bool
    calls: List[TraceCall] = field(default_factory=list)
    touched_addresses: List[str] = field(default_factory=list)
    selectors_seen: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_summary_dict(self) -> Dict[str, Any]:
        """Compact trace result for replay/classification output (no full call tree)."""
        patched_calls = [
            {
                "depth": c.depth,
                "call_type": c.call_type,
                "function": c.function_name or c.selector,
                "to": c.to_address,
            }
            for c in self.calls
            if c.matches_patched_contract or c.function_name
        ][:8]
        return {
            "tx_hash": self.tx_hash,
            "patched_contract_reached": self.patched_contract_reached,
            "patched_contract_delegatecall": self.patched_contract_delegatecall,
            "selectors_seen": self.selectors_seen,
            "patched_calls": patched_calls,
            "errors": self.errors,
        }

    def to_dict(self, *, include_calls: bool = False) -> Dict[str, Any]:
        if not include_calls:
            return self.to_summary_dict()
        d = asdict(self)
        d["calls"] = [asdict(c) for c in self.calls]
        return d

    def touched_address_set(self) -> Set[str]:
        return {a.lower() for a in self.touched_addresses if a}


def _fetch_call_trace(w3: Web3, tx_hash: str, timeout: str = "60s") -> Dict[str, Any]:
    provider = w3.provider
    if not hasattr(provider, "make_request"):
        raise RuntimeError("RPC provider does not support make_request")
    resp = provider.make_request(
        "debug_traceTransaction",
        [tx_hash, {"tracer": "callTracer", "timeout": timeout}],
    )
    if "error" in resp:
        raise RuntimeError(resp["error"])
    return resp.get("result") or {}


def _walk_trace(
    node: Dict[str, Any],
    patched_lower: str,
    depth: int,
    calls: List[TraceCall],
    touched: Set[str],
    selectors: Set[str],
    interesting_selectors: Set[str],
) -> None:
    to_addr = node.get("to")
    from_addr = node.get("from", "")
    inp = node.get("input") or ""
    sel = inp[2:10].lower() if inp.startswith("0x") and len(inp) >= 10 else ""
    call_type = node.get("type", "CALL")

    if to_addr:
        touched.add(to_addr.lower())
    if from_addr:
        touched.add(from_addr.lower())

    matches = bool(to_addr and to_addr.lower() == patched_lower)
    fn = KNOWN_SELECTORS.get(sel, "")

    if sel in interesting_selectors or matches or call_type in ("DELEGATECALL", "CALL"):
        if sel or matches:
            calls.append(
                TraceCall(
                    depth=depth,
                    call_type=call_type,
                    from_address=from_addr,
                    to_address=to_addr,
                    selector=sel,
                    function_name=fn,
                    value=node.get("value"),
                    gas_used=node.get("gasUsed"),
                    error=node.get("error"),
                    matches_patched_contract=matches,
                )
            )
            if sel:
                selectors.add(sel)

    for child in node.get("calls") or []:
        _walk_trace(
            child,
            patched_lower,
            depth + 1,
            calls,
            touched,
            selectors,
            interesting_selectors,
        )


def analyze_transaction_trace(
    w3: Web3,
    tx_hash: str,
    patched_contract: str,
    interesting_selectors: Optional[Set[str]] = None,
) -> TraceAnalysis:
    """
    Analyze a transaction trace and whether the patched contract is reached.
    """
    patched = Web3.to_checksum_address(patched_contract)
    patched_lower = patched.lower()
    interesting = interesting_selectors or set(KNOWN_SELECTORS.keys())

    errors: List[str] = []
    try:
        trace = _fetch_call_trace(w3, tx_hash)
    except Exception as e:
        return TraceAnalysis(
            tx_hash=tx_hash,
            patched_contract_reached=False,
            patched_contract_delegatecall=False,
            errors=[str(e)],
        )

    calls: List[TraceCall] = []
    touched: Set[str] = set()
    selectors: Set[str] = set()
    _walk_trace(trace, patched_lower, 0, calls, touched, selectors, interesting)

    reached = any(c.matches_patched_contract for c in calls)
    delegatecall = any(
        c.matches_patched_contract and c.call_type == "DELEGATECALL" for c in calls
    )

    # Also consider delegatecall targets: proxy may call implementation
    impl_calls = [c for c in calls if c.to_address and c.to_address.lower() == patched_lower]

    return TraceAnalysis(
        tx_hash=tx_hash,
        patched_contract_reached=reached or len(impl_calls) > 0,
        patched_contract_delegatecall=delegatecall,
        calls=calls,
        touched_addresses=sorted(touched),
        selectors_seen=sorted(selectors),
        errors=errors,
    )

### Beauty Chain
_Date: 2018-04-22
Attack Type: ERC20, Under/Overflow
Loss: $900 M USD_
**Root Cause**
Arithmetic Overflow

**Vulnerable code snippet:**
https://etherscan.io/address/0xc5d105e63711398af9bbff092d4b6769c82f793d#code#L259
```

function batchTransfer(address[] _receivers, uint256 _value) public whenNotPaused returns (bool) {
    uint cnt = _receivers.length;
    **uint256 amount = uint256(cnt) * _value;** **//vulnerable point**
    require(cnt > 0 && cnt <= 20);
    require(_value > 0 && balances[msg.sender] >= amount);

    balances[msg.sender] = balances[msg.sender].sub(amount);
    for (uint i = 0; i < cnt; i++) {
        balances[_receivers[i]] = balances[_receivers[i]].add(_value);
        Transfer(msg.sender, _receivers[i], _value);
    }
    return true;
  }

```

Vulnerability: Arithmetic overflow could occur when multiplying `_value * cnt`, causing `amount` to wrap around to a much smaller number and bypass balance checks.

Patch: Add a require statement to the batchTransfer function of the PausableToken contract to ensure multiplication will not overflow.
`require(_value <= uint256(-1) / cnt, "Arithmetic overflow on amount");
`

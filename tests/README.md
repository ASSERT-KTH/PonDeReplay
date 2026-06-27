# PonDeReplay Test Suite

Comprehensive test suite for the PonDeReplay transaction replay tool.

## Running Tests

### Run all tests
```bash
pytest tests/
```

### Run with verbose output
```bash
pytest tests/ -v
```

### Run specific test file
```bash
pytest tests/test_replayer.py
pytest tests/test_cli.py
```

### Run specific test class or function
```bash
pytest tests/test_replayer.py::TestReplayResult
pytest tests/test_cli.py::TestBytecodeReading::test_read_hex_file
```

### Run with coverage
```bash
pytest tests/ --cov=pondereplay --cov-report=html
```

### Skip integration tests
```bash
pytest tests/ -m "not integration"
```

### Run integration tests (requires RPC access)
```bash
pytest tests/ --run-integration
```

## Test Structure

- **test_replayer.py** - Core `TransactionReplayer` behavior, replay results, and sanity checks
- **test_cli.py** - CLI option handling, bytecode reading, and command output
- **test_txlist.py** - Explicit transaction-list parsing and validation
- **test_etherscan.py** - Etherscan history fetching helpers
- **test_preflight.py** - Preflight diagnostics and escalation decisions
- **test_anvil_replay.py** / **test_anvil_lifecycle.py** - Anvil replay backend behavior
- **test_state_compare.py** - State-effect comparison, drift tolerance, and divergence severity
- **test_classifier.py** / **test_classifier_oog.py** - Patch-effect classification
- **test_execution_outcome.py** - Execution outcome fields and faithfulness semantics
- **test_trace.py** - Trace analysis helpers
- **test_patch_guard.py** - Patch guard diagnostics
- **test_revert_decode.py** - Revert reason decoding
- **test_integration.py** - Network/RPC integration tests, skipped unless `--run-integration` is passed
- **conftest.py** - Pytest options and shared fixtures

## Test Coverage

Current test coverage includes:

- `ReplayResult` creation and serialization
- `TransactionReplayer` initialization and connection handling
- Transaction replay with state overrides and same-block escalation
- Sanity checks with original bytecode
- State comparison and patch-effect classification
- Bytecode reading from hex, JSON artifact, and binary formats
- CLI commands including `replay`, `sanity-check`, `compare-patch`, `replay-history`, and `bytecode`
- Output formatting, execution outcome fields, and error handling

## Writing New Tests

### Test naming conventions
- Test files: `test_*.py`
- Test classes: `Test*`
- Test functions: `test_*`

### Example test structure
```python
import pytest
from unittest.mock import Mock, patch

class TestMyFeature:
    """Test my new feature"""
    
    def test_basic_functionality(self):
        """Test basic use case"""
        # Arrange
        # Act
        # Assert
        pass
    
    def test_error_handling(self):
        """Test error conditions"""
        with pytest.raises(ValueError):
            # Code that should raise ValueError
            pass
```

### Using fixtures
```python
def test_with_fixture(sample_bytecode):
    """Test using a fixture from conftest.py"""
    assert sample_bytecode.startswith("0x")
```

### Mocking Web3 calls
```python
@patch('pondereplay.replayer.Web3')
def test_with_mocked_web3(mock_web3):
    mock_w3_instance = Mock()
    mock_w3_instance.is_connected.return_value = True
    mock_web3.return_value = mock_w3_instance
    # Your test code
```

## Continuous Integration

Tests run automatically on:
- Push to main branch
- Pull requests

CI also runs Black in check mode:

```bash
black --check pondereplay tests
pytest tests/
```

See `.github/workflows/ci.yml` for CI configuration.

## Markers

- `@pytest.mark.integration` - Integration tests requiring network access

Filter tests by marker:
```bash
pytest -m "not integration"  # Skip integration tests
```

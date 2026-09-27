import pytest
import hashlib
from unittest.mock import patch, MagicMock

# Mocking GenLayer environment variables and decorators for local testing
import sys
mock_gl = MagicMock()
mock_gl.vm.UserError = ValueError
mock_gl.message.sender_address = "0x1234567890abcdef1234567890abcdef12345678"

# Mock decorators so the contract can be imported locally without the GenVM
def mock_decorator(func):
    return func

mock_gl.public.write = mock_decorator
mock_gl.public.view = mock_decorator
sys.modules['genlayer'] = mock_gl
import builtins
builtins.allow_storage = mock_decorator
builtins.TreeMap = dict
builtins.u256 = int
builtins.u8 = int
builtins.Address = str

# Import the contract after mocking
from ReleaseIntegrityOracle import ReleaseIntegrityOracle, SEALED, VERSION

@pytest.fixture
def contract():
    """Fixture to initialize a fresh contract before each test."""
    oracle = ReleaseIntegrityOracle()
    oracle.assessments = {}
    oracle.attempts = {}
    oracle.replay = {}
    return oracle

def test_initial_state(contract):
    """Test if the contract initializes correctly."""
    config = contract.get_config()
    assert config["version"] == VERSION
    assert config["assessment_count"] == 0
    assert contract.count == 0

def test_open_assessment_success(contract):
    """Test successful creation of a new release assessment."""
    base_commit = "a" * 40
    target_commit = "b" * 40
    attest_commit = "c" * 40
    attest_sha256 = "d" * 64
    
    assessment_id = contract.open_assessment(
        owner="genlayer",
        repository="core",
        base_commit=base_commit,
        target_commit=target_commit,
        attestation_commit=attest_commit,
        attestation_path=".covenant/attest.json",
        attestation_sha256=attest_sha256,
        release_tag="v1.0.0"
    )
    
    assert assessment_id == 0
    assert contract.count == 1
    
    record = contract.get_assessment(assessment_id)
    assert record.owner == "genlayer"
    assert record.state == SEALED
    assert record.attempt_count == 0

def test_open_assessment_invalid_commit(contract):
    """Test validation failure for invalid commit hash length/format."""
    with pytest.raises(ValueError, match="INVALID_BASE_COMMIT"):
        contract.open_assessment(
            owner="genlayer",
            repository="core",
            base_commit="invalid_short_hash",
            target_commit="b" * 40,
            attestation_commit="c" * 40,
            attestation_path="attest.json",
            attestation_sha256="d" * 64,
            release_tag="v1.0.0"
        )

def test_open_assessment_path_traversal(contract):
    """Test validation failure for dangerous file paths (path traversal)."""
    with pytest.raises(ValueError, match="INVALID_ATTESTATION_PATH"):
        contract.open_assessment(
            owner="genlayer",
            repository="core",
            base_commit="a" * 40,
            target_commit="b" * 40,
            attestation_commit="c" * 40,
            attestation_path="../hidden/attest.json",
            attestation_sha256="d" * 64,
            release_tag="v1.0.0"
        )

def test_open_assessment_replay_protection(contract):
    """Test that the contract prevents duplicate assessments (Replay Protection)."""
    params = {
        "owner": "genlayer",
        "repository": "core",
        "base_commit": "a" * 40,
        "target_commit": "b" * 40,
        "attestation_commit": "c" * 40,
        "attestation_path": "attest.json",
        "attestation_sha256": "d" * 64,
        "release_tag": "v1.0.0"
    }
    
    # First submission should succeed
    contract.open_assessment(**params)
    
    # Second identical submission should fail
    with pytest.raises(ValueError, match="ASSESSMENT_REPLAY"):
        contract.open_assessment(**params)

def test_get_assessment_not_found(contract):
    """Test reading an assessment that does not exist."""
    with pytest.raises(ValueError, match="ASSESSMENT_NOT_FOUND"):
        contract.get_assessment(999)
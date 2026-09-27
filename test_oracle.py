import pytest
import hashlib
from unittest.mock import patch, MagicMock
import sys
import builtins

# Create a real empty class so Python can inherit from it normally
class MockContract:
    pass

# Configure mocks for GenLayer
mock_gl = MagicMock()
mock_gl.Contract = MockContract  # Specify that the base class is a real object
mock_gl.vm.UserError = ValueError
mock_gl.message.sender_address = "0x1234567890abcdef1234567890abcdef12345678"

def mock_decorator(func):
    return func

mock_gl.public.write = mock_decorator
mock_gl.public.view = mock_decorator
sys.modules['genlayer'] = mock_gl

builtins.allow_storage = mock_decorator
builtins.TreeMap = dict
builtins.u256 = int
builtins.u8 = int
builtins.Address = str
builtins.gl = mock_gl

# Import the contract ONLY AFTER all mocks have been configured
from ReleaseIntegrityOracle import ReleaseIntegrityOracle, SEALED, VERSION, ACCURATE

@pytest.fixture
def contract():
    """Fixture to initialize a fresh contract before each test."""
    oracle = ReleaseIntegrityOracle()
    oracle.assessments = {}
    oracle.attempts = {}
    oracle.replay = {}
    return oracle

@pytest.fixture
def valid_consensus_result():
    """Fixture providing a mock result for run_nondet_unsafe to simulate successful consensus."""
    return {
        "source_status": "VERIFIED",
        "compare_binding": "MATCH",
        "attestation_binding": "MATCH",
        "file_coverage": "MATCH",
        "release_binding": "MATCH",
        "authorization_change": "NO",
        "asset_flow_change": "NO",
        "dependency_change": "NO",
        "configuration_change": "NO",
        "disclosure_alignment": "MATCH",
        "evidence_digest": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    }

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

def test_evaluate_assessment_success(contract, valid_consensus_result):
    """Test the new _evaluate consensus logic successfully matching fields."""
    assessment_id = contract.open_assessment(
        owner="genlayer",
        repository="core",
        base_commit="a" * 40,
        target_commit="b" * 40,
        attestation_commit="c" * 40,
        attestation_path=".covenant/attest.json",
        attestation_sha256="d" * 64,
        release_tag="v1.0.0"
    )
    
    # Mock the run_nondet_unsafe method to return our valid simulated consensus
    with patch.object(builtins.gl.vm, 'run_nondet_unsafe', return_value=valid_consensus_result):
        contract.evaluate_assessment(assessment_id)
        
    record = contract.get_assessment(assessment_id)
    assert record.state == ACCURATE
    assert record.attempt_count == 1
    assert record.evidence_digest == valid_consensus_result["evidence_digest"]

def test_evaluate_assessment_consensus_failure(contract):
    """Test evaluation failure when GenVM consensus validation fails."""
    assessment_id = contract.open_assessment(
        owner="genlayer",
        repository="core",
        base_commit="a" * 40,
        target_commit="b" * 40,
        attestation_commit="c" * 40,
        attestation_path=".covenant/attest.json",
        attestation_sha256="d" * 64,
        release_tag="v1.0.0"
    )
    
    # Provide an invalid dict that fails the valid() check inside run_nondet_unsafe simulation
    invalid_result = {"source_status": "INVALID_FORMAT"} 
    
    with patch.object(builtins.gl.vm, 'run_nondet_unsafe', return_value=invalid_result):
        with pytest.raises(ValueError, match="CONSENSUS_VALIDATION_FAILED"):
            contract.evaluate_assessment(assessment_id)
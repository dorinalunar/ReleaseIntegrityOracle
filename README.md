# ReleaseIntegrityOracle
[![GenLayer](https://img.shields.io/badge/Platform-GenLayer-blue.svg)](https://genlayer.com)
[![Language](https://img.shields.io/badge/Language-Python%203.11-yellow.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An Intelligent Contract deployed on GenLayer that validates whether a GitHub release truthfully discloses real source changes. By combining deterministic git diff retrieval with non-deterministic LLM consensus (GenVM), `ReleaseIntegrityOracle` detects hidden logic alterations, undeclared dependency shifts, configuration tampering, and omitted critical disclosures.
---
## Architecture Overview
Traditional code releases rely on blind trust: users must assume that release notes accurately reflect actual code diffs. `ReleaseIntegrityOracle` eliminates this gap by processing git diffs and attestations on-chain:
1. **Commit & Attestation Pinning**: Evaluates a specific commit range (`base_commit` to `target_commit`) alongside a canonical SHA-256 attestation file.
2. **Deterministic Pre-flight Checks**: Fetches raw data from the GitHub API and GitHub Raw endpoints, verifying cryptographic digests, commit boundaries, and changed file lists.
3. **Optimistic LLM Semantic Classification**: Leverages GenVM non-deterministic prompts to audit code patches against claimed changes (authorization, asset flows, dependencies, configuration).
4. **Resilient Consensus Layer**: Validators independently verify data payload digests (`evidence_digest`) to guard against API drift while confirming semantic integrity without brittle string mismatches.
---
## Contract State Flow
```
[ SEALED ] 
    │
    ▼ (evaluate_assessment)
[ Non-Deterministic Verification ]
    │
    ├─── MATCH ─────────────► [ ACCURATE ]
    ├─── MISMATCH (Omission)► [ OMISSION_DETECTED ]
    ├─── MISMATCH (Conflict)► [ CONTRADICTION ]
    └─── API / LLM Issue ───► [ REVIEW_REQUIRED ] ──► (retry_assessment)
```
### Audit Status Codes

| State | Description |
| :--- | :--- |
| `ACCURATE` | Release notes and claimed attestation scope strictly match the patch changes. |
| `OMISSION_DETECTED` | Critical changes (authorization, asset flow, or config) are present in diffs but missing from notes. |
| `CONTRADICTION` | Commit binding, tag binding, or claimed scope directly conflicts with the git history. |
| `REVIEW_REQUIRED` | Network failure (rate limits), source unavailability, or ambiguous model inference. |

---
## Core Methods
### Write Methods
#### `open_assessment`
Initializes a new audit for a repository release.
```python
def open_assessment(
    owner: str,
    repository: str,
    base_commit: str,
    target_commit: str,
    attestation_commit: str,
    attestation_path: str,
    attestation_sha256: str,
    release_tag: str
) -> u256
```
- **Replay Protection**: Guarantees uniqueness per release scope via SHA-256 state hashing.
- **Constraints**: 40-character hex commit hashes, sanitized path strings, and path traversal prevention.
#### `evaluate_assessment`
Triggers the multi-node GenVM consensus loop for a `SEALED` audit.
```python
def evaluate_assessment(assessment_id: u256) -> None
```
#### `retry_assessment`
Reruns an assessment marked as `REVIEW_REQUIRED` (e.g., following transient GitHub rate limits), up to 5 attempts.
```python
def retry_assessment(assessment_id: u256) -> None
```
### View Methods
- **`get_assessment(assessment_id: u256) -> Assessment`**: Retrieves current status, attempt counts, and resolved evidence digest.
- **`get_attempt(assessment_id: u256, attempt: u8) -> Attempt`**: Returns granular breakdown of a specific consensus execution.
- **`get_config() -> dict`**: Returns protocol configuration limits and global assessment count.
---
## Attestation File Schema
Projects integrating with `ReleaseIntegrityOracle` include an attestation file (e.g., `.covenant/attestation.json`) pinned at `attestation_commit`:
```json
{
  "schema": "release-integrity/v1",
  "repository": "owner/repository",
  "base_commit": "40_char_commit_hash",
  "target_commit": "40_char_commit_hash",
  "release_tag": "v1.0.0",
  "claimed_scope": "GENERAL_RELEASE",
  "changed_files": [
    "src/contract.py",
    "config.json"
  ]
}
```
The corresponding GitHub Release body must contain the attestation digest line:
```text
disclosure_attestation_sha256: <64_character_hex_sha256>
```
---
## Deployment & Verification
### Prerequisites
- Python 3.11+
- `genlayer-py` runtime
- GenLayer Studio or CLI client
### Deployment via GenLayer CLI
```bash
genlayer deploy \
  --contract contracts/ReleaseIntegrityOracle.py \
  --network studio
```
---
## Security Model
- **Bounded Execution**: Strict payload limits (512 KB compare, 256 KB patches, 50 maximum files) protect nodes against Out-Of-Memory (OOM) exploits.
- **Prompt Injection Defense**: Release notes and git diffs are strictly parsed as passive data inputs delimited by demarcation tags to prevent prompt injection.
- **Path Sanitization**: Comprehensive validation prevents directory traversal vectors (`..` and leading slash checks).
---
## License
This project is licensed under the MIT License.

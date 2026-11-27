
# AEGIS-X
## Unified AI Cybersecurity Intelligence Platform

AEGIS-X is an independent cybersecurity research prototype focused on cross-domain evidence verification, digital identity, AI agent security, evidence provenance, and incident reconstruction.

The project explores how security evidence can be verified across identity, authorization, execution, and observed effects.

---

## Research Direction

**Identity-to-Effect Security Intelligence (ID2E)**

### Proposed Research Title

AEGIS-X: A Cross-Domain Evidence Verification Framework for Identity-to-Agent-to-Effect Security Assurance.

### ID2E-CHECK

The central verification model follows:

Identity -> Principal -> Agent -> Action -> Authorization -> Execution -> Observed Effect

The objective is to identify inconsistencies, missing evidence, unauthorized actions, and evidence tampering across this chain.

---

## Core Research Modules

### 1. SENTINEL-X
Agentic AI security monitoring.

Planned research areas:
- Agent identity and authentication
- Delegated authorization
- Agent tool-call monitoring
- Policy validation
- Agent action verification

### 2. DEEPTRUST
Deepfake and digital identity security.

Planned research areas:
- Synthetic media evidence
- Digital identity verification
- Media provenance
- Evidence authenticity
- Uncertainty assessment

### 3. ZERO-TRACE
Autonomous threat hunting and incident reconstruction.

Planned research areas:
- Endpoint event monitoring
- Security evidence correlation
- Incident timeline reconstruction
- Threat detection
- Evidence integrity verification

---

## Implemented Features

### Evidence Management
- FastAPI backend
- SQLite evidence storage
- Structured evidence records
- Evidence retrieval and listing

### Evidence Integrity
- SHA-256 evidence hashing
- Stored evidence integrity verification
- Tampered evidence detection
- Hash-linked evidence chain verification
- Missing and reordered evidence detection

### Cryptographic Signing
- Ed25519 evidence signing utilities
- Ed25519 provenance signing
- Persistent local signing key management
- Public-key verification

### Evidence Provenance
- Evidence source registration
- Source trust-level management
- Source revocation
- Provenance metadata registration
- Automatic provenance signing through the API
- Provenance signature verification
- Detection of modified provenance metadata
- Detection of replaced public keys
- Handling of legacy unsigned provenance records

### Incident Reconstruction
- Incident evidence collection
- Timeline reconstruction
- Authorization and execution contradiction detection
- Unknown authorization detection
- Evidence integrity failure detection
- Missing integrity verification detection

---

## Provenance Verification API

The provenance API supports:

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/sources/` | Register an evidence source |
| GET | `/sources/` | List evidence sources |
| GET | `/sources/{source_id}` | Retrieve source details |
| PATCH | `/sources/{source_id}/trust` | Update source trust |
| POST | `/sources/{source_id}/revoke` | Revoke a source |
| POST | `/sources/{source_id}/provenance` | Register and sign provenance |
| GET | `/sources/{source_id}/provenance` | Retrieve source provenance |
| GET | `/sources/{source_id}/provenance/{provenance_id}/verify` | Verify provenance signature |

The API uses a locally managed Ed25519 key pair. Provenance verification checks the signature against the locally trusted public key.

**Security distinction:** A valid signature proves that the corresponding private key signed the provenance metadata. It does not independently prove that the underlying event or collector statement is truthful.

---

## Technology Stack

- Python 3.10
- FastAPI
- SQLite
- SQLAlchemy
- Pydantic
- Cryptography
- Ed25519
- SHA-256
- Pytest
- HTML
- CSS
- JavaScript

---

## Project Structure

```text
AEGIS-X/
+-- backend/
¦   +-- app/
¦       +-- api/
¦       ¦   +-- evidence.py
¦       ¦   +-- incidents.py
¦       ¦   +-- sources.py
¦       +-- core/
¦       ¦   +-- database.py
¦       ¦   +-- integrity.py
¦       ¦   +-- key_manager.py
¦       ¦   +-- provenance_signing.py
¦       ¦   +-- signing.py
¦       +-- models/
¦       +-- services/
+-- datasets/
+-- docs/
+-- experiments/
+-- frontend/
+-- secrets/
+-- tests/
+-- requirements.txt
+-- README.md
+-- .gitignore
```

The `secrets/` directory contains local signing keys and must remain excluded from version control.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/Stuffjj/AEGIS-X.git
cd AEGIS-X
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Start the backend:

```bash
python -m uvicorn backend.app.main:app --port 8001 --reload
```

API documentation:

http://127.0.0.1:8001/docs

---

## Testing

Run the complete test suite:

```bash
python -m pytest -v
```

### Latest Verified Test Results

**54 tests passed**

Coverage includes:
- Evidence database storage
- Evidence record validation
- SHA-256 integrity verification
- Evidence chain verification
- Evidence signing
- Provenance signing
- Provenance API integration
- Source registration and trust management
- Incident reconstruction
- Stored incident integrity verification

Latest recorded test execution: 54 passed in 2.63 seconds.

---

## Security Considerations

- Private signing keys must never be uploaded to GitHub.
- Local signing keys are stored in the ignored `secrets/` directory.
- Public keys are used for signature verification.
- A cryptographic signature does not guarantee the truthfulness of the original event.
- Experiments must be performed only in authorized environments.
- Synthetic or properly licensed datasets should be used for deepfake research.

---

## Research Limitations and Future Work

AEGIS-X is a research prototype, not a production-certified security platform.

Planned research includes:
- Source-specific collector signing identities
- Stronger key rotation and revocation mechanisms
- Cross-domain evidence correlation
- Agent identity and delegated authorization verification
- Deepfake provenance experiments
- ID2E benchmark development
- Controlled security experiments
- Unified security monitoring dashboard

---

## Project Status

**Active Research and Development**

Current milestone:
- Evidence integrity and signing
- Evidence chain verification
- Incident reconstruction
- Source trust management
- API-integrated cryptographic provenance signing and verification

---

## Repository

GitHub: https://github.com/Stuffjj/AEGIS-X

Project: AEGIS-X
Research Direction: Identity-to-Effect Security Intelligence

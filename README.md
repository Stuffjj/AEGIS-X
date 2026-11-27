# AEGIS-X
## Unified AI Cybersecurity Intelligence Platform

AEGIS-X is an independent cybersecurity research prototype focused on evidence verification, digital identity, agent security, and incident reconstruction.

## Research Direction

Identity-to-Effect Security Intelligence (ID2E)

Research title:

AEGIS-X: A Cross-Domain Evidence Verification Framework for Identity-to-Agent-to-Effect Security Assurance.

## Core Modules

### SENTINEL-X
Agentic AI security monitoring.

### DEEPTRUST
Deepfake and digital identity security.

### ZERO-TRACE
Autonomous threat hunting.

## ID2E-CHECK

Identity -> Principal -> Agent -> Action -> Authorization -> Execution -> Observed Effect

The framework investigates evidence integrity, provenance, authorization consistency, and incident reconstruction.

## Implemented Features

- FastAPI backend
- SQLite evidence storage
- SHA-256 integrity verification
- Ed25519 evidence signing
- Hash-linked evidence chains
- Incident reconstruction
- Authorization and execution contradiction detection
- Evidence source registration and trust management
- Provenance registration
- Ed25519 provenance signing utility
- Persistent local key manager
- Automated pytest tests

Note: Provenance signing and key management currently work independently. Automatic signing through the provenance API is still under development.

## Technology Stack

- Python 3.10
- FastAPI
- SQLite
- SQLAlchemy
- Pydantic
- Cryptography
- Pytest
- HTML, CSS, JavaScript

## Installation

Create a virtual environment:

    python -m venv .venv
    .\.venv\Scripts\Activate.ps1

Install dependencies:

    python -m pip install -r requirements.txt

Start the backend:

    python -m uvicorn backend.app.main:app --port 8001 --reload

API documentation:

http://127.0.0.1:8001/docs

## Testing

Run:

    python -m pytest -v

Latest recorded result: 48 tests passed.

## Security Notes

- Never upload private signing keys to GitHub.
- A valid signature proves that the corresponding private key signed the data. It does not prove the underlying event is truthful.
- Conduct experiments only in authorized environments.
- Use synthetic or properly licensed datasets for deepfake research.

## Project Status

Research prototype in active development.

Future work includes API-integrated provenance verification, stronger key lifecycle management, cross-domain evidence correlation, experimental benchmarking, and a unified dashboard.

## Author

Independent Cybersecurity Research Project

Project: AEGIS-X
Research Direction: Identity-to-Effect Security Intelligence

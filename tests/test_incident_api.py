
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_normal_incident_reconstruction():
    payload = {
        "records": [
            {
                "identity": "test-user-001",
                "principal_type": "human",
                "action": "Login attempt",
                "resource": "Test application",
                "authorization_status": "authorized",
                "execution_status": "success",
                "observed_effect": "Login successful",
                "source": "synthetic-lab",
                "timestamp": "2026-11-27T14:00:00Z"
            }
        ]
    }

    response = client.post("/incidents/reconstruct", json=payload)

    assert response.status_code == 200
    result = response.json()
    assert result["total_events"] == 1
    assert result["findings"] == []
    assert result["status"] == "NO_INCONSISTENCIES_DETECTED"


def test_authorization_execution_contradiction():
    payload = {
        "records": [
            {
                "identity": "test-user-002",
                "principal_type": "human",
                "action": "Restricted file access",
                "resource": "Confidential test file",
                "authorization_status": "denied",
                "execution_status": "success",
                "observed_effect": "File access recorded",
                "source": "synthetic-lab",
                "timestamp": "2026-11-27T14:00:00Z"
            }
        ]
    }

    response = client.post("/incidents/reconstruct", json=payload)

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "REQUIRES_INVESTIGATION"
    assert len(result["findings"]) == 1
    assert result["findings"][0]["severity"] == "HIGH"
    assert (
        result["findings"][0]["finding"]
        == "AUTHORIZATION_EXECUTION_CONTRADICTION"
    )


def test_empty_incident():
    response = client.post(
        "/incidents/reconstruct",
        json={"records": []}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "NO_EVIDENCE"


def test_invalid_timestamp():
    payload = {
        "records": [
            {
                "identity": "test-user-003",
                "principal_type": "human",
                "action": "Login attempt",
                "resource": "Test application",
                "authorization_status": "authorized",
                "execution_status": "success",
                "observed_effect": "Login successful",
                "source": "synthetic-lab",
                "timestamp": "invalid-timestamp"
            }
        ]
    }

    response = client.post("/incidents/reconstruct", json=payload)

    assert response.status_code == 422

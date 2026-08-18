from fastapi.testclient import TestClient
from app import app

client = TestClient(app)


def safe_payload():
    return {
        "target": "preview",
        "event": "pull_request",
        "ref": "refs/heads/feature",
        "workflow": {
            "trigger": "pull_request",
            "permissions": {
                "contents": "read",
                "packages": "write",
                "id-token": "none"
            },
            "testsPassed": True,
            "matrixComplete": True,
            "failFast": False,
            "actions": [
                {
                    "owner": "actions",
                    "name": "checkout",
                    "ref": "v4"
                },
                {
                    "owner": "some-user",
                    "name": "some-action",
                    "ref": "0123456789abcdef0123456789abcdef01234567"
                }
            ]
        },
        "image": {
            "multiStage": True,
            "runsAsRoot": False,
            "secretMode": "none",
            "criticalVulnerabilities": 0,
            "digestPinned": True
        }
    }


def test_safe_request_is_promoted():
    response = client.post("/release-gate", json=safe_payload())

    assert response.status_code == 200
    assert response.json() == {
        "decision": "promote",
        "violations": []
    }


def test_bad_permissions():
    payload = safe_payload()
    payload["workflow"]["permissions"]["contents"] = "write"

    response = client.post("/release-gate", json=payload)

    assert response.json()["decision"] == "block"
    assert "EXCESS_PERMISSION" in response.json()["violations"]


def test_pr_target_is_rejected():
    payload = safe_payload()
    payload["workflow"]["trigger"] = "pull_request_target"

    response = client.post("/release-gate", json=payload)

    assert response.json()["decision"] == "block"
    assert "UNSAFE_PR_TRIGGER" in response.json()["violations"]


def test_third_party_action_must_use_sha():
    payload = safe_payload()
    payload["workflow"]["actions"].append({
        "owner": "third-party",
        "name": "deploy",
        "ref": "v1"
    })

    response = client.post("/release-gate", json=payload)

    assert "MUTABLE_ACTION" in response.json()["violations"]


def test_production_requires_main_and_approval():
    payload = safe_payload()

    payload["target"] = "production"
    payload["event"] = "push"
    payload["ref"] = "refs/heads/feature"
    payload["workflow"]["environmentApproval"] = False

    response = client.post("/release-gate", json=payload)

    violations = response.json()["violations"]

    assert response.json()["decision"] == "block"
    assert "INVALID_PRODUCTION_REF" in violations
    assert "APPROVAL_REQUIRED" in violations

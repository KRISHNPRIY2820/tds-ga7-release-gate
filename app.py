from fastapi import FastAPI
from typing import Any

app = FastAPI()


@app.post("/release-gate")
def release_gate(payload: dict[str, Any]):
    violations = []

    workflow = payload.get("workflow", {})
    image = payload.get("image", {})

    # 1. Permissions must be EXACTLY:
    # contents: read
    # packages: write
    # id-token: none
    expected_permissions = {
        "contents": "read",
        "packages": "write",
        "id-token": "none",
    }

    if workflow.get("permissions", {}) != expected_permissions:
        violations.append("EXCESS_PERMISSION")

    # 2. Pull requests must use pull_request
    if (
        payload.get("event") == "pull_request"
        and workflow.get("trigger") != "pull_request"
    ):
        violations.append("UNSAFE_PR_TRIGGER")

    # 3. Tests + matrix + failFast
    if (
        workflow.get("testsPassed") is not True
        or workflow.get("matrixComplete") is not True
        or workflow.get("failFast") is not False
    ):
        violations.append("TESTS_INCOMPLETE")

    # 4. Action pinning
    #
    # actions/* may use version tags.
    # Third-party actions must use a 40-char lowercase SHA.
    for action in workflow.get("actions", []):
        owner = action.get("owner", "")
        ref = action.get("ref", "")

        if owner == "actions":
            continue

        if (
            len(ref) != 40
            or any(c not in "0123456789abcdef" for c in ref)
        ):
            violations.append("MUTABLE_ACTION")
            break

    # 5. Image must be multi-stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")

    # 6. Image must run as non-root
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")

    # 7. Secret must not be copied into image layers.
    # Allowed: none or buildkit
    if image.get("secretMode") not in ("none", "buildkit"):
        violations.append("SECRET_IN_LAYER")

    # 8. No critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")

    # 9. Image must be digest pinned
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")

    # 10. Production requirements
    if payload.get("target") == "production":
        if not (
            payload.get("event") == "push"
            and payload.get("ref") == "refs/heads/main"
        ):
            violations.append("INVALID_PRODUCTION_REF")

        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")

    return {
        "decision": "promote" if not violations else "block",
        "violations": violations,
    }

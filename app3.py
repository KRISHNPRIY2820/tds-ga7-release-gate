from fastapi import FastAPI, Body
from typing import Any

app = FastAPI()

PRODUCTION_WORKSPACE = "prod-mod0nx"

REQUIRED_LABELS = {
    "owner": "student-l6x2k",
    "environment": "production",
    "cost_center": "cc-ado4",
}

ALLOWED_BACKENDS = {
    "gcs",
    "s3",
    "azurerm",
    "remote",
}

ALLOWED_PROVIDER_VERSIONS = {
    "6.2.1",
    "= 6.2.1",
    "~> 6.0",
}

DESTRUCTIVE_RESOURCE_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def reject(reason: str):
    return {
        "decision": "reject",
        "reason": reason,
    }


def approve():
    return {
        "decision": "approve",
        "reason": "APPROVE",
    }


def is_string(value: Any) -> bool:
    return isinstance(value, str)


def is_bool(value: Any) -> bool:
    return isinstance(value, bool)


@app.post("/terraform/plan")
def terraform_plan(payload: Any = Body(...)):

    # =========================================================
    # 1. REQUEST / NESTED OBJECT TYPES
    # =========================================================

    if not isinstance(payload, dict):
        return reject("INVALID_PLAN")

    # Required top-level fields
    required_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if not required_top.issubset(payload.keys()):
        return reject("INVALID_PLAN")

    # Top-level value types
    if not is_string(payload["environment"]):
        return reject("INVALID_PLAN")

    if not isinstance(payload["state"], dict):
        return reject("INVALID_PLAN")

    if not is_string(payload["providerVersion"]):
        return reject("INVALID_PLAN")

    if not is_bool(payload["destroyApproved"]):
        return reject("INVALID_PLAN")

    if not isinstance(payload["resource"], dict):
        return reject("INVALID_PLAN")

    # ---------------------------------------------------------
    # State object
    # ---------------------------------------------------------

    state = payload["state"]

    if "backend" not in state or "locked" not in state:
        return reject("INVALID_PLAN")

    if not is_string(state["backend"]):
        return reject("INVALID_PLAN")

    if not is_bool(state["locked"]):
        return reject("INVALID_PLAN")

    # ---------------------------------------------------------
    # Resource object
    # ---------------------------------------------------------

    resource = payload["resource"]

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if not required_resource.issubset(resource.keys()):
        return reject("INVALID_PLAN")

    if not is_string(resource["address"]):
        return reject("INVALID_PLAN")

    if not is_string(resource["type"]):
        return reject("INVALID_PLAN")

    if not is_string(resource["action"]):
        return reject("INVALID_PLAN")

    if resource["action"] not in {"create", "update", "delete"}:
        return reject("INVALID_PLAN")

    if not isinstance(resource["labels"], dict):
        return reject("INVALID_PLAN")

    if not is_bool(resource["forceDestroy"]):
        return reject("INVALID_PLAN")

    # secret may be null or string
    secret = resource["secret"]

    if secret is not None and not is_string(secret):
        return reject("INVALID_PLAN")

    # Every label value must be a string
    for key, value in resource["labels"].items():
        if not isinstance(key, str) or not isinstance(value, str):
            return reject("INVALID_PLAN")

    # =========================================================
    # 2. ENVIRONMENT
    # =========================================================

    if payload["environment"] != PRODUCTION_WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # =========================================================
    # 3. STATE SAFETY
    # =========================================================

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # =========================================================
    # 4. PROVIDER VERSION
    # =========================================================

    provider_version = payload["providerVersion"]

    if provider_version not in ALLOWED_PROVIDER_VERSIONS:
        return reject("UNPINNED_PROVIDER")

    # =========================================================
    # 5. REQUIRED LABELS
    # =========================================================

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if key not in labels:
            return reject("MISSING_LABELS")

        if labels[key] != expected_value:
            return reject("MISSING_LABELS")

    # =========================================================
    # 6. SECRET SAFETY
    # =========================================================

    if secret is not None:
        if not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

        # secret:// itself is not a valid non-empty reference
        if len(secret) <= len("secret://"):
            return reject("PLAINTEXT_SECRET")

    # =========================================================
    # 7. DELETE APPROVAL
    # =========================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in DESTRUCTIVE_RESOURCE_TYPES
    ):
        if payload["destroyApproved"] is not True:
            return reject("DELETE_NOT_APPROVED")

    # =========================================================
    # 8. PRODUCTION STORAGE BUCKET FORCE DESTROY
    # =========================================================

    if (
        resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # =========================================================
    # EVERYTHING PASSED
    # =========================================================

    return approve()
from fastapi import FastAPI
from typing import Any
import re

app = FastAPI()

ASSIGNED_TENANT = "tenant-vfkv8tw"
ALLOWED_EMAIL_DOMAIN = "notify-uu7kwcx.example"

ALLOWED_TOOLS = {
    "search",
    "lookup_record",
    "send_email",
    "render_html",
}


def result(decision: str, reason: str):
    return {
        "decision": decision,
        "reason": reason,
    }


def is_exact_dict(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value.keys()) == keys


def is_safe_html(html: str) -> bool:
    """
    Block:
    - <script> elements
    - <iframe> elements
    - inline event handlers such as onclick=, onload=, onerror=
    - javascript: URLs
    """

    # Block script tags
    if re.search(r"<\s*/?\s*script\b", html, re.IGNORECASE):
        return False

    # Block iframe tags
    if re.search(r"<\s*/?\s*iframe\b", html, re.IGNORECASE):
        return False

    # Block inline event handlers:
    # onclick=, onload=, onerror=, onmouseover=, etc.
    if re.search(r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=", html, re.IGNORECASE):
        return False

    # Block javascript: URLs
    if re.search(r"javascript\s*:", html, re.IGNORECASE):
        return False

    return True


@app.post("/action-firewall")
def action_firewall(payload: Any):

    # ---------------------------------------------------------
    # 1. TOP-LEVEL SCHEMA
    # ---------------------------------------------------------

    if not isinstance(payload, dict):
        return result("block", "INVALID_SCHEMA")

    allowed_top_level = {
        "provenance",
        "humanApproved",
        "untrustedContent",
        "action",
    }

    # untrustedContent is optional
    if not set(payload.keys()).issubset(allowed_top_level):
        return result("block", "INVALID_SCHEMA")

    # Required top-level fields
    required = {
        "provenance",
        "humanApproved",
        "action",
    }

    if not required.issubset(payload.keys()):
        return result("block", "INVALID_SCHEMA")

    # provenance
    if payload["provenance"] not in {"trusted", "untrusted"}:
        return result("block", "INVALID_SCHEMA")

    # humanApproved
    if not isinstance(payload["humanApproved"], bool):
        return result("block", "INVALID_SCHEMA")

    # untrustedContent, if supplied, must be text
    if "untrustedContent" in payload:
        if not isinstance(payload["untrustedContent"], str):
            return result("block", "INVALID_SCHEMA")

    # action must be an object
    action = payload["action"]

    if not isinstance(action, dict):
        return result("block", "INVALID_SCHEMA")

    if set(action.keys()) != {"tool", "args"}:
        return result("block", "INVALID_SCHEMA")

    if not isinstance(action["tool"], str):
        return result("block", "INVALID_SCHEMA")

    if not isinstance(action["args"], dict):
        return result("block", "INVALID_SCHEMA")

    tool = action["tool"]
    args = action["args"]

    # ---------------------------------------------------------
    # 2. TOOL ALLOWLIST
    # ---------------------------------------------------------

    if tool not in ALLOWED_TOOLS:
        return result("block", "TOOL_NOT_ALLOWED")

    # ---------------------------------------------------------
    # 3. TOOL ARGUMENT SCHEMA
    # ---------------------------------------------------------

    if tool == "search":

        if not is_exact_dict(args, {"query"}):
            return result("block", "INVALID_SCHEMA")

        query = args["query"]

        if not isinstance(query, str):
            return result("block", "INVALID_SCHEMA")

        if not (1 <= len(query) <= 200):
            return result("block", "INVALID_SCHEMA")

    elif tool == "lookup_record":

        if not is_exact_dict(args, {"tenantId", "recordId"}):
            return result("block", "INVALID_SCHEMA")

        tenant_id = args["tenantId"]
        record_id = args["recordId"]

        if not isinstance(tenant_id, str):
            return result("block", "INVALID_SCHEMA")

        if not isinstance(record_id, str):
            return result("block", "INVALID_SCHEMA")

        if record_id == "":
            return result("block", "INVALID_SCHEMA")

        # Tenant scope is checked after the argument schema.
        if tenant_id != ASSIGNED_TENANT:
            return result("block", "TENANT_SCOPE")

    elif tool == "send_email":

        if not is_exact_dict(args, {"to", "subject", "body"}):
            return result("block", "INVALID_SCHEMA")

        to = args["to"]
        subject = args["subject"]
        body = args["body"]

        if not isinstance(to, str):
            return result("block", "INVALID_SCHEMA")

        if not isinstance(subject, str):
            return result("block", "INVALID_SCHEMA")

        if not isinstance(body, str):
            return result("block", "INVALID_SCHEMA")

        # Exact recipient domain.
        #
        # We require an address with exactly the assigned domain
        # after the final @.
        if "@" not in to:
            return result("block", "EGRESS_DENIED")

        local_part, domain = to.rsplit("@", 1)

        if not local_part or domain != ALLOWED_EMAIL_DOMAIN:
            return result("block", "EGRESS_DENIED")

        # Email requires explicit human approval.
        if payload["humanApproved"] is not True:
            return result("block", "APPROVAL_REQUIRED")

    elif tool == "render_html":

        if not is_exact_dict(args, {"html"}):
            return result("block", "INVALID_SCHEMA")

        html = args["html"]

        if not isinstance(html, str):
            return result("block", "INVALID_SCHEMA")

        if not is_safe_html(html):
            return result("block", "UNSAFE_OUTPUT")

    # ---------------------------------------------------------
    # 4. EVERYTHING PASSED
    # ---------------------------------------------------------

    return result("allow", "ALLOW")

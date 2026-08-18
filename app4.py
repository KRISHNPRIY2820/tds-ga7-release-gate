from fastapi import FastAPI, Body
from typing import Any
from urllib.parse import unquote, urlparse
import re

app = FastAPI()

ALLOWED_HOSTS = {
    "cdn-f0e78ur.example",
    "app-3cyvrof.example",
}

CHANNELS = {
    "html",
    "markdown",
    "url",
    "sql",
    "shell",
}


def response(safe: bool, reason: str):
    return {
        "safe": safe,
        "reason": reason,
    }


# ------------------------------------------------------------
# HTML entity decoding
# Only the entities explicitly specified by the task.
# ------------------------------------------------------------

HTML_ENTITIES = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
}


def decode_html_entities_once(text: str) -> str:
    # Numeric decimal entities: &#NN;
    def decimal_entity(match):
        try:
            return chr(int(match.group(1), 10))
        except (ValueError, OverflowError):
            return match.group(0)

    text = re.sub(
        r"&#([0-9]+);",
        decimal_entity,
        text,
    )

    # Numeric hexadecimal entities: &#xNN;
    def hex_entity(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    text = re.sub(
        r"&#x([0-9a-fA-F]+);",
        hex_entity,
        text,
    )

    # Named entities explicitly allowed by the task.
    # Longest first so &amp; is handled correctly.
    for entity, replacement in HTML_ENTITIES.items():
        text = text.replace(entity, replacement)

    return text


def decode_once(text: str) -> str:
    """
    Decode exactly once, in this order:
      1. percent escapes
      2. HTML entities
      3. \\uXXXX escapes
    """

    decoded = unquote(text)

    decoded = decode_html_entities_once(decoded)

    def unicode_escape(match):
        try:
            return chr(int(match.group(1), 16))
        except (ValueError, OverflowError):
            return match.group(0)

    decoded = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        unicode_escape,
        decoded,
    )

    return decoded


# ------------------------------------------------------------
# URL extraction
# ------------------------------------------------------------

HTML_URL_RE = re.compile(
    r"""(?:src|href)\s*=\s*(["'])(.*?)\1""",
    re.IGNORECASE | re.DOTALL,
)

MARKDOWN_URL_RE = re.compile(
    r"""\]\(\s*(.*?)\s*\)""",
    re.DOTALL,
)


def extract_urls(channel: str, text: str):
    if channel == "html":
        return [match.group(2) for match in HTML_URL_RE.finditer(text)]

    if channel == "markdown":
        urls = []

        for match in MARKDOWN_URL_RE.finditer(text):
            target = match.group(1).strip()

            # Markdown can use <https://host/path>.
            if target.startswith("<") and ">" in target:
                target = target[1:target.find(">")]

            # Ignore an optional Markdown title after the URL.
            # The URL itself is the first whitespace-delimited value.
            if target:
                if target.startswith(("http://", "https://", "//")):
                    target = target.split()[0]
                elif target.startswith("<"):
                    target = target.split()[0]

            urls.append(target)

        return urls

    if channel == "url":
        trimmed = text.strip()
        return [trimmed] if trimmed else []

    return []


# ------------------------------------------------------------
# Dangerous schemes
# ------------------------------------------------------------

DANGEROUS_SCHEME_RE = re.compile(
    r"(?:javascript|data|vbscript)\s*:",
    re.IGNORECASE,
)


def has_dangerous_scheme(channel: str, text: str) -> bool:
    # Explicit dangerous schemes anywhere in the text.
    if DANGEROUS_SCHEME_RE.search(text):
        return True

    # Every extracted URL must use http/https.
    for value in extract_urls(channel, text):
        candidate = value.strip()

        if candidate.startswith("//"):
            # Protocol-relative URLs are resolved as HTTPS.
            scheme = "https"
        else:
            parsed = urlparse(candidate)
            scheme = parsed.scheme.lower()

        # No scheme means a relative reference, which is allowed.
        if scheme and scheme not in {"http", "https"}:
            return True

    return False


# ------------------------------------------------------------
# External host checking
# ------------------------------------------------------------

def has_external_exfil(channel: str, text: str) -> bool:
    for value in extract_urls(channel, text):
        candidate = value.strip()

        # Protocol-relative URL counts as absolute.
        if candidate.startswith("//"):
            parsed = urlparse("https:" + candidate)
            hostname = parsed.hostname

            if hostname is None or hostname not in ALLOWED_HOSTS:
                return True

            continue

        parsed = urlparse(candidate)

        # Relative references are fine.
        if not parsed.scheme:
            continue

        # At this point dangerous schemes should already have
        # been handled. Only http/https are relevant here.
        if parsed.scheme.lower() not in {"http", "https"}:
            continue

        hostname = parsed.hostname

        if hostname is None or hostname not in ALLOWED_HOSTS:
            return True

    return False


# ------------------------------------------------------------
# Channel-specific rules
# ------------------------------------------------------------

def check_channel(channel: str, text: str):
    if channel == "html":

        # SCRIPT_TAG:
        # opening script, iframe, object, or embed tag.
        if re.search(
            r"<\s*(?:script|iframe|object|embed)\b",
            text,
            re.IGNORECASE,
        ):
            return "SCRIPT_TAG"

        # EVENT_HANDLER:
        # on...= attribute.
        if re.search(
            r"\bon[a-zA-Z][a-zA-Z0-9_-]*\s*=",
            text,
            re.IGNORECASE,
        ):
            return "EVENT_HANDLER"

        if has_dangerous_scheme(channel, text):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, text):
            return "EXTERNAL_EXFIL"

        return None

    if channel == "markdown":

        if has_dangerous_scheme(channel, text):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, text):
            return "EXTERNAL_EXFIL"

        return None

    if channel == "url":

        if has_dangerous_scheme(channel, text):
            return "DANGEROUS_SCHEME"

        if has_external_exfil(channel, text):
            return "EXTERNAL_EXFIL"

        return None

    if channel == "sql":

        if re.search(
            r"""['";]|--|/\*|\bunion\b|\bor\s+1\s*=\s*1\b""",
            text,
            re.IGNORECASE,
        ):
            return "SQL_METACHAR"

        return None

    if channel == "shell":

        if re.search(
            r"""[;&|`<>]|\$\(|\$\{""",
            text,
        ):
            return "SHELL_METACHAR"

        return None

    return "INVALID_SCHEMA"


# ------------------------------------------------------------
# Endpoint
# ------------------------------------------------------------

@app.post("/sanitize-output")
def sanitize_output(payload: Any = Body(...)):

    # ========================================================
    # 1. INVALID_SCHEMA
    # ========================================================

    if not isinstance(payload, dict):
        return response(False, "INVALID_SCHEMA")

    if "channel" not in payload or "output" not in payload:
        return response(False, "INVALID_SCHEMA")

    channel = payload["channel"]
    output = payload["output"]

    if channel not in CHANNELS:
        return response(False, "INVALID_SCHEMA")

    if not isinstance(output, str):
        return response(False, "INVALID_SCHEMA")

    if len(output) > 20000:
        return response(False, "INVALID_SCHEMA")

    # ========================================================
    # 2. ENCODED_PAYLOAD
    # ========================================================

    decoded = decode_once(output)

    if decoded != output:
        decoded_reason = check_channel(channel, decoded)

        if decoded_reason is not None:
            return response(False, "ENCODED_PAYLOAD")

    # ========================================================
    # 3. ORIGINAL OUTPUT CHANNEL RULES
    # ========================================================

    reason = check_channel(channel, output)

    if reason is not None:
        return response(False, reason)

    # ========================================================
    # SAFE
    # ========================================================

    return response(True, "SAFE")
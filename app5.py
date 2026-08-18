from fastapi import FastAPI, Body
from typing import Any
from datetime import datetime, timezone

app = FastAPI()

ASSIGNED_SUBJECT = "jp2yt1.example"

VALID_SOURCE_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def invalid_result():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


def unverified_result():
    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }


def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        normalized = value

        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        dt = datetime.fromisoformat(normalized)

        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError):
        return None


def is_number(value: Any) -> bool:
    # bool is a subclass of int in Python, but it is not a
    # meaningful numeric staleness window here.
    return isinstance(value, (int, float)) and not isinstance(value, bool)


@app.post("/corroborate")
def corroborate(payload: Any = Body(...)):

    # =========================================================
    # 1. INVALID INPUT
    # =========================================================

    if not isinstance(payload, dict):
        return invalid_result()

    if "claim" not in payload:
        return invalid_result()

    if "asOf" not in payload:
        return invalid_result()

    if "stalenessDays" not in payload:
        return invalid_result()

    if "sources" not in payload:
        return invalid_result()

    claim = payload["claim"]

    if not isinstance(claim, dict):
        return invalid_result()

    if "value" not in claim:
        return invalid_result()

    if not isinstance(claim["value"], str):
        return invalid_result()

    as_of = parse_timestamp(payload["asOf"])

    if as_of is None:
        return invalid_result()

    staleness_days = payload["stalenessDays"]

    if not is_number(staleness_days):
        return invalid_result()

    sources = payload["sources"]

    if not isinstance(sources, list):
        return invalid_result()

    claim_value = claim["value"]

    # Convert the staleness window to seconds.
    staleness_seconds = staleness_days * 24 * 60 * 60

    # =========================================================
    # Keep only valid sources
    # =========================================================

    valid_sources = []

    for source in sources:

        if not isinstance(source, dict):
            continue

        required_fields = {
            "id",
            "origin",
            "value",
            "observedAt",
            "type",
        }

        if not required_fields.issubset(source.keys()):
            continue

        if not isinstance(source["id"], str):
            continue

        if not isinstance(source["origin"], str):
            continue

        if not isinstance(source["value"], str):
            continue

        if not isinstance(source["observedAt"], str):
            continue

        if source["type"] not in VALID_SOURCE_TYPES:
            continue

        observed_at = parse_timestamp(source["observedAt"])

        if observed_at is None:
            continue

        valid_sources.append(
            {
                "source": source,
                "observed_at": observed_at,
            }
        )

    # =========================================================
    # Determine freshness
    #
    # Fresh iff:
    #     asOf - observedAt <= stalenessDays
    #
    # No wall clock is used.
    # =========================================================

    fresh_sources = []

    for item in valid_sources:

        age_seconds = (
            as_of - item["observed_at"]
        ).total_seconds()

        if age_seconds <= staleness_seconds:
            fresh_sources.append(item)

    # =========================================================
    # 2. AUTHORITATIVE CONTRADICTION
    #
    # First applicable decision after invalid input.
    # =========================================================

    contradicting_ids = []

    for item in fresh_sources:

        source = item["source"]

        if (
            source.get("authoritative") is True
            and source["value"] != claim_value
        ):
            contradicting_ids.append(source["id"])

    if contradicting_ids:
        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": sorted(contradicting_ids),
        }

    # =========================================================
    # 3. SUPPORT
    #
    # Keep fresh sources agreeing with the claim.
    # One representative per origin.
    # Representative = lexicographically smallest id.
    # =========================================================

    agreeing_sources = []

    for item in fresh_sources:

        source = item["source"]

        if source["value"] == claim_value:
            agreeing_sources.append(source)

    representatives = {}

    for source in agreeing_sources:

        origin = source["origin"]

        if origin not in representatives:
            representatives[origin] = source
        else:
            current = representatives[origin]

            if source["id"] < current["id"]:
                representatives[origin] = source

    representative_sources = list(representatives.values())

    if len(representative_sources) >= 2:

        representative_ids = sorted(
            source["id"]
            for source in representative_sources
        )

        distinct_types = {
            source["type"]
            for source in representative_sources
        }

        if len(distinct_types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": representative_ids,
        }

    # =========================================================
    # 4. EVERYTHING ELSE
    # =========================================================

    return unverified_result()
from datetime import datetime
from typing import Any

from fastapi import FastAPI

app = FastAPI()

VALID_TYPES = {
    "dns",
    "ct_log",
    "registry",
    "archive",
    "scan",
}


def parse_timestamp(value: Any):
    if not isinstance(value, str):
        return None

    try:
        return datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except (ValueError, TypeError):
        return None


def invalid_response():
    return {
        "verdict": "invalid",
        "confidence": "low",
        "corroboratingSources": [],
    }


@app.post("/corroborate")
def corroborate(body: Any):

    # --------------------------------------------------
    # RULE 1: INVALID
    # --------------------------------------------------

    if not isinstance(body, dict):
        return invalid_response()

    claim = body.get("claim")
    as_of = parse_timestamp(body.get("asOf"))
    staleness_days = body.get("stalenessDays")
    sources = body.get("sources")

    if (
        not isinstance(claim, dict)
        or not isinstance(claim.get("value"), str)
        or as_of is None
        or isinstance(staleness_days, bool)
        or not isinstance(staleness_days, (int, float))
        or not isinstance(sources, list)
    ):
        return invalid_response()

    claim_value = claim["value"]

    # --------------------------------------------------
    # FILTER VALID + FRESH SOURCES
    # --------------------------------------------------

    max_age_seconds = staleness_days * 24 * 60 * 60

    fresh_sources = []

    for source in sources:

        if not isinstance(source, dict):
            continue

        # Valid source requirements
        if (
            not isinstance(source.get("id"), str)
            or not isinstance(source.get("origin"), str)
            or not isinstance(source.get("value"), str)
            or not isinstance(source.get("observedAt"), str)
            or source.get("type") not in VALID_TYPES
        ):
            continue

        observed_at = parse_timestamp(
            source["observedAt"]
        )

        if observed_at is None:
            continue

        age_seconds = (
            as_of - observed_at
        ).total_seconds()

        # Fresh if:
        # asOf - observedAt <= stalenessDays
        #
        # Future timestamps are therefore also fresh.
        if age_seconds <= max_age_seconds:
            fresh_sources.append(source)

    # --------------------------------------------------
    # RULE 2: CONTRADICTED
    # --------------------------------------------------

    contradicting = [
        source
        for source in fresh_sources
        if source.get("authoritative") is True
        and source["value"] != claim_value
    ]

    if contradicting:

        ids = sorted(
            source["id"]
            for source in contradicting
        )

        return {
            "verdict": "contradicted",
            "confidence": "low",
            "corroboratingSources": ids,
        }

    # --------------------------------------------------
    # RULE 3: SUPPORTED
    # --------------------------------------------------

    matching = [
        source
        for source in fresh_sources
        if source["value"] == claim_value
    ]

    # One representative per origin.
    # Representative = lexicographically smallest ID.
    representatives = {}

    for source in matching:

        origin = source["origin"]

        if (
            origin not in representatives
            or source["id"]
            < representatives[origin]["id"]
        ):
            representatives[origin] = source

    reps = list(representatives.values())

    if len(reps) >= 2:

        ids = sorted(
            source["id"]
            for source in reps
        )

        types = {
            source["type"]
            for source in reps
        }

        if len(types) >= 2:
            confidence = "high"
        else:
            confidence = "medium"

        return {
            "verdict": "supported",
            "confidence": confidence,
            "corroboratingSources": ids,
        }

    # --------------------------------------------------
    # RULE 4: UNVERIFIED
    # --------------------------------------------------

    return {
        "verdict": "unverified",
        "confidence": "low",
        "corroboratingSources": [],
    }


@app.get("/")
def root():
    return {
        "service": "OSINT Corroboration Engine",
        "status": "ok",
    }

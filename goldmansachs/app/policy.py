from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from typing import Any

TIERS = ("untrusted", "readonly", "write")
TIER_RANK = {tier: rank for rank, tier in enumerate(TIERS)}


@dataclass(frozen=True)
class Source:
    max_tier: str
    secret_env: str


SOURCES = {
    "demo-readonly": Source("readonly", "DEMO_READONLY_SECRET"),
    "demo-write": Source("write", "PARTNER_WRITE_SECRET"),
}

SUSPICIOUS = re.compile(
    r"(prompt injection|ignore (all )?(previous|prior) instructions|"
    r"exfiltrat|steal.{0,20}(secret|token|key)|"
    r"(password|secret|api[_ -]?key).{0,30}(send|upload|post))",
    re.IGNORECASE,
)


def verify_signature(source: str, body: bytes, signature: str | None) -> bool:
    config = SOURCES.get(source)
    if config is None or not signature:
        return False
    secret = os.getenv(config.secret_env)
    if not secret:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def deterministic_tier(source: str, payload: dict[str, Any], authenticated: bool) -> str:
    config = SOURCES.get(source)
    if config is None or not authenticated:
        return "untrusted"
    serialized = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    if SUSPICIOUS.search(serialized):
        return "untrusted"
    return config.max_tier


def clamp_tier(candidate: str, source: str, authenticated: bool) -> str:
    """A classifier may downgrade source trust, but can never raise it."""
    if not authenticated or source not in SOURCES or candidate not in TIER_RANK:
        return "untrusted"
    maximum = SOURCES[source].max_tier
    return candidate if TIER_RANK[candidate] <= TIER_RANK[maximum] else maximum

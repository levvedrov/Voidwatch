"""
Voidwatch license system — JWT / RS256.

Keys are issued by you (signed with your private key) and verified here
using the bundled public key. No internet check required.

The active key is persisted in license.json next to the server so it
survives restarts. It can also be set via VOIDWATCH_LICENSE_KEY in .env
(env var takes priority).

Feature flags:
  "ml"        — ML scoring in score_batch
  "export"    — CSV report endpoints
  "feedback"  — analyst feedback submission
  "allowlist" — allowlist management
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# Paste your RSA public key here before shipping.
# Generate with:
#   openssl genrsa -out license_private.pem 2048
#   openssl rsa -in license_private.pem -pubout -out license_public.pem
_PUBLIC_KEY = os.environ.get("VOIDWATCH_LICENSE_PUBLIC_KEY", """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwdcZmiFeDGs99jY9gYRT
ATox7N+zhGc68h6bfnwaM9BmtWfvzn2yHcKlG8l5hk8Y1GHSCIn3D473kK8oRP8u
6qAgXxEE5R6uxmDIIOKOfc9jpVusQVZWFfVv6fjaHL869QqQLgo7dqzreIFHq2NQ
GtCXL8BZUsO7UPeNQ3zQMX8aLokObHV2Ed6PrRTF8sLOfdKD/ZAnKaCsKYkB9i+u
YXi7lDS6bxgoyPQUxd6Qpyda9zu7IeEU5JTb710owIQvpdTzTvowIbH0rj4KoEZ4
9EmOErtrtkY1QbV01WK4mDZqGdVxIanN8Zom+BSB2y4P5KKkNdcjYo5QU5XSjrb7
1wIDAQAB
-----END PUBLIC KEY-----""")

_LICENSE_FILE = Path(__file__).parent / "license.json"

_TIERS: dict[str, dict[str, Any]] = {
    "free": {
        "features":    [],
        "retain_days": 7,
        "display":     "Free",
    },
    "pro": {
        "features":    ["ml", "export", "feedback", "allowlist"],
        "retain_days": 90,
        "display":     "Pro",
    },
    "enterprise": {
        "features":    ["ml", "export", "feedback", "allowlist"],
        "retain_days": 365,
        "display":     "Enterprise",
    },
}


class License:
    def __init__(self, tier: str, features: list[str], expires, customer: str, raw: str):
        self.tier     = tier
        self.features = set(features)
        self.expires  = expires
        self.customer = customer
        self.raw      = raw

    def can(self, feature: str) -> bool:
        return feature in self.features

    def require(self, feature: str) -> None:
        from fastapi import HTTPException
        if not self.can(feature):
            raise HTTPException(
                status_code=402,
                detail=f"'{feature}' requires a Pro or Enterprise license."
            )

    @property
    def retain_days(self) -> int:
        return _TIERS.get(self.tier, _TIERS["free"])["retain_days"]

    @property
    def is_valid(self) -> bool:
        return self.expires is None or datetime.now(timezone.utc) < self.expires

    def to_dict(self) -> dict:
        return {
            "tier":     self.tier,
            "display":  _TIERS.get(self.tier, {}).get("display", self.tier.title()),
            "features": sorted(self.features),
            "customer": self.customer,
            "expires":  self.expires.isoformat() if self.expires else None,
            "valid":    self.is_valid,
        }


def _free() -> License:
    return License(tier="free", features=[], expires=None, customer="", raw="")


def _parse(raw: str) -> License:
    """Validate a JWT string and return a License, or raise ValueError."""
    if not _PUBLIC_KEY:
        raise ValueError("Public key not configured — contact your administrator")
    try:
        import jwt as _jwt
        payload = _jwt.decode(raw, _PUBLIC_KEY, algorithms=["RS256"])
    except Exception as e:
        raise ValueError(f"Invalid license key: {e}") from e

    tier = payload.get("tier", "free")
    if tier not in _TIERS:
        raise ValueError(f"Unknown tier '{tier}'")

    exp_raw = payload.get("expires")
    expires = None
    if exp_raw:
        try:
            expires = datetime.fromisoformat(exp_raw).replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    features = payload.get("features", _TIERS[tier]["features"])
    customer = payload.get("customer", "")
    lic = License(tier=tier, features=features, expires=expires, customer=customer, raw=raw)

    if not lic.is_valid:
        raise ValueError("License key has expired")

    return lic


def activate(raw: str) -> License:
    """Validate key, persist it, reload the global singleton. Raises ValueError on bad key."""
    global license
    lic = _parse(raw.strip())
    _LICENSE_FILE.write_text(json.dumps({"key": raw.strip()}), encoding="utf-8")
    license = lic
    log.info("[license] Activated %s — customer: %s", lic.tier.upper(), lic.customer)
    return lic


def load() -> License:
    # env var takes priority
    raw = os.environ.get("VOIDWATCH_LICENSE_KEY", "").strip()

    # fall back to persisted file
    if not raw and _LICENSE_FILE.exists():
        try:
            raw = json.loads(_LICENSE_FILE.read_text(encoding="utf-8")).get("key", "")
        except Exception:
            raw = ""

    if not raw:
        log.info("[license] No key — Free tier")
        return _free()

    try:
        lic = _parse(raw)
        log.info("[license] %s tier — customer: %s", lic.tier.upper(), lic.customer or "(none)")
        return lic
    except ValueError as e:
        log.warning("[license] %s — falling back to Free", e)
        return _free()


license: License = load()

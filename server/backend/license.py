"""
Voidwatch license system.

License keys are signed JWTs (RS256). You hold the private key; the public key
is bundled here. A key encodes:
  tier       : "free" | "pro" | "enterprise"
  features   : list of enabled feature strings
  expires    : ISO date string (or absent = never)
  customer   : display name

Feature flags checked across the codebase:
  "ml"       — ML scoring in score_batch
  "export"   — CSV report endpoints
  "feedback" — analyst feedback submission
  "allowlist"— allowlist management

Free tier runs with no key at all. Set VOIDWATCH_LICENSE_KEY in .env to upgrade.
"""
from __future__ import annotations

import os
import logging
from datetime import datetime, timezone
from typing import Any

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Your RSA public key — replace with the real one before shipping.
# Generate a pair with:
#   openssl genrsa -out license_private.pem 2048
#   openssl rsa -in license_private.pem -pubout -out license_public.pem
# Keep license_private.pem SECRET (never commit it).
# Paste the public key here.
# ---------------------------------------------------------------------------
_PUBLIC_KEY = os.environ.get("VOIDWATCH_LICENSE_PUBLIC_KEY", "")

_TIERS: dict[str, dict[str, Any]] = {
    "free": {
        "features":       [],
        "retain_days":    7,
        "display":        "Free",
    },
    "pro": {
        "features":       ["ml", "export", "feedback", "allowlist"],
        "retain_days":    90,
        "display":        "Pro",
    },
    "enterprise": {
        "features":       ["ml", "export", "feedback", "allowlist"],
        "retain_days":    365,
        "display":        "Enterprise",
    },
}


class License:
    def __init__(self, tier: str, features: list[str], expires, customer: str, raw: str):
        self.tier     = tier
        self.features = set(features)
        self.expires  = expires   # datetime | None
        self.customer = customer
        self.raw      = raw       # original JWT string

    # ------------------------------------------------------------------
    def can(self, feature: str) -> bool:
        return feature in self.features

    def require(self, feature: str, detail: str = "") -> None:
        from fastapi import HTTPException
        if not self.can(feature):
            msg = detail or f"Feature '{feature}' requires a Pro or Enterprise license."
            raise HTTPException(status_code=402, detail=msg)

    @property
    def retain_days(self) -> int:
        return _TIERS.get(self.tier, _TIERS["free"])["retain_days"]

    @property
    def is_valid(self) -> bool:
        if self.expires is None:
            return True
        return datetime.now(timezone.utc) < self.expires

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
    return License(
        tier="free",
        features=[],
        expires=None,
        customer="",
        raw="",
    )


def load() -> License:
    raw = os.environ.get("VOIDWATCH_LICENSE_KEY", "").strip()
    if not raw:
        log.info("[license] No key set — running Free tier")
        return _free()

    if not _PUBLIC_KEY:
        log.warning("[license] VOIDWATCH_LICENSE_PUBLIC_KEY not set — cannot verify key, falling back to Free")
        return _free()

    try:
        import jwt
        payload = jwt.decode(raw, _PUBLIC_KEY, algorithms=["RS256"])
    except Exception as e:
        log.warning("[license] Invalid license key (%s) — falling back to Free", e)
        return _free()

    tier = payload.get("tier", "free")
    if tier not in _TIERS:
        tier = "free"

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
        log.warning("[license] License expired — falling back to Free")
        return _free()

    log.info("[license] %s tier — customer: %s  features: %s",
             tier.upper(), customer or "(none)", sorted(lic.features))
    return lic


# Module-level singleton — loaded once at import time
license: License = load()

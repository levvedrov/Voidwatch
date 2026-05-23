"""
Issue a signed Voidwatch license key.

Usage:
  python issue_license.py pro    "Acme Corp"  2027-06-01
  python issue_license.py enterprise "BigCo" 2028-01-01
  python issue_license.py pro    "TestUser"   none

Arguments:
  tier       pro | enterprise
  customer   customer name (quote if it contains spaces)
  expires    YYYY-MM-DD, or 'none' for no expiry

Output: JWT license key (paste into Voidwatch activation screen or VOIDWATCH_LICENSE_KEY)
"""
import sys
import json
from pathlib import Path

def main():
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    tier     = sys.argv[1].lower()
    customer = sys.argv[2]
    expires  = sys.argv[3]

    valid_tiers = {"pro", "enterprise", "beta"}
    if tier not in valid_tiers:
        print(f"Error: tier must be one of {valid_tiers}")
        sys.exit(1)

    features = {
        "pro":        ["ml", "export", "feedback", "allowlist"],
        "enterprise": ["ml", "export", "feedback", "allowlist"],
        "beta":       ["ml", "export", "feedback", "allowlist"],
    }[tier]

    payload = {
        "tier":     tier,
        "customer": customer,
        "features": features,
    }
    if expires.lower() != "none":
        payload["expires"] = expires

    key_path = Path(__file__).parent / "license_private.pem"
    if not key_path.exists():
        print(f"Error: private key not found at {key_path}")
        print("Generate with: openssl genrsa -out server/license_private.pem 2048")
        sys.exit(1)

    try:
        import jwt
    except ImportError:
        print("Error: PyJWT not installed — pip install PyJWT cryptography")
        sys.exit(1)

    private_key = key_path.read_text()
    token = jwt.encode(payload, private_key, algorithm="RS256")

    print(f"\nLicense key for {customer!r} ({tier.upper()}):")
    print("-" * 60)
    print(token)
    print("-" * 60)
    if expires.lower() != "none":
        print(f"Expires: {expires}")
    print(f"Features: {', '.join(features)}")

if __name__ == "__main__":
    main()

import hmac
import hashlib
import os

# Review-1 demo secret. In production, load this from an environment variable.
_SECRET = os.environ.get("OFFERPROOF_HMAC_SECRET", "review1-local-secret").encode()

def normalize(value):
    return " ".join((value or "").strip().lower().split())

def fingerprint(value):
    normalized = normalize(value)
    return hmac.new(_SECRET, normalized.encode(), hashlib.sha256).hexdigest()

def mask_email(email):
    email = (email or "").strip()
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 2:
        masked = local[:1] + "*"
    else:
        masked = local[:1] + "*" * (len(local)-2) + local[-1:]
    return f"{masked}@{domain}"

def mask_phone(phone):
    digits = "".join(ch for ch in (phone or "") if ch.isdigit())
    if len(digits) < 4:
        return "*" * len(digits)
    return "*" * (len(digits)-4) + digits[-4:]

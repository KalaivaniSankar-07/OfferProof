import re
from urllib.parse import urlparse


FREE_EMAILS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "rediffmail.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "mail.com",
    "zoho.com"
}


RISK_TERMS = {
    # Payment-related indicators
    "registration fee": 20,
    "security deposit": 20,
    "training fee": 18,
    "processing fee": 18,
    "joining fee": 20,
    "application fee": 15,
    "interview fee": 20,
    "refundable amount": 12,
    "pay now": 16,
    "immediate payment": 16,
    "send money": 18,
    "make payment": 16,

    # Pressure tactics
    "limited slots": 10,
    "limited vacancy": 10,
    "urgent hiring": 10,
    "join immediately": 10,
    "offer expires today": 14,
    "last chance": 10,
    "act now": 10,

    # Suspicious recruitment methods
    "whatsapp only": 10,
    "telegram only": 12,
    "contact on telegram": 12,
    "no interview": 18,
    "without interview": 18,
    "direct selection": 12,
    "instant joining": 12,

    # Unrealistic promises
    "guaranteed placement": 15,
    "guaranteed job": 15,
    "100% placement": 12,
    "easy money": 15,
    "work from home and earn": 10,

    # Payment methods
    "upi": 8,
    "google pay": 8,
    "phonepe": 8,
    "paytm": 8,
    "scan qr": 10
}


SUSPICIOUS_TLDS = (
    ".xyz",
    ".top",
    ".click",
    ".work",
    ".live",
    ".site",
    ".online",
    ".buzz",
    ".icu",
    ".shop"
)


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "shorturl.at",
    "rb.gy"
}


def normalize_domain(domain):
    domain = (domain or "").lower().strip()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def add_reason(reasons, reason):
    if reason not in reasons:
        reasons.append(reason)


def analyze_offer(company, email, phone, website, payment_id, message):
    company = (company or "").strip()
    email = (email or "").strip()
    phone = (phone or "").strip()
    website = (website or "").strip()
    payment_id = (payment_id or "").strip()
    message = (message or "").strip()

    score = 0
    reasons = []

    combined_text = (
        f"{company} {email} {phone} "
        f"{website} {payment_id} {message}"
    ).lower()

    # 1. Suspicious phrase detection
    for phrase, points in RISK_TERMS.items():
        if phrase in combined_text:
            score += points
            add_reason(
                reasons,
                f'Suspicious phrase detected: "{phrase}".'
            )

    # 2. Payment identifier check
    if payment_id:
        score += 22
        add_reason(
            reasons,
            "A payment or UPI identifier was provided before independent verification."
        )

    # 3. Recruiter email checks
    email_domain = ""

    if email:
        if "@" not in email:
            score += 10
            add_reason(
                reasons,
                "Recruiter email address does not appear to be valid."
            )
        else:
            email_domain = normalize_domain(email.rsplit("@", 1)[-1])

            if email_domain in FREE_EMAILS:
                score += 15
                add_reason(
                    reasons,
                    "Recruiter is using a free or public email domain."
                )

    # 4. Website checks
    website_host = ""

    if website:
        website_url = (
            website if "://" in website
            else "https://" + website
        )

        parsed = urlparse(website_url)
        website_host = normalize_domain(parsed.hostname)

        if not website_host:
            score += 10
            add_reason(
                reasons,
                "The submitted company website format appears invalid."
            )

        if website_host.endswith(SUSPICIOUS_TLDS):
            score += 14
            add_reason(
                reasons,
                "Website uses a domain ending associated with low-trust campaigns."
            )

        if website_host in URL_SHORTENERS:
            score += 18
            add_reason(
                reasons,
                "The submitted website uses a shortened URL that hides the final destination."
            )

        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", website_host):
            score += 18
            add_reason(
                reasons,
                "The website uses a raw IP address instead of a normal company domain."
            )

        if website.lower().startswith("http://"):
            score += 6
            add_reason(
                reasons,
                "The submitted website does not use an HTTPS connection."
            )

    # 5. Email and website domain comparison
    if (
        email_domain
        and website_host
        and email_domain not in FREE_EMAILS
        and email_domain != website_host
        and not website_host.endswith("." + email_domain)
        and not email_domain.endswith("." + website_host)
    ):
        score += 15
        add_reason(
            reasons,
            "Recruiter email domain does not match the stated company website."
        )

    # 6. Payment amount detection
    money_pattern = (
        r"(?:₹|rs\.?|inr)\s*\d+"
        r"|\b\d{3,6}\s*(?:rupees|rs|inr)\b"
    )

    payment_words = {
        "fee",
        "pay",
        "payment",
        "deposit",
        "amount",
        "transfer"
    }

    if (
        re.search(money_pattern, combined_text, re.IGNORECASE)
        and any(word in combined_text for word in payment_words)
    ):
        score += 12
        add_reason(
            reasons,
            "The offer combines a payment request with a specific monetary amount."
        )

    # 7. QR code payment request
    if (
        "qr code" in combined_text
        or "scan the qr" in combined_text
    ):
        score += 12
        add_reason(
            reasons,
            "The offer asks the applicant to use a QR code for payment."
        )

    # 8. Sensitive document request
    sensitive_terms = [
        "aadhaar",
        "aadhar",
        "pan card",
        "bank account",
        "bank details",
        "otp",
        "cvv",
        "debit card",
        "credit card"
    ]

    detected_sensitive_terms = [
        term for term in sensitive_terms
        if term in combined_text
    ]

    if detected_sensitive_terms:
        score += 15
        add_reason(
            reasons,
            "The message requests sensitive identity or financial information."
        )

    # 9. Extremely short offer message
    if message and len(message.split()) < 5:
        score += 5
        add_reason(
            reasons,
            "The offer message contains very little verifiable information."
        )

    # 10. Multiple high-pressure indicators
    pressure_terms = [
        "urgent",
        "immediately",
        "today only",
        "limited slots",
        "last chance",
        "act now"
    ]

    pressure_count = sum(
        1 for term in pressure_terms
        if term in combined_text
    )

    if pressure_count >= 2:
        score += 10
        add_reason(
            reasons,
            "The message uses multiple urgency and pressure tactics."
        )

    # Keep score within 0–100
    score = max(0, min(score, 100))

    # Risk classification
    if score >= 70:
        level = "HIGH RISK"
        tone = "danger"
        recommendation = (
            "Do not make any payment or share sensitive documents. "
            "Verify the company using its official website and independently "
            "published contact information."
        )

    elif score >= 40:
        level = "SUSPICIOUS"
        tone = "warning"
        recommendation = (
            "Proceed carefully. Verify the recruiter, company domain and offer "
            "through independent official channels before taking any action."
        )

    else:
        level = "LOW INDICATORS"
        tone = "safe"
        recommendation = (
            "No major scam indicators were found by the current engine. "
            "This does not guarantee that the offer is genuine, so independent "
            "verification is still recommended."
        )

    if not reasons:
        reasons.append(
            "No major rule-based scam indicators were detected in the submitted details."
        )

    return {
        "score": score,
        "level": level,
        "tone": tone,
        "reasons": reasons[:8],
        "recommendation": recommendation
    }
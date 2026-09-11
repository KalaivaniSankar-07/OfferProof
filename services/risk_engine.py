import re
from urllib.parse import urlparse

FREE_EMAILS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "rediffmail.com", "proton.me", "protonmail.com"
}

HIGH_RISK_TERMS = {
    "registration fee": 20,
    "security deposit": 20,
    "training fee": 18,
    "processing fee": 18,
    "pay now": 16,
    "immediate payment": 16,
    "limited slots": 10,
    "urgent": 8,
    "refundable amount": 12,
    "upi": 8,
    "whatsapp only": 8,
    "guaranteed placement": 12
}

def analyze_offer(company, email, phone, website, payment_id, message):
    score = 0
    reasons = []
    text = f"{company} {email} {phone} {website} {payment_id} {message}".lower()

    for phrase, points in HIGH_RISK_TERMS.items():
        if phrase in text:
            score += points
            reasons.append(f"Suspicious phrase detected: “{phrase}”")

    if payment_id:
        score += 22
        reasons.append("Payment identifier requested/provided before independent verification.")

    if email and "@" in email:
        domain = email.split("@")[-1].lower().strip()
        if domain in FREE_EMAILS:
            score += 15
            reasons.append("Recruiter is using a free/public email domain.")

    if website:
        parsed = urlparse(website if "://" in website else "https://" + website)
        host = (parsed.netloc or "").lower()
        suspicious_tlds = (".xyz", ".top", ".click", ".work", ".live", ".site")
        if host.endswith(suspicious_tlds):
            score += 14
            reasons.append("Website uses a domain ending commonly seen in disposable/low-trust campaigns.")

        if email and "@" in email:
            email_domain = email.split("@")[-1].lower().strip()
            if email_domain not in FREE_EMAILS and email_domain not in host and host not in email_domain:
                score += 15
                reasons.append("Recruiter email domain does not match the stated company website.")

    if re.search(r"\b\d{4,6}\b", message) and any(x in text for x in ["fee", "pay", "payment", "deposit"]):
        score += 10
        reasons.append("Message appears to combine a payment request with a specific amount.")

    score = min(score, 100)

    if score >= 70:
        level = "HIGH RISK"
        tone = "danger"
        recommendation = "Do not make a payment or share sensitive documents until the company is independently verified."
    elif score >= 40:
        level = "SUSPICIOUS"
        tone = "warning"
        recommendation = "Verify the recruiter and company through independent official channels before proceeding."
    else:
        level = "LOW INDICATORS"
        tone = "safe"
        recommendation = "No major warning indicators were found by the current Review-1 engine, but this is not a guarantee of legitimacy."

    if not reasons:
        reasons.append("No major rule-based scam indicators detected in the submitted details.")

    return {
        "score": score,
        "level": level,
        "tone": tone,
        "reasons": reasons[:6],
        "recommendation": recommendation
    }

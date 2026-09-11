# OfferProof
### AI-Powered Recruitment Fraud Detection & Verification Platform
**Tagline:** Verify Before You Trust.

OfferProof is a privacy-first student safety platform designed to reduce fake internship and recruitment scams.

## Review 1 Progress — Approximately 40%

### Completed / Working
- Professional responsive landing page
- Offer verification form
- Explainable rule-based scam risk scoring
- Detection of payment-pressure phrases
- Recruiter free-email-domain warning
- Recruiter email vs company website mismatch check
- Scam reporting module
- SQLite database
- Privacy-safe masking of student/recruiter identifiers
- HMAC-based repeat-scam fingerprint matching
- Previous report count
- Confirmed victim count
- Aggregate reported financial loss
- Fraud intelligence dashboard

### Pending / Next Steps
- PDF offer-letter extraction and analysis
- Screenshot / WhatsApp message analysis
- Domain reputation and age verification APIs
- Machine-learning classifier trained on scam/genuine offer datasets
- Scam relationship graph
- Advanced Agentic AI verification workflow
- Authentication / role-based access control
- Production deployment and security hardening

## Run locally
```bash
pip install -r requirements.txt
python app.py
```

Open: `http://127.0.0.1:5000`

## Privacy Note
Raw identifiers are not shown publicly. Repeat-scam matching uses HMAC-based fingerprints, while displayed email/phone details are masked.

> Review-1 implementation is a prototype and its risk score is an indicator, not proof that an organization is fraudulent.

# OFFERPROOF — REVIEW 1 PROGRESS REPORT

## 1. Project Title
OfferProof — AI-Powered Recruitment Fraud Detection & Verification Platform

## 2. Problem Statement
Students are increasingly targeted by fake internship and recruitment offers that impersonate companies, create urgency, and request registration, training, security or processing fees. Students may also unknowingly share personal information with fraudulent recruiters.

## 3. Proposed Solution
OfferProof is a privacy-first software platform that allows a student to enter internship/job offer details before trusting or paying a recruiter. The system analyses multiple risk signals, produces an explainable risk score, compares scam identifiers with previous reports, and displays the number of reports, confirmed victims and aggregate reported loss.

## 4. Review 1 Completion
Approximate completion: 40%

## 5. Work Completed So Far
- Flask application and structured project setup
- Responsive cybersecurity-themed user interface
- Offer verification form
- Rule-based risk analysis engine
- Detection of payment pressure and suspicious recruitment language
- Recruiter email-domain checks
- Company website / recruiter email mismatch analysis
- Scam reporting workflow
- SQLite data storage
- Privacy-safe masking of email and phone data
- Secure HMAC fingerprints for repeat-scam matching
- Historical report matching
- Confirmed victim and total-loss aggregation
- Fraud intelligence dashboard

## 6. Currently Working
A student can submit an offer for analysis and receive a risk score with clear reasons. A scam can be reported to the database. When later verification data contains the same email, phone, website or payment identifier, OfferProof can detect previous reports and show aggregate victim intelligence without exposing victim identities.

## 7. Privacy and Cybersecurity Work Completed
- Sensitive identifiers are masked before display.
- Matching uses a secret-keyed HMAC fingerprint instead of publishing raw identifiers.
- The public GitHub repository excludes the local database, environment secrets and IDE configuration.
- The current system clearly labels the risk score as an indicator and does not claim legal proof of fraud.

## 8. Pending Work
- PDF offer letter analysis
- Screenshot and WhatsApp-message analysis
- External domain reputation verification
- ML-based scam classifier
- Agentic AI verification pipeline
- Scam relationship/network graph
- Authentication and role-based access
- Production deployment and security testing

## 9. Next Steps
The next development cycle will focus on PDF/document intelligence, domain forensics and a machine-learning model. After that, scam-network graph analysis and an Agentic AI verification workflow will be integrated.

## 10. Current Technology Stack
Frontend: HTML, CSS
Backend: Python Flask
Database: SQLite
AI/Data Logic: Explainable rule-based risk scoring (Review 1)
Cybersecurity: Data masking, HMAC fingerprinting, minimal public exposure of sensitive data
Version Control: GitHub

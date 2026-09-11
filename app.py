from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
from datetime import datetime
from services.risk_engine import analyze_offer
from services.privacy import fingerprint, mask_email, mask_phone

app = Flask(__name__)
app.secret_key = "offerproof-review1-demo-key"
DB_NAME = "offerproof.db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scam_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT,
            email_fp TEXT,
            phone_fp TEXT,
            website_fp TEXT,
            payment_fp TEXT,
            masked_email TEXT,
            masked_phone TEXT,
            victim INTEGER DEFAULT 0,
            amount_lost REAL DEFAULT 0,
            created_at TEXT
        )
    """)
    conn.commit()
    conn.close()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/verify")
def verify():
    return render_template("verify.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    company = request.form.get("company", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    website = request.form.get("website", "").strip()
    payment_id = request.form.get("payment_id", "").strip()
    message = request.form.get("message", "").strip()

    result = analyze_offer(company, email, phone, website, payment_id, message)

    conn = get_db()
    clauses = []
    params = []

    if email:
        clauses.append("email_fp = ?")
        params.append(fingerprint(email))
    if phone:
        clauses.append("phone_fp = ?")
        params.append(fingerprint(phone))
    if website:
        clauses.append("website_fp = ?")
        params.append(fingerprint(website))
    if payment_id:
        clauses.append("payment_fp = ?")
        params.append(fingerprint(payment_id))

    match_count = 0
    victim_count = 0
    total_loss = 0

    if clauses:
        query = "SELECT * FROM scam_reports WHERE " + " OR ".join(clauses)
        rows = conn.execute(query, params).fetchall()
        unique_ids = {row["id"] for row in rows}
        match_count = len(unique_ids)
        victim_count = sum(1 for row in rows if row["victim"] == 1)
        total_loss = sum(float(row["amount_lost"] or 0) for row in rows)

    conn.close()

    return render_template(
        "result.html",
        result=result,
        company=company,
        email=mask_email(email),
        phone=mask_phone(phone),
        website=website,
        previous_reports=match_count,
        victim_count=victim_count,
        total_loss=total_loss
    )

@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "POST":
        company = request.form.get("company", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        website = request.form.get("website", "").strip()
        payment_id = request.form.get("payment_id", "").strip()
        victim = 1 if request.form.get("victim") == "yes" else 0

        try:
            amount_lost = float(request.form.get("amount_lost", "0") or 0)
        except ValueError:
            amount_lost = 0

        conn = get_db()
        conn.execute("""
            INSERT INTO scam_reports
            (company, email_fp, phone_fp, website_fp, payment_fp,
             masked_email, masked_phone, victim, amount_lost, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            company,
            fingerprint(email) if email else "",
            fingerprint(phone) if phone else "",
            fingerprint(website) if website else "",
            fingerprint(payment_id) if payment_id else "",
            mask_email(email),
            mask_phone(phone),
            victim,
            amount_lost,
            datetime.now().isoformat(timespec="seconds")
        ))
        conn.commit()
        conn.close()
        flash("Scam report saved securely. Personal identifiers are masked/fingerprinted.")
        return redirect(url_for("report"))

    return render_template("report.html")

@app.route("/dashboard")
def dashboard():
    conn = get_db()
    stats = conn.execute("""
        SELECT
            COUNT(*) AS reports,
            SUM(victim) AS victims,
            COALESCE(SUM(amount_lost), 0) AS loss
        FROM scam_reports
    """).fetchone()

    recent = conn.execute("""
        SELECT company, masked_email, masked_phone, victim, amount_lost, created_at
        FROM scam_reports
        ORDER BY id DESC
        LIMIT 6
    """).fetchall()
    conn.close()

    return render_template("dashboard.html", stats=stats, recent=recent)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)

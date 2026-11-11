from flask import Flask, render_template, request, redirect, url_for, flash
import sqlite3
import os
import secrets
import math
from datetime import datetime

from services.risk_engine import analyze_offer
from services.pdf_analyzer import extract_pdf_text
from services.privacy import fingerprint, mask_email, mask_phone


app = Flask(__name__)
app.secret_key = os.environ.get("OFFERPROOF_SESSION_SECRET") or secrets.token_hex(32)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

DB_NAME = os.environ.get("OFFERPROOF_DB_PATH", "offerproof.db")


# -------------------------------------------------
# DATABASE CONNECTION
# -------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


# -------------------------------------------------
# DATABASE INITIALIZATION
# -------------------------------------------------

def init_db():
    conn = get_db()

    # Scam reports table
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

    # Verification history table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            company TEXT,
            masked_email TEXT,
            masked_phone TEXT,
            website TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            reasons TEXT,
            previous_reports INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


# -------------------------------------------------
# HOME PAGE
# -------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -------------------------------------------------
# VERIFY OFFER PAGE
# -------------------------------------------------

@app.route("/verify")
def verify():
    return render_template("verify.html")


# -------------------------------------------------
# ANALYZE OFFER
# -------------------------------------------------

@app.route("/analyze", methods=["POST"])
def analyze():
    company = request.form.get("company", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    website = request.form.get("website", "").strip()
    payment_id = request.form.get("payment_id", "").strip()
    message = request.form.get("message", "").strip()
    offer_pdf = request.files.get("offer_pdf")

    # Extract text from uploaded PDF
    if offer_pdf and offer_pdf.filename:
        try:
            pdf_text = extract_pdf_text(offer_pdf)

            if not pdf_text:
                flash("No readable text was found in the PDF. Scanned PDFs need OCR; other submitted details were checked.")
            if pdf_text:
                if message:
                    message = message + "\n" + pdf_text
                else:
                    message = pdf_text

        except Exception as error:
            app.logger.warning("PDF extraction failed: %s", type(error).__name__)
            flash(
                "The PDF could not be analyzed. "
                "Other submitted details were checked."
            )

    # Analyze offer using risk engine
    result = analyze_offer(
        company,
        email,
        phone,
        website,
        payment_id,
        message
    )

    conn = get_db()

    # Search matching previous scam reports
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
        query = """
            SELECT *
            FROM scam_reports
            WHERE
        """ + " OR ".join(clauses)

        rows = conn.execute(query, params).fetchall()

        match_count = len(rows)

        victim_count = sum(
            1 for row in rows
            if row["victim"] == 1
        )

        total_loss = sum(
            float(row["amount_lost"] or 0)
            for row in rows
        )

    # Convert reason list into database text
    reasons_text = " | ".join(result["reasons"])

    # Save every verification attempt
    conn.execute("""
        INSERT INTO verification_history (
            company,
            masked_email,
            masked_phone,
            website,
            risk_score,
            risk_level,
            reasons,
            previous_reports,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        company,
        mask_email(email),
        mask_phone(phone),
        website,
        result["score"],
        result["level"],
        reasons_text,
        match_count,
        datetime.now().isoformat(timespec="seconds")
    ))

    conn.commit()
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


# -------------------------------------------------
# REPORT SCAM
# -------------------------------------------------

@app.route("/report", methods=["GET", "POST"])
def report():
    if request.method == "POST":
        company = request.form.get("company", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        website = request.form.get("website", "").strip()
        payment_id = request.form.get("payment_id", "").strip()

        victim = (
            1
            if request.form.get("victim") == "yes"
            else 0
        )

        try:
            amount_lost = float(
                request.form.get("amount_lost", "0") or 0
            )

            if not math.isfinite(amount_lost) or amount_lost < 0:
                amount_lost = 0

        except ValueError:
            amount_lost = 0

        conn = get_db()

        conn.execute("""
            INSERT INTO scam_reports (
                company,
                email_fp,
                phone_fp,
                website_fp,
                payment_fp,
                masked_email,
                masked_phone,
                victim,
                amount_lost,
                created_at
            )
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

        flash(
            "Scam report saved securely. "
            "Personal identifiers are masked and fingerprinted."
        )

        return redirect(url_for("report"))

    return render_template("report.html")


# -------------------------------------------------
# DASHBOARD
# -------------------------------------------------

@app.route("/dashboard")
def dashboard():
    conn = get_db()

    stats = conn.execute("""
        SELECT
            COUNT(*) AS reports,
            COALESCE(SUM(victim), 0) AS victims,
            COALESCE(SUM(amount_lost), 0) AS loss
        FROM scam_reports
    """).fetchone()

    recent = conn.execute("""
        SELECT
            company,
            masked_email,
            masked_phone,
            victim,
            amount_lost,
            created_at
        FROM scam_reports
        ORDER BY id DESC
        LIMIT 6
    """).fetchall()

    verification_stats = conn.execute("""
        SELECT
            COUNT(*) AS total_checks,
            SUM(
                CASE
                    WHEN risk_level = 'HIGH RISK'
                    THEN 1 ELSE 0
                END
            ) AS high_risk,
            SUM(
                CASE
                    WHEN risk_level = 'SUSPICIOUS'
                    THEN 1 ELSE 0
                END
            ) AS suspicious,
            SUM(
                CASE
                    WHEN risk_level = 'LOW INDICATORS'
                    THEN 1 ELSE 0
                END
            ) AS low_risk
        FROM verification_history
    """).fetchone()

    conn.close()

    return render_template(
        "dashboard.html",
        stats=stats,
        recent=recent,
        verification_stats=verification_stats
    )


# -------------------------------------------------
# VERIFICATION HISTORY
# -------------------------------------------------

@app.route("/history")
def history():
    conn = get_db()

    checks = conn.execute("""
        SELECT
            id,
            company,
            masked_email,
            masked_phone,
            website,
            risk_score,
            risk_level,
            reasons,
            previous_reports,
            created_at
        FROM verification_history
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return render_template(
        "history.html",
        checks=checks
    )


# -------------------------------------------------
# RUN APPLICATION
# -------------------------------------------------

@app.cli.command("init-db")
def init_db_command():
    """Create missing database tables without deleting existing records."""
    init_db()
    print("Database initialized.")


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
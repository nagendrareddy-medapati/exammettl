import os
import random
import io
import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, session, send_file, jsonify, make_response
import pandas as pd
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv

# IST = UTC+5:30
IST = timezone(timedelta(hours=5, minutes=30))

def now_ist():
    """Return current datetime in IST."""
    return datetime.now(IST)

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "exam_secret_key_change_in_prod")

@app.route('/favicon.ico')
def favicon():
    return make_response('', 204)

def send_reset_email(to_email, reset_link):
    """Send password reset email via SMTP. Reads config from environment variables."""
    smtp_host   = os.environ.get("SMTP_HOST", "smtp.gmail.com")
    smtp_port   = int(os.environ.get("SMTP_PORT", 587))
    smtp_user   = os.environ.get("SMTP_USER", "")
    smtp_pass   = os.environ.get("SMTP_PASS", "")
    from_name   = os.environ.get("SMTP_FROM_NAME", "Exammettl")
    from_email  = os.environ.get("SMTP_FROM_EMAIL", smtp_user)

    if not smtp_user or not smtp_pass:
        raise RuntimeError("SMTP_USER and SMTP_PASS must be set in .env to send emails.")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = "Reset Your Exammettl Password"
    msg["From"]    = f"{from_name} <{from_email}>"
    msg["To"]      = to_email

    text_body = f"""\
Hi,

You requested a password reset for your Exammettl account.

Click the link below to set a new password (valid for 1 hour):
{reset_link}

If you did not request this, you can safely ignore this email.

— The Exammettl Team
"""
    html_body = f"""\
<html><body style="font-family:sans-serif;color:#222;">
  <h2 style="color:#3498db;">🔑 Password Reset Request</h2>
  <p>You requested a password reset for your <b>Exammettl</b> account.</p>
  <p>
    <a href="{reset_link}"
       style="display:inline-block;padding:10px 22px;background:#3498db;color:#fff;
              border-radius:6px;text-decoration:none;font-weight:bold;">
      Reset My Password
    </a>
  </p>
  <p style="font-size:13px;color:#666;">
    This link is valid for <b>1 hour</b>.<br>
    If you did not request this, you can safely ignore this email.
  </p>
  <hr style="border:none;border-top:1px solid #eee;"/>
  <p style="font-size:12px;color:#aaa;">— The Exammettl Team</p>
</body></html>
"""
    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.ehlo()
        server.starttls()
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, to_email, msg.as_string())

MONGO_URI = os.environ.get("MONGO_URI", "")
_mongo_client = None

def get_client():
    global _mongo_client
    if _mongo_client is None:
        if not MONGO_URI:
            raise RuntimeError("MONGO_URI is not set.")
        _mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _mongo_client

def get_db():
    return get_client()["exam_system"]

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{hashed}"

def verify_password(stored, provided):
    try:
        salt, hashed = stored.split(":")
        return hashlib.sha256((salt + provided).encode()).hexdigest() == hashed
    except Exception:
        return False

def get_client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

def doc_to_row(doc):
    return [
        str(doc["_id"]),
        doc.get("question", ""),
        doc.get("option_a", ""),
        doc.get("option_b", ""),
        doc.get("option_c", ""),
        doc.get("option_d", ""),
        doc.get("correct_option", ""),
        doc.get("type", "mcq"),
        doc.get("subject", ""),
        doc.get("topic", ""),
        doc.get("difficulty", "medium"),
    ]

def seed_questions():
    try:
        db = get_db()
    except Exception as e:
        print(f"Could not connect: {e}")
        return
    if db.questions.count_documents({}) == 0:
        sample = [
            {"question": "What does HTML stand for?", "type": "mcq",
             "option_a": "Hyper Text Markup Language", "option_b": "High Tech Modern Language",
             "option_c": "Hyper Transfer Markup Language", "option_d": "Home Tool Markup Language",
             "correct_option": "A", "subject": "Web Development", "topic": "HTML", "difficulty": "easy"},
            {"question": "Which language is used for styling web pages?", "type": "mcq",
             "option_a": "HTML", "option_b": "Python", "option_c": "CSS", "option_d": "Java",
             "correct_option": "C", "subject": "Web Development", "topic": "CSS", "difficulty": "easy"},
            {"question": "MongoDB is a relational database.", "type": "truefalse",
             "option_a": "True", "option_b": "False", "option_c": "", "option_d": "",
             "correct_option": "B", "subject": "Databases", "topic": "NoSQL", "difficulty": "easy"},
            {"question": "What does CPU stand for?", "type": "mcq",
             "option_a": "Central Processing Unit", "option_b": "Computer Personal Unit",
             "option_c": "Central Peripheral Utility", "option_d": "Core Processing Utility",
             "correct_option": "A", "subject": "Computer Science", "topic": "Hardware", "difficulty": "easy"},
            {"question": "Which symbol is used for comments in Python?", "type": "mcq",
             "option_a": "//", "option_b": "/* */", "option_c": "#", "option_d": "--",
             "correct_option": "C", "subject": "Programming", "topic": "Python", "difficulty": "easy"},
            {"question": "Briefly explain the difference between SQL and NoSQL databases.", "type": "essay",
             "option_a": "", "option_b": "", "option_c": "", "option_d": "", "correct_option": "",
             "subject": "Databases", "topic": "General", "difficulty": "medium"},
        ]
        db.questions.insert_many(sample)
        print(f"Seeded {len(sample)} questions.")

@app.errorhandler(500)
def internal_error(e):
    return f"""<div style="font-family:sans-serif;text-align:center;margin-top:80px;">
      <h2>Server Error</h2><p>{str(e)}</p><a href="/">Go Home</a></div>""", 500

# ── REGISTER ────────────────────────────────────────────────────────────────────
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        role     = request.form.get("role", "candidate")
        if not all([username, email, password]):
            error = "All fields are required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        else:
            db = get_db()
            if db.users.find_one({"$or": [{"username": username}, {"email": email}]}):
                error = "Username or email already exists."
            else:
                db.users.insert_one({
                    "username": username, "email": email,
                    "password": hash_password(password), "role": role,
                    "created_at": now_ist(), "reset_token": None,
                    "profile": {"full_name": username, "bio": ""}
                })
                success = "Registration successful! You can now login."
    return render_template("register.html", error=error, success=success)

# ── FORGOT PASSWORD ──────────────────────────────────────────────────────────────
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    error = None; success = None
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.users.find_one({"email": email})
        if user:
            token = secrets.token_urlsafe(32)
            db.users.update_one({"email": email}, {"$set": {
                "reset_token": token,
                "reset_token_expires": now_ist() + timedelta(hours=1)
            }})
            base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
            reset_link = f"{base_url}/reset_password/{token}"
            try:
                send_reset_email(email, reset_link)
                success = "A password reset link has been sent to your email. Please check your inbox (and spam folder)."
            except Exception as e:
                error = f"Could not send reset email: {str(e)}"
        else:
            error = "No account found with that email."
    return render_template("forgot_password.html", error=error, success=success)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    db = get_db()
    user = db.users.find_one({"reset_token": token, "reset_token_expires": {"$gt": now_ist()}})
    error = None
    if not user:
        return render_template("forgot_password.html", error="Invalid or expired link.", success=None)
    if request.method == "POST":
        new_pass = request.form.get("password", "").strip()
        if len(new_pass) < 6:
            error = "Password must be at least 6 characters."
        else:
            db.users.update_one({"_id": user["_id"]}, {"$set": {
                "password": hash_password(new_pass), "reset_token": None
            }})
            return redirect("/?msg=Password+reset+successful")
    return render_template("reset_password.html", token=token, error=error)

# ── PROFILE ──────────────────────────────────────────────────────────────────────
@app.route("/profile", methods=["GET", "POST"])
def profile():
    if "user" not in session:
        return redirect("/")
    db = get_db()
    user = db.users.find_one({"username": session["user"]})
    success = None; error = None
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        bio       = request.form.get("bio", "").strip()
        new_pass  = request.form.get("new_password", "").strip()
        if new_pass and len(new_pass) < 6:
            error = "Password must be at least 6 characters."
        else:
            upd = {"profile.full_name": full_name, "profile.bio": bio}
            if new_pass:
                upd["password"] = hash_password(new_pass)
            db.users.update_one({"username": session["user"]}, {"$set": upd})
            success = "Profile updated!"
            user = db.users.find_one({"username": session["user"]})
    return render_template("profile.html", user=user, success=success, error=error)

# ── LOGIN ────────────────────────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def login():
    error = None
    msg = request.args.get("msg")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            error = "Username and password are required."
        else:
            db = get_db()
            client_ip = get_client_ip()
            existing = db.active_sessions.find_one({"username": username})
            if existing and existing.get("ip") != client_ip:
                db.logs.insert_one({"username": username, "activity": "Multiple Login Attempt",
                                    "ip": client_ip, "timestamp": now_ist()})
            user = db.users.find_one({"username": username})
            if user and verify_password(user["password"], password):
                session.clear()
                session["user"] = username
                session["role"] = user.get("role", "candidate")
                db.active_sessions.update_one({"username": username},
                    {"$set": {"username": username, "ip": client_ip, "last_seen": now_ist()}}, upsert=True)
                db.logs.insert_one({"username": username, "activity": "Login",
                                    "ip": client_ip, "timestamp": now_ist()})
                return redirect("/dashboard")
            error = "Invalid username or password."
    return render_template("login.html", error=error, msg=msg)

# ── DASHBOARD ────────────────────────────────────────────────────────────────────
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    db = get_db()
    exams = list(db.exams.find({"status": "active"}))
    user_results = list(db.results.find({"username": session["user"]}, {"_id": 0, "details": 0, "subjective_answers": 0}))
    notifications = list(db.notifications.find(
        {"$or": [{"target": "all"}, {"target": session["user"]}]}
    ).sort("created_at", -1).limit(5))
    return render_template("dashboard.html", exams=exams, results=user_results, notifications=notifications)

# ── EXAM ─────────────────────────────────────────────────────────────────────────
@app.route("/exam", methods=["GET", "POST"])
@app.route("/exam/<exam_id>", methods=["GET", "POST"])
def exam(exam_id=None):
    if "user" not in session:
        return redirect("/")
    db = get_db()
    exam_doc = None
    if exam_id:
        try:
            exam_doc = db.exams.find_one({"_id": ObjectId(exam_id)})
        except Exception:
            pass
    if exam_doc and exam_doc.get("enrollment_type") == "closed":
        enrolled = db.enrollments.find_one({"exam_id": str(exam_doc["_id"]), "username": session["user"]})
        if not enrolled:
            return render_template("exam.html", questions=[], error="You are not enrolled in this exam.")
    if exam_doc:
        now = now_ist()
        start = exam_doc.get("start_time")
        end   = exam_doc.get("end_time")
        # Make stored datetimes timezone-aware if they are naive
        if start and start.tzinfo is None:
            start = start.replace(tzinfo=IST)
        if end and end.tzinfo is None:
            end = end.replace(tzinfo=IST)
        if start and now < start:
            return render_template("exam.html", questions=[], error=f"Exam starts at {start.strftime('%Y-%m-%d %H:%M IST')}.")
        if end and now > end:
            return render_template("exam.html", questions=[], error="This exam has ended.")
    duration_seconds = (exam_doc.get("duration_minutes", 10) * 60) if exam_doc else 600
    if "questions" not in session:
        query = {}
        if exam_doc and exam_doc.get("filters"):
            query = {k: v for k, v in exam_doc["filters"].items() if v}
        docs = list(db.questions.find(query))
        random.shuffle(docs)
        questions = [doc_to_row(d) for d in docs]
        session["questions"] = questions
        session["exam_id"] = exam_id
        session["duration"] = duration_seconds
    else:
        questions = session["questions"]
    if not questions:
        return render_template("exam.html", questions=[], error="No questions found.")
    if request.method == "POST":
        score = 0.0
        details = []
        subjective_answers = []
        for q in questions:
            qid   = q[0]; correct = q[6]; qtype = q[7] if len(q) > 7 else "mcq"
            ans   = request.form.get(qid, "").strip()
            if qtype in ("mcq", "truefalse"):
                if ans == correct:
                    score += 1; details.append({"qid": qid, "ans": ans, "correct": True})
                elif ans:
                    score -= 0.25; details.append({"qid": qid, "ans": ans, "correct": False})
                else:
                    details.append({"qid": qid, "ans": "", "correct": False})
            elif qtype in ("essay", "descriptive", "short_answer"):
                subjective_answers.append({"qid": qid, "question": q[1], "answer": ans, "score": None, "graded": False})
        db.results.insert_one({
            "username": session["user"], "score": round(score, 2),
            "total": len(questions), "timestamp": now_ist(),
            "exam_id": exam_id, "details": details,
            "subjective_answers": subjective_answers,
            "pending_grading": len(subjective_answers) > 0,
            "ip": get_client_ip(),
        })
        session["last_score"] = round(score, 2)
        session["total_questions"] = len(questions)
        session.pop("questions", None)
        return redirect("/result")
    return render_template("exam.html", questions=questions, duration=session.get("duration", duration_seconds))

# ── AUTO-SAVE ─────────────────────────────────────────────────────────────────────
@app.route("/autosave", methods=["POST"])
def autosave():
    if "user" not in session:
        return "Unauthorized", 401
    db = get_db()
    answers = request.get_json(force=True, silent=True) or {}
    db.autosave.update_one({"username": session["user"]},
        {"$set": {"answers": answers, "saved_at": now_ist()}}, upsert=True)
    return jsonify({"status": "ok"})

# ── RESULT ────────────────────────────────────────────────────────────────────────
@app.route("/result")
def result():
    if "user" not in session:
        return redirect("/")
    score = session.get("last_score")
    total = session.get("total_questions", 0)
    if score is None:
        db = get_db()
        rec = db.results.find_one({"username": session["user"]}, sort=[("timestamp", -1)])
        if rec:
            score = rec["score"]; total = rec.get("total", 0)
        else:
            return redirect("/")
    return render_template("result.html", score=score, total=total)

# ── SCORE REPORT PDF ──────────────────────────────────────────────────────────────
@app.route("/score_report")
def score_report():
    if "user" not in session:
        return redirect("/")
    db = get_db()
    results = list(db.results.find({"username": session["user"]}).sort("timestamp", -1))
    username = session["user"]
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    pdf = SimpleDocTemplate(output, pagesize=letter)
    content = [
        Paragraph("Score Report", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"Candidate: <b>{username}</b>", styles["Normal"]),
        Paragraph(f"Generated: {now_ist().strftime('%d %B %Y, %H:%M IST')}", styles["Normal"]),
        Spacer(1, 18),
    ]
    table_data = [["#", "Date", "Score", "Total", "Percentage", "Grade"]]
    for i, r in enumerate(results, 1):
        total = r.get("total", 1); score = r.get("score", 0)
        pct = round((score / total) * 100, 1) if total > 0 else 0
        grade = "A" if pct >= 80 else "B" if pct >= 65 else "C" if pct >= 50 else "F"
        ts = r.get("timestamp", now_ist()).strftime("%Y-%m-%d %H:%M")
        table_data.append([str(i), ts, str(score), str(total), f"{pct}%", grade])
    t = Table(table_data, colWidths=[30, 130, 60, 60, 80, 50])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3498db")),
        ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
        ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f2f2f2")]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ("ALIGN",      (2, 0), (-1, -1), "CENTER"),
    ]))
    content.append(t)
    pdf.build(content)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"score_report_{username}.pdf",
                     mimetype="application/pdf")

# ── ADMIN LOGIN ───────────────────────────────────────────────────────────────────
@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == os.environ.get("ADMIN_USERNAME", "admin") and password == os.environ.get("ADMIN_PASSWORD", "admin123"):
            session["admin"] = username
            return redirect("/admin")
        error = "Invalid credentials."
    return render_template("admin_login.html", error=error)

# ── ADMIN DASHBOARD ───────────────────────────────────────────────────────────────
@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    success = None; error = None
    if request.method == "POST":
        q = request.form.get("q", "").strip()
        qtype = request.form.get("qtype", "mcq")
        a = request.form.get("a", "").strip(); b = request.form.get("b", "").strip()
        c = request.form.get("c", "").strip(); d = request.form.get("d", "").strip()
        correct = request.form.get("correct", "").strip().upper()
        subject = request.form.get("subject", "").strip()
        topic   = request.form.get("topic", "").strip()
        difficulty = request.form.get("difficulty", "medium")
        if not q:
            error = "Question text is required."
        elif qtype == "mcq" and (not all([a, b, c, d]) or correct not in ("A","B","C","D")):
            error = "MCQ needs all 4 options and correct answer A/B/C/D."
        elif qtype == "truefalse" and correct not in ("A", "B"):
            error = "True/False correct answer must be A (True) or B (False)."
        else:
            db.questions.insert_one({
                "question": q, "type": qtype,
                "option_a": a if qtype not in ("essay","descriptive","short_answer") else "",
                "option_b": b if qtype not in ("essay","descriptive","short_answer") else "",
                "option_c": c if qtype == "mcq" else "",
                "option_d": d if qtype == "mcq" else "",
                "correct_option": correct if qtype not in ("essay","descriptive","short_answer") else "",
                "subject": subject, "topic": topic, "difficulty": difficulty,
                "created_at": now_ist(),
            })
            success = "Question added successfully!"
    questions = [doc_to_row(d) for d in db.questions.find()]
    results   = list(db.results.find({}, {"_id": 0, "details": 0, "subjective_answers": 0}))
    exams     = list(db.exams.find())
    users     = list(db.users.find({}, {"password": 0}))
    logs      = list(db.logs.find().sort("timestamp", -1).limit(50))
    pending   = list(db.results.find({"pending_grading": True}))
    return render_template("admin.html", questions=questions, results=results,
        exams=exams, users=users, logs=logs, pending_grading=pending,
        success=success, error=error)

# ── CREATE EXAM ───────────────────────────────────────────────────────────────────
@app.route("/admin/create_exam", methods=["GET", "POST"])
def create_exam():
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    success = None; error = None
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        duration = int(request.form.get("duration", 10))
        start_time = request.form.get("start_time", "")
        end_time   = request.form.get("end_time", "")
        enroll_type = request.form.get("enrollment_type", "open")
        subject_filter = request.form.get("subject_filter", "").strip()
        difficulty_filter = request.form.get("difficulty_filter", "").strip()
        if not title:
            error = "Exam title is required."
        else:
            filters = {}
            if subject_filter: filters["subject"] = subject_filter
            if difficulty_filter: filters["difficulty"] = difficulty_filter
            db.exams.insert_one({
                "title": title, "duration_minutes": duration,
                "start_time": datetime.strptime(start_time, "%Y-%m-%dT%H:%M") if start_time else None,
                "end_time": datetime.strptime(end_time, "%Y-%m-%dT%H:%M") if end_time else None,
                "enrollment_type": enroll_type, "filters": filters,
                "status": "active", "created_at": now_ist(),
            })
            success = "Exam created!"
    return render_template("create_exam.html", success=success, error=error)

# ── ENROLL CANDIDATE ──────────────────────────────────────────────────────────────
@app.route("/admin/enroll", methods=["POST"])
def enroll_candidate():
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    exam_id = request.form.get("exam_id", "")
    username = request.form.get("username", "").strip()
    if exam_id and username:
        db.enrollments.update_one({"exam_id": exam_id, "username": username},
            {"$set": {"exam_id": exam_id, "username": username, "enrolled_at": now_ist()}}, upsert=True)
    return redirect("/admin")

# ── MANUAL GRADING ────────────────────────────────────────────────────────────────
@app.route("/admin/grade/<result_id>", methods=["GET", "POST"])
def grade_result(result_id):
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    rec = db.results.find_one({"_id": ObjectId(result_id)})
    if not rec:
        return "Not found", 404
    success = None
    if request.method == "POST":
        subjective_answers = rec.get("subjective_answers", [])
        extra_score = 0.0
        for sa in subjective_answers:
            qid = sa["qid"]
            awarded = request.form.get(f"score_{qid}", "")
            try:
                awarded = float(awarded); sa["score"] = awarded; sa["graded"] = True; extra_score += awarded
            except ValueError:
                pass
        new_score = round(rec["score"] + extra_score, 2)
        db.results.update_one({"_id": ObjectId(result_id)}, {"$set": {
            "subjective_answers": subjective_answers, "score": new_score, "pending_grading": False
        }})
        success = f"Grading saved! Final score: {new_score}"
        rec = db.results.find_one({"_id": ObjectId(result_id)})
    return render_template("grade.html", result=rec, result_id=result_id, success=success)

# ── SEND NOTIFICATION ──────────────────────────────────────────────────────────────
@app.route("/admin/notify", methods=["POST"])
def send_notification():
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    message = request.form.get("message", "").strip()
    target  = request.form.get("target", "all")
    ntype   = request.form.get("ntype", "general")
    if message:
        db.notifications.insert_one({
            "message": message, "target": target, "type": ntype,
            "created_at": now_ist(), "created_by": session["admin"]
        })
    return redirect("/admin")

# ── DELETE QUESTION ───────────────────────────────────────────────────────────────
@app.route("/delete_question/<qid>", methods=["POST"])
def delete_question(qid):
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    try:
        db.questions.delete_one({"_id": ObjectId(qid)})
    except Exception:
        pass
    return redirect("/admin")

# ── DELETE EXAM ───────────────────────────────────────────────────────────────────
@app.route("/admin/delete_exam/<exam_id>", methods=["POST"])
def delete_exam(exam_id):
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    try:
        db.exams.delete_one({"_id": ObjectId(exam_id)})
        # Also remove all enrollments and results linked to this exam
        db.enrollments.delete_many({"exam_id": exam_id})
        db.results.delete_many({"exam_id": exam_id})
    except Exception:
        pass
    return redirect("/admin")

# ── DELETE STUDENT ────────────────────────────────────────────────────────────────
@app.route("/admin/delete_student/<username>", methods=["POST"])
def delete_student(username):
    if "admin" not in session:
        return redirect("/admin_login")
    db = get_db()
    try:
        db.users.delete_one({"username": username})
        # Also remove all related data for this student
        db.results.delete_many({"username": username})
        db.active_sessions.delete_many({"username": username})
        db.enrollments.delete_many({"username": username})
        db.logs.delete_many({"username": username})
        db.autosave.delete_many({"username": username})
    except Exception:
        pass
    return redirect("/admin")

# ── EXPORT EXCEL ──────────────────────────────────────────────────────────────────
@app.route("/export")
def export():
    if "admin" not in session:
        return "Access Denied", 403
    db = get_db()
    data = list(db.results.find({}, {"_id": 0, "details": 0, "subjective_answers": 0}))
    if not data:
        return "No results to export.", 404
    df = pd.DataFrame(data)
    df.rename(columns={"username": "Username", "score": "Score", "total": "Total Questions", "timestamp": "Timestamp"}, inplace=True)
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Results")
    output.seek(0)
    return send_file(output, as_attachment=True, download_name="results.xlsx",
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

# ── CERTIFICATE ───────────────────────────────────────────────────────────────────
@app.route("/certificate")
def certificate():
    if "user" not in session:
        return redirect("/")
    score = session.get("last_score", 0); username = session["user"]
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    pdf = SimpleDocTemplate(output, pagesize=letter)
    content = [
        Paragraph("Certificate of Completion", styles["Title"]),
        Spacer(1, 30),
        Paragraph(f"This is to certify that <b>{username}</b>", styles["Normal"]),
        Spacer(1, 12),
        Paragraph("has successfully completed the <b>Online Examination</b>.", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Score Achieved: <b>{score}</b>", styles["Normal"]),
        Spacer(1, 12),
        Paragraph(f"Date: {now_ist().strftime('%d %B %Y')}", styles["Normal"]),
    ]
    pdf.build(content)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=f"certificate_{username}.pdf",
                     mimetype="application/pdf")

# ── ACTIVITY LOG ──────────────────────────────────────────────────────────────────
@app.route("/log", methods=["POST"])
def log():
    if "user" not in session:
        return "Unauthorized", 401
    db = get_db()
    activity = request.form.get("activity", "unknown")
    db.logs.insert_one({"username": session["user"], "activity": activity,
                        "ip": get_client_ip(), "timestamp": now_ist()})
    return "logged", 200

# ── SESSION TIMEOUT ───────────────────────────────────────────────────────────────
@app.before_request
def check_session_timeout():
    if "user" in session:
        last_active = session.get("last_active")
        timeout = int(os.environ.get("SESSION_TIMEOUT_MINUTES", 30))
        if last_active:
            try:
                last_active_dt = datetime.fromisoformat(last_active)
                # Make naive datetimes timezone-aware (IST) for comparison
                if last_active_dt.tzinfo is None:
                    last_active_dt = last_active_dt.replace(tzinfo=IST)
                if now_ist() - last_active_dt > timedelta(minutes=timeout):
                    try:
                        db = get_db()
                        db.active_sessions.delete_one({"username": session.get("user")})
                    except Exception:
                        pass
                    session.clear()
                    return redirect("/?msg=Session+expired.+Please+login+again.")
            except Exception:
                pass
        session["last_active"] = now_ist().isoformat()

# ── LOGOUT ────────────────────────────────────────────────────────────────────────
@app.route("/logout")
def logout():
    if "user" in session:
        try:
            db = get_db()
            db.active_sessions.delete_one({"username": session["user"]})
        except Exception:
            pass
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    print("Starting Flask server...")
    if not MONGO_URI:
        print("ERROR: MONGO_URI not set in .env")
    else:
        seed_questions()
    app.run(debug=True)
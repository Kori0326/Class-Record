"""
Student Class Record Management System
CC 105 - Information Management | University of Caloocan City

Web-based tool for teachers to manage students, record recitation / activity /
quiz / exam scores, and view midterm, final-term and overall grades.
"""
import os
import secrets
import sqlite3
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "class_record.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# ---------------------------------------------------------------------------
# Grading configuration (edit these to match the teacher's grading policy)
# ---------------------------------------------------------------------------
TERMS = ["midterm", "final"]
CATEGORIES = ["recitation", "activity", "quiz", "exam"]
WEIGHTS = {"recitation": 0.10, "activity": 0.30, "quiz": 0.20, "exam": 0.40}
PASSING_GRADE = 75.0


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS students (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    student_number TEXT NOT NULL UNIQUE,
    last_name      TEXT NOT NULL,
    first_name     TEXT NOT NULL,
    middle_name    TEXT DEFAULT '',
    course         TEXT DEFAULT '',
    year_section   TEXT DEFAULT '',
    email          TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS scores (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
    term       TEXT NOT NULL CHECK (term IN ('midterm', 'final')),
    category   TEXT NOT NULL CHECK (category IN ('recitation', 'activity', 'quiz', 'exam')),
    title      TEXT NOT NULL,
    score      REAL NOT NULL CHECK (score >= 0),
    max_score  REAL NOT NULL CHECK (max_score > 0),
    CHECK (score <= max_score)
);

CREATE INDEX IF NOT EXISTS idx_scores_student ON scores(student_id, term);
"""


def init_db():
    db = sqlite3.connect(DATABASE)
    db.executescript(SCHEMA)
    # Default teacher account (change the password after first login)
    exists = db.execute("SELECT 1 FROM users WHERE username = 'teacher'").fetchone()
    if not exists:
        db.execute(
            "INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)",
            ("teacher", generate_password_hash("teacher123"), "Class Teacher"),
        )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Security: login required + simple CSRF protection
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_from_csrf():
    if request.method == "POST":
        sent = request.form.get("_csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            abort(400, "Invalid or missing security token. Please reload the page.")


# ---------------------------------------------------------------------------
# Grade computation
# ---------------------------------------------------------------------------
def category_percentages(scores):
    """Return {category: percent or None} from a list of score rows."""
    totals = {c: [0.0, 0.0] for c in CATEGORIES}
    for s in scores:
        totals[s["category"]][0] += s["score"]
        totals[s["category"]][1] += s["max_score"]
    return {c: (t[0] / t[1] * 100 if t[1] else None) for c, t in totals.items()}


def term_grade(scores):
    """Weighted term grade. Categories with no scores are excluded and the
    remaining weights are re-normalised so a missing category does not
    unfairly lower the grade. Returns None if there are no scores at all."""
    pct = category_percentages(scores)
    used = {c: p for c, p in pct.items() if p is not None}
    if not used:
        return None
    weight_sum = sum(WEIGHTS[c] for c in used)
    return sum(p * WEIGHTS[c] for c, p in used.items()) / weight_sum


def overall_grade(midterm, final):
    grades = [g for g in (midterm, final) if g is not None]
    return sum(grades) / len(grades) if grades else None


def remark(grade):
    if grade is None:
        return "No grade yet"
    return "Passed" if grade >= PASSING_GRADE else "Failed"


def student_summary(db, student_id):
    rows = db.execute(
        "SELECT * FROM scores WHERE student_id = ?", (student_id,)
    ).fetchall()
    by_term = {t: [r for r in rows if r["term"] == t] for t in TERMS}
    mid = term_grade(by_term["midterm"])
    fin = term_grade(by_term["final"])
    ovr = overall_grade(mid, fin)
    return {
        "midterm": mid,
        "final": fin,
        "overall": ovr,
        "remark": remark(ovr),
        "category_pct": {t: category_percentages(by_term[t]) for t in TERMS},
    }


def fmt(value):
    return "—" if value is None else f"{value:.2f}"


app.jinja_env.filters["fmt"] = fmt


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["full_name"] = user["full_name"]
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//")
                            else url_for("dashboard"))
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    n_students = db.execute("SELECT COUNT(*) FROM students").fetchone()[0]
    n_scores = db.execute("SELECT COUNT(*) FROM scores").fetchone()[0]
    students = db.execute("SELECT id FROM students").fetchall()
    overalls = [student_summary(db, s["id"])["overall"] for s in students]
    graded = [o for o in overalls if o is not None]
    avg = sum(graded) / len(graded) if graded else None
    passing = sum(1 for o in graded if o >= PASSING_GRADE)
    return render_template("dashboard.html", n_students=n_students,
                           n_scores=n_scores, avg=avg, passing=passing,
                           graded=len(graded))


# ---------------------------------------------------------------------------
# Student Management
# ---------------------------------------------------------------------------
@app.route("/students")
@login_required
def students():
    q = request.args.get("q", "").strip()
    db = get_db()
    if q:
        like = f"%{q}%"
        rows = db.execute(
            """SELECT * FROM students
               WHERE last_name LIKE ? OR first_name LIKE ? OR student_number LIKE ?
               ORDER BY last_name, first_name""",
            (like, like, like),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM students ORDER BY last_name, first_name"
        ).fetchall()
    return render_template("students.html", students=rows, q=q)


def read_student_form():
    f = request.form
    data = {k: f.get(k, "").strip() for k in
            ("student_number", "last_name", "first_name", "middle_name",
             "course", "year_section", "email")}
    errors = []
    if not data["student_number"]:
        errors.append("Student number is required.")
    if not data["last_name"] or not data["first_name"]:
        errors.append("First name and last name are required.")
    return data, errors


@app.route("/students/add", methods=["GET", "POST"])
@login_required
def add_student():
    data = {}
    if request.method == "POST":
        data, errors = read_student_form()
        if not errors:
            try:
                db = get_db()
                db.execute(
                    """INSERT INTO students (student_number, last_name, first_name,
                       middle_name, course, year_section, email)
                       VALUES (:student_number, :last_name, :first_name,
                       :middle_name, :course, :year_section, :email)""", data)
                db.commit()
                flash("Student added.", "success")
                return redirect(url_for("students"))
            except sqlite3.IntegrityError:
                errors.append("That student number already exists.")
        for e in errors:
            flash(e, "error")
    return render_template("student_form.html", student=data, mode="Add")


@app.route("/students/<int:sid>/edit", methods=["GET", "POST"])
@login_required
def edit_student(sid):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ?", (sid,)).fetchone()
    if not student:
        abort(404)
    if request.method == "POST":
        data, errors = read_student_form()
        if not errors:
            try:
                data["id"] = sid
                db.execute(
                    """UPDATE students SET student_number=:student_number,
                       last_name=:last_name, first_name=:first_name,
                       middle_name=:middle_name, course=:course,
                       year_section=:year_section, email=:email WHERE id=:id""",
                    data)
                db.commit()
                flash("Student updated.", "success")
                return redirect(url_for("students"))
            except sqlite3.IntegrityError:
                errors.append("That student number already exists.")
        for e in errors:
            flash(e, "error")
        student = data
    return render_template("student_form.html", student=student, mode="Edit")


@app.route("/students/<int:sid>/delete", methods=["POST"])
@login_required
def delete_student(sid):
    db = get_db()
    db.execute("DELETE FROM students WHERE id = ?", (sid,))  # scores cascade
    db.commit()
    flash("Student and their scores were deleted.", "success")
    return redirect(url_for("students"))


# ---------------------------------------------------------------------------
# Academic Record Management (scores)
# ---------------------------------------------------------------------------
def read_score_form():
    f = request.form
    term = f.get("term", "")
    category = f.get("category", "")
    title = f.get("title", "").strip()
    errors = []
    if term not in TERMS:
        errors.append("Choose a valid grading period.")
    if category not in CATEGORIES:
        errors.append("Choose a valid category.")
    if not title:
        errors.append("Title is required (e.g. Quiz 1).")
    try:
        score = float(f.get("score", ""))
        max_score = float(f.get("max_score", ""))
        if max_score <= 0:
            errors.append("Maximum score must be greater than 0.")
        elif score < 0 or score > max_score:
            errors.append("Score must be between 0 and the maximum score.")
    except ValueError:
        score = max_score = 0
        errors.append("Score and maximum score must be numbers.")
    return {"term": term, "category": category, "title": title,
            "score": score, "max_score": max_score}, errors


@app.route("/students/<int:sid>")
@login_required
def student_record(sid):
    db = get_db()
    student = db.execute("SELECT * FROM students WHERE id = ?", (sid,)).fetchone()
    if not student:
        abort(404)
    scores = db.execute(
        "SELECT * FROM scores WHERE student_id = ? ORDER BY term, category, id",
        (sid,)).fetchall()
    summary = student_summary(db, sid)
    return render_template("student_record.html", student=student,
                           scores=scores, summary=summary, terms=TERMS,
                           categories=CATEGORIES, weights=WEIGHTS,
                           passing=PASSING_GRADE)


@app.route("/students/<int:sid>/scores/add", methods=["POST"])
@login_required
def add_score(sid):
    db = get_db()
    if not db.execute("SELECT 1 FROM students WHERE id = ?", (sid,)).fetchone():
        abort(404)
    data, errors = read_score_form()
    if errors:
        for e in errors:
            flash(e, "error")
    else:
        data["student_id"] = sid
        db.execute(
            """INSERT INTO scores (student_id, term, category, title, score, max_score)
               VALUES (:student_id, :term, :category, :title, :score, :max_score)""",
            data)
        db.commit()
        flash("Score recorded.", "success")
    return redirect(url_for("student_record", sid=sid))


@app.route("/scores/<int:score_id>/edit", methods=["GET", "POST"])
@login_required
def edit_score(score_id):
    db = get_db()
    row = db.execute("SELECT * FROM scores WHERE id = ?", (score_id,)).fetchone()
    if not row:
        abort(404)
    if request.method == "POST":
        data, errors = read_score_form()
        if errors:
            for e in errors:
                flash(e, "error")
        else:
            data["id"] = score_id
            db.execute(
                """UPDATE scores SET term=:term, category=:category, title=:title,
                   score=:score, max_score=:max_score WHERE id=:id""", data)
            db.commit()
            flash("Score updated.", "success")
            return redirect(url_for("student_record", sid=row["student_id"]))
    student = db.execute("SELECT * FROM students WHERE id = ?",
                         (row["student_id"],)).fetchone()
    return render_template("score_form.html", score=row, student=student,
                           terms=TERMS, categories=CATEGORIES)


@app.route("/scores/<int:score_id>/delete", methods=["POST"])
@login_required
def delete_score(score_id):
    db = get_db()
    row = db.execute("SELECT student_id FROM scores WHERE id = ?",
                     (score_id,)).fetchone()
    if not row:
        abort(404)
    db.execute("DELETE FROM scores WHERE id = ?", (score_id,))
    db.commit()
    flash("Score deleted.", "success")
    return redirect(url_for("student_record", sid=row["student_id"]))


# ---------------------------------------------------------------------------
# Class Record Viewing
# ---------------------------------------------------------------------------
@app.route("/class-record")
@login_required
def class_record():
    db = get_db()
    students_ = db.execute(
        "SELECT * FROM students ORDER BY last_name, first_name").fetchall()
    rows = [{"student": s, "summary": student_summary(db, s["id"])}
            for s in students_]
    return render_template("class_record.html", rows=rows, passing=PASSING_GRADE)


# ---------------------------------------------------------------------------
# Account: change password (password *recovery* is out of scope per proposal)
# ---------------------------------------------------------------------------
@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    if request.method == "POST":
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?",
                          (session["user_id"],)).fetchone()
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if not check_password_hash(user["password_hash"], current):
            flash("Current password is incorrect.", "error")
        elif len(new) < 8:
            flash("New password must be at least 8 characters.", "error")
        elif new != confirm:
            flash("New passwords do not match.", "error")
        else:
            db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                       (generate_password_hash(new), user["id"]))
            db.commit()
            flash("Password changed.", "success")
            return redirect(url_for("dashboard"))
    return render_template("account.html")


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, message="Page not found."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400,
                           message=getattr(e, "description", "Bad request.")), 400


if __name__ == "__main__":
    init_db()
    app.run(debug=False)
else:
    init_db()

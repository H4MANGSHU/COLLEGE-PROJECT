from __future__ import annotations

import os
import uuid
from contextlib import closing
from datetime import date
from pathlib import Path
from typing import Any

import psycopg
from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_from_directory, session
from psycopg.rows import dict_row
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

ROOT_DIR = Path(__file__).resolve().parent.parent
load_dotenv(ROOT_DIR / ".env", override=True)

UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

app = Flask("paperhub", static_folder=None)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "paperhub-dev-secret-key")


def connect_to_database():
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise psycopg.OperationalError("DATABASE_URL is not configured.")

    config: dict[str, Any] = {
        "row_factory": dict_row,
        "connect_timeout": 5,
    }
    ca_certificate = os.environ.get("AIVEN_CA_CERT") or os.environ.get("PGSSLROOTCERT")
    default_ca_certificate = Path(__file__).with_name("aiven-ca.pem")
    if ca_certificate:
        config["sslrootcert"] = ca_certificate
        config["sslmode"] = "verify-full"
    elif default_ca_certificate.is_file():
        config["sslrootcert"] = str(default_ca_certificate)
        config["sslmode"] = "verify-full"

    return psycopg.connect(database_url, **config)


def get_user_db():
    return connect_to_database()


def get_papers_db():
    return connect_to_database()


def fetch_one(connection, query: str, params: tuple[Any, ...] = ()):
    cursor = connection.cursor()
    try:
        cursor.execute(query, params)
        return cursor.fetchone()
    finally:
        cursor.close()


def fetch_all(connection, query: str, params: tuple[Any, ...] = ()):
    cursor = connection.cursor()
    try:
        cursor.execute(query, params)
        return cursor.fetchall()
    finally:
        cursor.close()


def execute_write(connection, query: str, params: tuple[Any, ...] = ()):
    cursor = connection.cursor()
    try:
        cursor.execute(query, params)
        row = cursor.fetchone() if cursor.description else None
        return (row["id"] if row else None), cursor.rowcount
    finally:
        cursor.close()


@app.errorhandler(psycopg.Error)
def handle_database_error(error: psycopg.Error):
    app.logger.error("PostgreSQL request failed: %s", error, exc_info=True)
    return jsonify({"message": "PostgreSQL is unavailable or its schema is not initialized."}), 503


def serialize_user(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user.get("email"),
        "phone": user.get("phone"),
        "dob": user.get("dob"),
        "role": user.get("role"),
    }


def get_user_by_username(username: str) -> dict[str, Any] | None:
    with closing(get_user_db()) as connection:
        return fetch_one(
            connection,
            """
            SELECT id, username, password_hash, email, phone, dob, role
            FROM users
            WHERE LOWER(username) = LOWER(%s)
            """,
            (username,),
        )


def get_user_profile() -> dict[str, Any] | None:
    username = session.get("username")
    if not username:
        return None
    user = get_user_by_username(username)
    return serialize_user(user) if user else None


def get_papers() -> list[dict[str, Any]]:
    with closing(get_papers_db()) as connection:
        return fetch_all(
            connection,
            """
            SELECT id, title, department, exam_type, subject_code, subject_name,
                   semester, exam_year, file_type, file_path_or_url, uploaded_by
            FROM papers
            ORDER BY id
            """,
        )


def get_paper_by_id(paper_id: int) -> dict[str, Any] | None:
    with closing(get_papers_db()) as connection:
        return fetch_one(
            connection,
            """
            SELECT id, title, department, exam_type, subject_code, subject_name,
                   semester, exam_year, file_type, file_path_or_url, uploaded_by
            FROM papers
            WHERE id = %s
            """,
            (paper_id,),
        )


@app.get("/")
def index():
    return send_from_directory(ROOT_DIR, "index.html")


@app.get("/static/css/style.css")
def serve_stylesheet():
    return send_from_directory(ROOT_DIR, "styles.css")


@app.get("/static/js/app.js")
def serve_frontend_script():
    return send_from_directory(ROOT_DIR, "app.js")


@app.get("/uploads/<path:filename>")
def uploaded_file(filename: str):
    return send_from_directory(UPLOAD_DIR, filename)


@app.get("/api/health")
def health_check():
    with closing(get_user_db()) as connection:
        fetch_one(connection, "SELECT 1")
    with closing(get_papers_db()) as connection:
        fetch_one(connection, "SELECT 1")
    return jsonify({"status": "ok", "database": "postgresql"})


@app.get("/api/auth/session")
def auth_session():
    user = get_user_profile()
    if not user:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, **user})


@app.post("/api/auth/login")
def login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    if not username or not password:
        return jsonify({"message": "Username and password are required."}), 400

    user = get_user_by_username(username)
    if not user or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "Invalid username or password."}), 401

    session["username"] = user["username"]
    session["role"] = user["role"]
    return jsonify({"message": "Login successful.", **serialize_user(user)})


@app.post("/api/auth/admin-login")
def admin_login():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""

    user = get_user_by_username(username) if username else None
    if not user or user["role"] != "admin" or not check_password_hash(user["password_hash"], password):
        return jsonify({"message": "Invalid admin credentials."}), 401

    session["username"] = user["username"]
    session["role"] = user["role"]
    return jsonify({"message": "Admin login successful.", **serialize_user(user)})


@app.post("/api/auth/register")
def register():
    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip()
    phone = (request.form.get("phone") or "").strip()
    dob_text = request.form.get("dob") or ""
    password = request.form.get("password") or ""

    if not all([username, email, phone, dob_text, password]):
        return jsonify({"message": "Please fill in all fields."}), 400
    if len(password) < 6:
        return jsonify({"message": "Password must be at least 6 characters long."}), 400
    try:
        dob = date.fromisoformat(dob_text)
    except ValueError:
        return jsonify({"message": "Please provide a valid date of birth."}), 400

    try:
        with closing(get_user_db()) as connection:
            user_id, _ = execute_write(
                connection,
                """
                INSERT INTO users (username, password_hash, email, phone, dob, role)
                VALUES (%s, %s, %s, %s, %s, 'student')
                RETURNING id
                """,
                (username, generate_password_hash(password, method="scrypt"), email, phone, dob),
            )
            connection.commit()
            user = fetch_one(
                connection,
                "SELECT id, username, email, phone, dob, role FROM users WHERE id = %s",
                (user_id,),
            )
    except psycopg.IntegrityError:
        return jsonify({"message": "Username or email already exists."}), 409

    session["username"] = user["username"]
    session["role"] = user["role"]
    return jsonify({"message": "Registration successful.", **serialize_user(user)})


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"message": "Signed out successfully."})


@app.get("/api/papers")
def list_papers():
    papers = get_papers()
    search = (request.args.get("search") or "").strip().lower()
    department = (request.args.get("department") or "").strip()
    exam_type = (request.args.get("exam_type") or "").strip()
    semester = (request.args.get("semester") or "").strip()
    year = (request.args.get("year") or "").strip()
    username = session.get("username")

    filtered = []
    for paper in papers:
        if search and search not in f"{paper['title']} {paper['subject_name']} {paper['subject_code']}".lower():
            continue
        if department and paper["department"] != department:
            continue
        if exam_type and paper["exam_type"] != exam_type:
            continue
        if semester and str(paper["semester"]) != semester:
            continue
        if year and str(paper["exam_year"]) != year:
            continue
        if session.get("role") == "admin" and paper["uploaded_by"] != username:
            continue
        filtered.append(paper)

    return jsonify({"papers": filtered})


@app.post("/api/papers/add")
def add_paper():
    if session.get("role") != "admin":
        return jsonify({"message": "Only admins can upload papers."}), 403

    title = (request.form.get("title") or "").strip()
    department = (request.form.get("department") or "").strip()
    exam_type = (request.form.get("exam_type") or "").strip()
    subject_code = (request.form.get("subject_code") or "").strip()
    subject_name = (request.form.get("subject_name") or "").strip()
    semester_text = request.form.get("semester") or ""
    year_text = request.form.get("exam_year") or ""
    upload_type = request.form.get("upload_type") or "link"

    if not all([title, department, exam_type, subject_code, subject_name, semester_text, year_text]):
        return jsonify({"message": "Missing required paper information."}), 400
    if exam_type not in {"Internal Theory", "Internal Lab", "Sessional Theory", "Sessional Lab"}:
        return jsonify({"message": "Invalid exam type."}), 400
    try:
        semester = int(semester_text)
        exam_year = int(year_text)
    except ValueError:
        return jsonify({"message": "Semester and exam year must be numbers."}), 400
    if semester < 1 or semester > 8 or exam_year < 2000 or exam_year > 2099:
        return jsonify({"message": "Semester or exam year is out of range."}), 400

    saved_path: Path | None = None
    if upload_type == "file":
        pdf_file = request.files.get("pdf_file")
        filename = secure_filename(pdf_file.filename or "") if pdf_file else ""
        if not filename.lower().endswith(".pdf"):
            return jsonify({"message": "Please select a PDF file."}), 400
        file_value = f"{uuid.uuid4().hex}_{filename}"
        saved_path = UPLOAD_DIR / file_value
        pdf_file.save(saved_path)
        file_type = "direct_upload"
    elif upload_type == "link":
        file_value = (request.form.get("pdf_url") or "").strip()
        if not file_value:
            return jsonify({"message": "Please provide a PDF link."}), 400
        file_type = "external_link"
    else:
        return jsonify({"message": "Invalid upload type."}), 400

    try:
        with closing(get_papers_db()) as connection:
            paper_id, _ = execute_write(
                connection,
                """
                INSERT INTO papers (
                    title, department, exam_type, subject_code, subject_name,
                    semester, exam_year, file_type, file_path_or_url, uploaded_by
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    title,
                    department,
                    exam_type,
                    subject_code,
                    subject_name,
                    semester,
                    exam_year,
                    file_type,
                    file_value,
                    session["username"],
                ),
            )
            connection.commit()
            paper = get_paper_by_id(paper_id)
    except psycopg.Error:
        if saved_path and saved_path.exists():
            saved_path.unlink()
        raise

    return jsonify({"message": "Paper uploaded successfully.", "paper": paper})


@app.post("/api/papers/update/<int:paper_id>")
def update_paper(paper_id: int):
    if session.get("role") != "admin":
        return jsonify({"message": "Only admins can edit papers."}), 403

    paper = get_paper_by_id(paper_id)
    if not paper:
        return jsonify({"message": "Paper not found."}), 404
    if paper["uploaded_by"] != session.get("username"):
        return jsonify({"message": "You can only edit your own uploaded papers."}), 403

    title = (request.form.get("title") or paper["title"]).strip()
    department = (request.form.get("department") or paper["department"]).strip()
    exam_type = (request.form.get("exam_type") or paper["exam_type"]).strip()
    subject_code = (request.form.get("subject_code") or paper["subject_code"]).strip()
    subject_name = (request.form.get("subject_name") or paper["subject_name"]).strip()
    try:
        semester = int(request.form.get("semester") or paper["semester"])
        exam_year = int(request.form.get("exam_year") or paper["exam_year"])
    except ValueError:
        return jsonify({"message": "Semester and exam year must be numbers."}), 400
    if not all([title, department, exam_type, subject_code, subject_name]):
        return jsonify({"message": "Paper information cannot be empty."}), 400
    if exam_type not in {"Internal Theory", "Internal Lab", "Sessional Theory", "Sessional Lab"}:
        return jsonify({"message": "Invalid exam type."}), 400
    if semester < 1 or semester > 8 or exam_year < 2000 or exam_year > 2099:
        return jsonify({"message": "Semester or exam year is out of range."}), 400

    with closing(get_papers_db()) as connection:
        execute_write(
            connection,
            """
            UPDATE papers
            SET title = %s, department = %s, exam_type = %s, subject_code = %s,
                subject_name = %s, semester = %s, exam_year = %s
            WHERE id = %s
            """,
            (title, department, exam_type, subject_code, subject_name, semester, exam_year, paper_id),
        )
        connection.commit()
    updated_paper = get_paper_by_id(paper_id)
    return jsonify({"message": "Paper updated successfully.", "paper": updated_paper})


@app.delete("/api/papers/delete/<int:paper_id>")
def delete_paper(paper_id: int):
    if session.get("role") != "admin":
        return jsonify({"message": "Only admins can delete papers."}), 403

    paper = get_paper_by_id(paper_id)
    if not paper:
        return jsonify({"message": "Paper not found."}), 404
    if paper["uploaded_by"] != session.get("username"):
        return jsonify({"message": "You can only delete your own uploaded papers."}), 403

    with closing(get_papers_db()) as connection:
        execute_write(connection, "DELETE FROM papers WHERE id = %s", (paper_id,))
        connection.commit()
    return jsonify({"message": "Paper deleted successfully."})


@app.route("/<path:path>")
def serve_path(path: str):
    candidate = (ROOT_DIR / path).resolve()
    if candidate.is_file() and candidate.parent == ROOT_DIR:
        return send_from_directory(ROOT_DIR, path)
    return index()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG", "").lower() in {"1", "true", "yes"}
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=debug)

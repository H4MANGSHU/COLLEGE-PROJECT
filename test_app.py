import unittest
from pathlib import Path
from unittest.mock import patch

import app as backend
from werkzeug.security import check_password_hash


class AppRouteTests(unittest.TestCase):
    def setUp(self):
        backend.app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = backend.app.test_client()
        self.paper = {
            "id": 1,
            "title": "Sample paper",
            "department": "BCA",
            "exam_type": "Internal Theory",
            "subject_code": "BCA401",
            "subject_name": "Databases",
            "semester": 4,
            "exam_year": 2026,
            "uploaded_by": "admin1",
        }
        with self.client.session_transaction() as session:
            session["username"] = "admin1"
            session["role"] = "admin"

    def test_update_rejects_invalid_exam_type(self):
        with patch.object(backend, "get_paper_by_id", return_value=self.paper):
            response = self.client.post(
                "/api/papers/update/1",
                data={"exam_type": "Invalid"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["message"], "Invalid exam type.")

    def test_update_rejects_out_of_range_semester(self):
        with patch.object(backend, "get_paper_by_id", return_value=self.paper):
            response = self.client.post(
                "/api/papers/update/1",
                data={"semester": "9"},
            )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.get_json()["message"],
            "Semester or exam year is out of range.",
        )

    def test_backend_source_is_not_served_as_a_static_file(self):
        response = self.client.get("/backend/app.py")
        self.addCleanup(response.close)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b"import psycopg", response.data)
        self.assertIn(b"<!DOCTYPE html>", response.data)

    def test_application_uses_aiven_ca_with_hostname_verification(self):
        with patch.dict(
            "os.environ",
            {
                "DATABASE_URL": "postgresql://test@db.example.com/defaultdb",
                "AIVEN_CA_CERT": "C:\\certs\\aiven-ca.pem",
            },
        ), patch.object(backend.psycopg, "connect") as connect:
            backend.connect_to_database()

        connect.assert_called_once_with(
            "postgresql://test@db.example.com/defaultdb",
            row_factory=backend.dict_row,
            connect_timeout=5,
            sslrootcert="C:\\certs\\aiven-ca.pem",
            sslmode="verify-full",
        )

    def test_application_name_is_paperhub(self):
        self.assertEqual(backend.app.name, "paperhub")

    def test_demo_student_seed_hash_matches_displayed_password(self):
        schema_path = Path(backend.__file__).with_name("schema.sql")
        seed = next(
            line
            for line in schema_path.read_text(encoding="utf-8").splitlines()
            if "'student_john'" in line
        )
        stored_hash = seed.split("'")[3]

        self.assertTrue(check_password_hash(stored_hash, "password123"))


if __name__ == "__main__":
    unittest.main()

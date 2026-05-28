from __future__ import annotations

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from auth.login import login_user
from auth.otp import start_email_otp, verify_email_otp
from auth.register import register_user
import database.database as db


class AuthFlowTests(unittest.TestCase):
    def test_registered_user_can_login_with_same_credentials(self) -> None:
        old_values = {
            "DATA_DIR": db.DATA_DIR,
            "LOG_DIR": db.LOG_DIR,
            "REPORT_DIR": db.REPORT_DIR,
            "DB_PATH": db.DB_PATH,
        }

        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                db.DATA_DIR = root / "data"
                db.LOG_DIR = root / "logs"
                db.REPORT_DIR = root / "reports"
                db.DB_PATH = db.DATA_DIR / "phishguard.db"

                created, create_msg = register_user("newuser@example.com", "StrongPass123", role="standard_user")
                self.assertTrue(created, create_msg)

                logged_in, user, login_msg = login_user("newuser@example.com", "StrongPass123")
                self.assertTrue(logged_in, login_msg)
                self.assertIsNotNone(user)
                self.assertEqual(user["role"], "admin")

                created_second, create_second_msg = register_user("second@example.com", "StrongPass123", role="admin")
                self.assertTrue(created_second, create_second_msg)
                logged_in_second, second_user, second_login_msg = login_user("second@example.com", "StrongPass123")
                self.assertTrue(logged_in_second, second_login_msg)
                self.assertIsNotNone(second_user)
                self.assertEqual(second_user["role"], "standard_user")

                duplicate, duplicate_msg = register_user("newuser@example.com", "StrongPass123", role="standard_user")
                self.assertFalse(duplicate, duplicate_msg)
        finally:
            db.DATA_DIR = old_values["DATA_DIR"]
            db.LOG_DIR = old_values["LOG_DIR"]
            db.REPORT_DIR = old_values["REPORT_DIR"]
            db.DB_PATH = old_values["DB_PATH"]

    def test_email_otp_verifies_sent_code(self) -> None:
        sent: dict[str, str] = {}

        def capture_email(email: str, code: str) -> None:
            sent["email"] = email
            sent["code"] = code

        with patch("auth.otp.send_otp_email", side_effect=capture_email):
            challenge = start_email_otp("newuser@example.com")

        self.assertEqual(sent["email"], "newuser@example.com")
        ok, msg = verify_email_otp(challenge, sent["code"])
        self.assertTrue(ok, msg)


if __name__ == "__main__":
    unittest.main()

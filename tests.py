"""
Unit tests for the phishing detector.
Run:  python -m pytest tests.py -v
      python tests.py
"""

import unittest
from detector import PhishingDetector, EmailData


class TestPhishingDetector(unittest.TestCase):

    def setUp(self):
        self.d = PhishingDetector()

    # ── Verdicts ─────────────────────────────────────────────────────────────

    def test_clean_email_is_safe(self):
        email = EmailData(
            sender="newsletter@github.com",
            subject="Your monthly summary",
            body="Hi Alex, here is your activity summary. Visit https://github.com/explore",
        )
        result = self.d.analyze(email)
        self.assertEqual(result.verdict, "safe")

    def test_obvious_phish_detected(self):
        email = EmailData(
            sender="support@paypa1-secure.tk",
            subject="URGENT: Your Account Has Been Suspended!",
            body=(
                "Dear Valued Customer, your account has been suspended due to "
                "unauthorized access. Verify your account immediately to avoid "
                "permanent suspension. Act now — 24 hours. Kindly re-enter your "
                "password and billing information: https://bit.ly/verify-now"
            ),
        )
        result = self.d.analyze(email)
        self.assertIn(result.verdict, ("likely_phishing", "phishing"))

    def test_lottery_scam_detected(self):
        email = EmailData(
            sender="prize@freegifts.ml",
            subject="YOU HAVE WON",
            body="Congratulations! You have won one million dollars. Send your bank account details and SSN.",
            attachments=["claim.exe"],
        )
        result = self.d.analyze(email)
        self.assertIn(result.verdict, ("likely_phishing", "phishing"))

    # ── Individual flags ──────────────────────────────────────────────────────

    def test_urgency_flag(self):
        email = EmailData(body="Act now! Your account will expire in 24 hours. Action required.")
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("Urgency Language", categories)

    def test_credential_flag(self):
        email = EmailData(body="Please enter your password and verify your account details here.")
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("Credential Harvesting", categories)

    def test_dangerous_attachment_flag(self):
        email = EmailData(body="Please open the file.", attachments=["invoice.exe", "report.zip"])
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("Dangerous Attachment", categories)

    def test_url_shortener_flag(self):
        email = EmailData(body="Click here: https://bit.ly/some-link")
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("URL Shorteners", categories)

    def test_ip_url_flagged(self):
        email = EmailData(body="Visit: http://192.168.1.1/login")
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("Suspicious URLs", categories)

    def test_all_caps_subject_flagged(self):
        email = EmailData(subject="URGENT ACTION REQUIRED NOW", body="Please respond.")
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("ALL CAPS Subject", categories)

    def test_poor_grammar_flagged(self):
        email = EmailData(body="Dear valued customer, kindly click the link and do the needful.")
        result = self.d.analyze(email)
        categories = [f[0] for f in result.flags]
        self.assertIn("Poor Grammar Patterns", categories)

    # ── Score sanity ──────────────────────────────────────────────────────────

    def test_score_is_non_negative(self):
        email = EmailData(body="Hello world.")
        result = self.d.analyze(email)
        self.assertGreaterEqual(result.score, 0)

    def test_confidence_between_0_and_1(self):
        email = EmailData(body="Send your bank account details now or your account will be suspended!")
        result = self.d.analyze(email)
        self.assertGreaterEqual(result.confidence, 0.0)
        self.assertLessEqual(result.confidence, 1.0)

    def test_phish_scores_higher_than_clean(self):
        clean = EmailData(
            sender="updates@github.com",
            subject="Your activity this week",
            body="Hi, here are your GitHub notifications.",
        )
        phish = EmailData(
            sender="noreply@paypa1-secure.tk",
            subject="URGENT: Verify your account now!!!",
            body=(
                "Dear valued customer, your account has been suspended due to unauthorized access. "
                "Verify immediately or it will be deleted. Kindly enter your password: "
                "https://bit.ly/verify123"
            ),
        )
        clean_result = self.d.analyze(clean)
        phish_result = self.d.analyze(phish)
        self.assertGreater(phish_result.score, clean_result.score)


if __name__ == "__main__":
    unittest.main(verbosity=2)

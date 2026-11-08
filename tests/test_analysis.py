import unittest
from types import SimpleNamespace

import app


class ThreatScoringTests(unittest.TestCase):
    def test_legitimate_google_domain_not_flagged(self):
        score, findings = app.url_analysis("https://www.google.com/", "www.google.com")
        self.assertFalse(any("brand-name impersonation" in f["title"].lower() for f in findings))

    def test_google_in_unrelated_domain_is_flagged(self):
        score, findings = app.url_analysis("https://google.fake-domain.com/", "google.fake-domain.com")
        self.assertTrue(any("brand-name impersonation" in f["title"].lower() for f in findings))

    def test_403_is_limited_inspection_not_header_risk(self):
        response = SimpleNamespace(headers={}, status_code=403)
        score, findings, status = app.header_analysis(response)
        self.assertEqual(score, 0)
        self.assertIn("Limited security-header assessment", [f["title"] for f in findings])

    def test_missing_headers_have_small_cap(self):
        response = SimpleNamespace(headers={}, status_code=200)
        score, findings, status = app.header_analysis(response)
        self.assertEqual(score, 5)
        self.assertTrue(all(f["severity"] == "low" for f in findings))


if __name__ == "__main__":
    unittest.main()

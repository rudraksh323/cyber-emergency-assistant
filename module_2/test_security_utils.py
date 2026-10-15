"""Tests for Module 2 URL analysis and helper functions."""

import unittest

from module_2.security_utils import check_url, edit_distance, format_url_result


class EditDistanceTests(unittest.TestCase):
    def test_equal_values_have_zero_distance(self):
        self.assertEqual(edit_distance("paypal", "paypal"), 0)

    def test_single_character_typo_has_distance_one(self):
        self.assertEqual(edit_distance("paypa1", "paypal"), 1)


class UrlCheckerTests(unittest.TestCase):
    def test_normal_https_url_is_safe(self):
        result = check_url("https://google.com")
        self.assertEqual(result["level"], "SAFE")
        self.assertEqual(result["score"], 0)

    def test_missing_scheme_is_treated_as_http(self):
        result = check_url("example.com")
        self.assertEqual(result["level"], "SAFE")
        self.assertEqual(result["score"], 1)
        self.assertIn("does not use HTTPS", result["reasons"])

    def test_raw_ip_with_login_words_is_dangerous(self):
        result = check_url("http://192.0.2.1/login/verify-account")
        self.assertEqual(result["level"], "DANGEROUS")
        self.assertGreaterEqual(result["score"], 5)

    def test_brand_typo_is_dangerous(self):
        result = check_url("http://paypa1.xyz/verify")
        self.assertEqual(result["level"], "DANGEROUS")
        self.assertTrue(any("misspelled 'paypal'" in reason for reason in result["reasons"]))

    def test_invalid_url_is_dangerous(self):
        result = check_url("https://")
        self.assertEqual(result["level"], "DANGEROUS")

    def test_result_formatter_includes_reasons(self):
        output = format_url_result(check_url("http://example.com/login"))
        self.assertIn("SUSPICIOUS", output)
        self.assertIn("login", output)


if __name__ == "__main__":
    unittest.main()

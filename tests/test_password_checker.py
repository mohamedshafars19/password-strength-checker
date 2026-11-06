"""Unit tests for password_checker module."""

import unittest
import sys
import os

# Add root directory to sys.path so tests can import password_checker
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from password_checker import (
    check_password_strength,
    has_repeated_characters,
    has_sequential_characters,
    is_common_password,
)


class TestPasswordChecker(unittest.TestCase):
    """Test suite verifying validation logic and security heuristics."""

    def test_empty_input(self):
        """Empty input should result in zero score and 'Waiting for input' status."""
        result = check_password_strength("")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["strength"], "Waiting for input")
        self.assertFalse(result["is_acceptable"])
        self.assertFalse(any(result["requirements"].values()))

    def test_none_or_non_string_input(self):
        """None or non-string inputs should be handled gracefully without exceptions."""
        result_none = check_password_strength(None)
        self.assertEqual(result_none["score"], 0)
        self.assertEqual(result_none["strength"], "Waiting for input")

        result_int = check_password_strength(12345678)
        self.assertTrue(result_int["requirements"]["digit"])
        self.assertTrue(result_int["requirements"]["length"])
        self.assertFalse(result_int["requirements"]["uppercase"])

    def test_shorter_than_8_characters(self):
        """Passwords shorter than 8 chars fail length condition and cannot be Excellent."""
        result = check_password_strength("Ab1!xyz")  # 7 chars
        self.assertFalse(result["requirements"]["length"])
        self.assertTrue(result["requirements"]["uppercase"])
        self.assertTrue(result["requirements"]["lowercase"])
        self.assertTrue(result["requirements"]["digit"])
        self.assertTrue(result["requirements"]["special"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_missing_uppercase(self):
        """Password missing uppercase letter."""
        result = check_password_strength("lowercase1!")
        self.assertFalse(result["requirements"]["uppercase"])
        self.assertTrue(result["requirements"]["length"])
        self.assertTrue(result["requirements"]["lowercase"])
        self.assertTrue(result["requirements"]["digit"])
        self.assertTrue(result["requirements"]["special"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_missing_lowercase(self):
        """Password missing lowercase letter."""
        result = check_password_strength("UPPERCASE1!")
        self.assertFalse(result["requirements"]["lowercase"])
        self.assertTrue(result["requirements"]["length"])
        self.assertTrue(result["requirements"]["uppercase"])
        self.assertTrue(result["requirements"]["digit"])
        self.assertTrue(result["requirements"]["special"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_missing_number(self):
        """Password missing digit."""
        result = check_password_strength("NoNumberSpecial!")
        self.assertFalse(result["requirements"]["digit"])
        self.assertTrue(result["requirements"]["length"])
        self.assertTrue(result["requirements"]["uppercase"])
        self.assertTrue(result["requirements"]["lowercase"])
        self.assertTrue(result["requirements"]["special"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_missing_special_character(self):
        """Password missing special symbol."""
        result = check_password_strength("NoSpecialChar123")
        self.assertFalse(result["requirements"]["special"])
        self.assertTrue(result["requirements"]["length"])
        self.assertTrue(result["requirements"]["uppercase"])
        self.assertTrue(result["requirements"]["lowercase"])
        self.assertTrue(result["requirements"]["digit"])
        self.assertEqual(result["score"], 4)
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_repeated_character_patterns(self):
        """Password with 3 or more repeated identical characters."""
        self.assertTrue(has_repeated_characters("aaa"))
        self.assertTrue(has_repeated_characters("Passs123!"))
        self.assertTrue(has_repeated_characters("11123456"))
        self.assertFalse(has_repeated_characters("K9#mQ2$vL5!x"))

        result = check_password_strength("Aaaabb12!#")
        self.assertTrue(result["security_checks"]["has_repeated"])
        # Even with all 5 criteria, repeated pattern downgrades to Good
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_sequential_character_patterns(self):
        """Password with sequential letters, numbers, or keyboard runs."""
        self.assertTrue(has_sequential_characters("abc"))
        self.assertTrue(has_sequential_characters("123"))
        self.assertTrue(has_sequential_characters("cba"))
        self.assertTrue(has_sequential_characters("qwerty"))
        self.assertFalse(has_sequential_characters("k9mQ2vL5x"))

        result = check_password_strength("Abc12345!#")
        self.assertTrue(result["security_checks"]["has_sequential"])
        self.assertEqual(result["strength"], "Good")
        self.assertFalse(result["is_acceptable"])

    def test_common_weak_passwords(self):
        """Known weak passwords must be detected and marked Weak."""
        self.assertTrue(is_common_password("password"))
        self.assertTrue(is_common_password("Password123!"))
        self.assertTrue(is_common_password("admin12345"))
        self.assertTrue(is_common_password("12345678"))

        result = check_password_strength("Password123!")
        self.assertTrue(result["security_checks"]["is_common"])
        self.assertEqual(result["strength"], "Weak")
        self.assertEqual(result["legacy_strength"], "POOR ❌")
        self.assertFalse(result["is_acceptable"])

    def test_satisfying_all_original_requirements(self):
        """A strong password meeting all 5 requirements with no bad patterns is Excellent."""
        result = check_password_strength("K9#mQ2$vL5!x")
        self.assertEqual(result["score"], 5)
        self.assertTrue(result["requirements"]["length"])
        self.assertTrue(result["requirements"]["uppercase"])
        self.assertTrue(result["requirements"]["lowercase"])
        self.assertTrue(result["requirements"]["digit"])
        self.assertTrue(result["requirements"]["special"])
        self.assertTrue(result["requirements"]["length_12"])
        self.assertFalse(result["security_checks"]["is_common"])
        self.assertFalse(result["security_checks"]["has_repeated"])
        self.assertFalse(result["security_checks"]["has_sequential"])
        self.assertEqual(result["strength"], "Excellent")
        self.assertEqual(result["legacy_strength"], "EXCELLENT ✅")
        self.assertTrue(result["is_acceptable"])

    def test_poor_classification_score_under_3(self):
        """Passwords satisfying <= 2 requirements are Weak / POOR."""
        result = check_password_strength("short")
        self.assertLessEqual(result["score"], 2)
        self.assertEqual(result["strength"], "Weak")
        self.assertEqual(result["legacy_strength"], "POOR ❌")


if __name__ == "__main__":
    unittest.main()


"""Password Strength Checker Module.

Provides robust password validation, strength scoring, security heuristics,
and actionable improvement recommendations.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

# Step 1: Base Password Rules (preserved from original project)
RULES: tuple[str, ...] = (
    "Minimum 8 characters",
    "At least one uppercase letter",
    "At least one lowercase letter",
    "At least one digit",
    "At least one special character",
)

# Standard special characters (preserving and standardizing original set)
SPECIAL_CHARACTERS: Set[str] = set("!@#$%^&*()_+-=[]{}|;:',.<>?/`~\"\\")

# Common weak passwords list for local detection
COMMON_WEAK_PASSWORDS: Set[str] = {
    "password",
    "password123",
    "password1",
    "password!",
    "password123!",
    "123456",
    "12345678",
    "123456789",
    "1234567890",
    "qwerty",
    "qwerty123",
    "admin",
    "admin123",
    "admin12345",
    "welcome",
    "welcome123",
    "letmein",
    "letmein123",
    "iloveyou",
    "iloveyou123",
    "monkey",
    "monkey123",
    "dragon",
    "dragon123",
    "master",
    "master123",
    "sunshine",
    "sunshine1",
    "princess",
    "princess1",
    "football",
    "football1",
    "charlie",
    "charlie12",
    "trustno1",
    "abc12345",
    "passw0rd",
    "p@ssword",
    "p@ssw0rd",
    "secret123",
    "login123",
    "default123",
    "changeme",
    "changeme123",
}


def is_common_password(password: str) -> bool:
    """Check if the password matches a known common weak password."""
    if not password:
        return False
    normalized = password.strip().lower()
    return normalized in COMMON_WEAK_PASSWORDS


def has_repeated_characters(password: str, threshold: int = 3) -> bool:
    """Detect consecutive identical characters of length >= threshold (case-insensitive)."""
    if not password or len(password) < threshold:
        return False
    lower = password.lower()
    count = 1
    for i in range(1, len(lower)):
        if lower[i] == lower[i - 1]:
            count += 1
            if count >= threshold:
                return True
        else:
            count = 1
    return False


def has_sequential_characters(password: str, threshold: int = 3) -> bool:
    """Detect ascending or descending sequential patterns (letters, digits, keyboard)."""
    if not password or len(password) < threshold:
        return False
    lower = password.lower()

    # Check ascending / descending sequences in consecutive character windows
    for i in range(len(lower) - threshold + 1):
        window = lower[i : i + threshold]

        # Numeric sequences (e.g. 123, 321, 789)
        if window.isdigit():
            diffs = [int(window[j + 1]) - int(window[j]) for j in range(threshold - 1)]
            if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
                return True

        # Alphabetical sequences (e.g. abc, cba, xyz)
        elif window.isalpha() and window.isascii():
            ords = [ord(c) for c in window]
            diffs = [ords[j + 1] - ords[j] for j in range(threshold - 1)]
            if all(d == 1 for d in diffs) or all(d == -1 for d in diffs):
                return True

    # Common keyboard sequences
    keyboard_sequences = ["qwerty", "asdfgh", "zxcvbn"]
    for seq in keyboard_sequences:
        for i in range(len(seq) - threshold + 1):
            sub = seq[i : i + threshold]
            if sub in lower or sub[::-1] in lower:
                return True

    return False


def get_recommendations(
    requirements: Dict[str, bool],
    security_checks: Dict[str, bool],
    score: int,
) -> List[str]:
    """Generate clear, actionable recommendations based on validation checks."""
    recommendations: List[str] = []

    # Criteria recommendations
    if not requirements.get("length", False):
        recommendations.append("Make your password at least 8 characters long.")
    if not requirements.get("uppercase", False):
        recommendations.append("Include at least one uppercase letter (A-Z).")
    if not requirements.get("lowercase", False):
        recommendations.append("Include at least one lowercase letter (a-z).")
    if not requirements.get("digit", False):
        recommendations.append("Add at least one numeric digit (0-9).")
    if not requirements.get("special", False):
        recommendations.append("Include at least one special character (!@#$%^&*...).")

    # Security heuristic warnings
    if security_checks.get("is_common", False):
        recommendations.append(
            "This password is very common and easily guessed. Choose a more unique phrase."
        )
    if security_checks.get("has_repeated", False):
        recommendations.append(
            "Avoid repeating identical characters 3 or more times (e.g. 'aaa' or '111')."
        )
    if security_checks.get("has_sequential", False):
        recommendations.append(
            "Avoid sequential patterns (e.g. '123', 'abc', or keyboard rows)."
        )

    # Positive length suggestion if all base criteria met
    if (
        score == 5
        and not requirements.get("length_12", False)
        and not security_checks.get("has_repeated", False)
        and not security_checks.get("has_sequential", False)
        and not security_checks.get("is_common", False)
    ):
        recommendations.append(
            "Consider extending to 12+ characters for enhanced security."
        )

    return recommendations


def check_password_strength(password: Any) -> Dict[str, Any]:
    """Evaluate password strength according to base criteria and security heuristics.

    Returns a dictionary containing:
        - password_length: int
        - requirements: dict of boolean criteria flags
        - security_checks: dict of security heuristic flags
        - score: int (0 to 5)
        - strength: "Waiting for input" | "Weak" | "Good" | "Excellent"
        - legacy_strength: "POOR ❌" | "GOOD ⚠️" | "EXCELLENT ✅"
        - score_percent: int (0 to 100)
        - recommendations: list of strings
        - is_acceptable: bool (True only when Excellent)
    """
    if password is None:
        password = ""
    elif not isinstance(password, str):
        password = str(password)

    length = len(password)

    # Empty input handling
    if length == 0:
        return {
            "password_length": 0,
            "requirements": {
                "length": False,
                "uppercase": False,
                "lowercase": False,
                "digit": False,
                "special": False,
                "length_12": False,
            },
            "security_checks": {
                "is_common": False,
                "has_repeated": False,
                "has_sequential": False,
            },
            "score": 0,
            "max_score": 5,
            "score_percent": 0,
            "strength": "Waiting for input",
            "legacy_strength": "POOR ❌",
            "recommendations": ["Enter a password to evaluate its strength."],
            "is_acceptable": False,
        }

    # Base requirements evaluation
    conditions: Dict[str, bool] = {
        "length": length >= 8,
        "uppercase": False,
        "lowercase": False,
        "digit": False,
        "special": False,
        "length_12": length >= 12,
    }

    for ch in password:
        if ch.isupper():
            conditions["uppercase"] = True
        elif ch.islower():
            conditions["lowercase"] = True
        elif ch.isdigit():
            conditions["digit"] = True
        elif ch in SPECIAL_CHARACTERS:
            conditions["special"] = True

    # Base score (0 to 5)
    base_criteria = ["length", "uppercase", "lowercase", "digit", "special"]
    score = sum(1 for key in base_criteria if conditions[key])

    # Security heuristics
    is_common = is_common_password(password)
    has_repeated = has_repeated_characters(password)
    has_sequential = has_sequential_characters(password)

    security_checks = {
        "is_common": is_common,
        "has_repeated": has_repeated,
        "has_sequential": has_sequential,
    }

    # Strength classification
    if is_common or score <= 2:
        strength = "Weak"
        legacy_strength = "POOR ❌"
    elif score <= 4:
        strength = "Good"
        legacy_strength = "GOOD ⚠️"
    else:  # score == 5
        if has_repeated or has_sequential:
            strength = "Good"
            legacy_strength = "GOOD ⚠️"
        else:
            strength = "Excellent"
            legacy_strength = "EXCELLENT ✅"

    score_percent = int((score / 5) * 100)
    recommendations = get_recommendations(conditions, security_checks, score)
    is_acceptable = strength == "Excellent"

    return {
        "password_length": length,
        "requirements": conditions,
        "security_checks": security_checks,
        "score": score,
        "max_score": 5,
        "score_percent": score_percent,
        "strength": strength,
        "legacy_strength": legacy_strength,
        "recommendations": recommendations,
        "is_acceptable": is_acceptable,
    }


def main() -> None:
    """Interactive command-line interface preserving original behavior with upgrades."""
    print("=" * 45)
    print("        PASSWORD STRENGTH CHECKER")
    print("=" * 45)
    print("\nPassword Rules:")
    for rule in RULES:
        print(f"- {rule}")
    print("- 12+ characters recommended for maximum security\n")

    while True:
        try:
            password = input("\nEnter your password: ")
        except (KeyboardInterrupt, EOFError):
            print("\nExiting. Stay safe!")
            break

        result = check_password_strength(password)
        strength = result["legacy_strength"]

        print(f"\nPassword Strength: {strength} ({result['strength']})")
        print(f"Criteria Satisfied: {result['score']}/{result['max_score']}")

        if result["recommendations"]:
            print("\nRecommendations:")
            for rec in result["recommendations"]:
                print(f"  • {rec}")

        if result["is_acceptable"]:
            print("\n🎉 Password accepted successfully!")
            break
        else:
            print("\nPlease change your password to make it stronger.")


if __name__ == "__main__":
    main()

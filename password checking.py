"""Password Strength Checker with Change Option (Improved).

Preserves original workflow, rules, and classifications while integrating
modular validation, security heuristic checks, and actionable recommendations.
"""

from password_checker import (
    RULES,
    SPECIAL_CHARACTERS as special_chars,
    check_password_strength,
    main,
)

# Preserved top-level exports for backwards compatibility
rules = RULES

if __name__ == "__main__":
    main()

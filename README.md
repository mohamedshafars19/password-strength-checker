# Password Strength Checker

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-0071E3?style=for-the-badge&logo=safari&logoColor=white)](https://mohamedshafars19.github.io/password-strength-checker/)
[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![JavaScript](https://img.shields.io/badge/JavaScript-ES6%2B-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)
[![Privacy](https://img.shields.io/badge/Privacy-100%25%20Client--Side-34C759?style=for-the-badge&logo=apple&logoColor=white)](https://github.com/mohamedshafars19/password-strength-checker)

An elegant, privacy-first Password Strength Checker inspired by the design principles of **Apple macOS**, **Apple Passwords**, and **System Settings**.

It provides real-time validation, security heuristic analysis, and actionable improvement recommendations, available both as a standalone **Python CLI application** and a **zero-dependency browser demo** hosted on GitHub Pages.

---

## Live Demo

Experience the live application deployed via GitHub Pages:

🔗 **[https://mohamedshafars19.github.io/password-strength-checker/](https://mohamedshafars19.github.io/password-strength-checker/)**

---

## Key Features

- **Apple-Inspired Interface**: Crafted with Apple design aesthetics — soft `#F5F5F7` background, rounded white cards, refined typography (`SF Pro` stack), subtle elevation shadows, and smooth micro-interactions.
- **Dual Implementation Parity**: Python and JavaScript engines share identical validation logic, scoring models, and security checks.
- **Real-Time Interactive Feedback**: Instant evaluation as you type, updating visual indicators, score progress, and checklist items.
- **Show/Hide & One-Click Clear**: Native-feeling controls for toggling password visibility and resetting input.
- **Security Heuristics**: Beyond simple character counting, it detects common leaked passwords, repeated character sequences, and predictable keyboard/alphanumeric runs.
- **Actionable Guidance**: Clear, contextual recommendations explain exactly what steps to take to strengthen weak passwords.
- **100% Client-Side Privacy**: Operates with complete zero-knowledge isolation — no server backend, no third-party APIs, no cookies, and no persistent storage.

---

## Password Validation Rules & Heuristics

### 1. Base Criteria (Score 0 – 5)

| Requirement | Description | Target |
| :--- | :--- | :--- |
| **Minimum Length** | At least 8 characters long | `len >= 8` |
| **Uppercase Letter** | At least one capital Latin letter | `[A-Z]` |
| **Lowercase Letter** | At least one small Latin letter | `[a-z]` |
| **Numeric Digit** | At least one number | `[0-9]` |
| **Special Character** | At least one symbol (`!@#$%^&*()_+-=[]{}...`) | Symbol set |
| **Recommended Length** | 12+ characters for extended brute-force resilience | Bonus indicator |

### 2. Security Heuristic Checks

1. **Common Weak Password Detection**: Matches passwords against a curated list of commonly compromised passwords (e.g. `password123`, `admin12345`, `12345678`). Matches are automatically downgraded to **Weak / Poor**.
2. **Repeated Character Sequences**: Flags 3 or more consecutive identical characters (e.g. `aaa`, `111`), warning the user against low-entropy repetition.
3. **Sequential Pattern Detection**: Detects ascending/descending alphanumeric runs (`123`, `abc`, `cba`) and keyboard sequences (`qwerty`, `asdfgh`), preventing predictable patterns.

### 3. Strength Classifications

- **Waiting for input**: Input field is empty.
- **Weak (POOR ❌)**: Score $\le$ 2, or password matches a known common weak password.
- **Good (GOOD ⚠️)**: Score is 3 or 4, or score is 5 but contains repeated or sequential patterns.
- **Excellent (EXCELLENT ✅)**: All 5 base criteria met with zero security heuristic warnings.

---

## Privacy and Security Architecture

Security and privacy are fundamental requirements of this project:

- **Local Processing Only**: All evaluation runs strictly inside your local runtime (Python terminal or client-side browser engine).
- **No Network Transmission**: Zero HTTP requests, zero telemetry, zero analytics tracking, and no external API calls.
- **No Client-Side Storage**: Entered passwords are never written to `localStorage`, `sessionStorage`, `IndexedDB`, or cookies.
- **No Console Leaks**: Passwords are never logged to the browser developer console.
- **Memory Ephemerality**: Passwords are discarded the moment the input is cleared or the browser tab is closed.

---

## Project Structure

```
PASSWORD-STRENGTH-CHECKER/
│
├── index.html                   # Apple-inspired web interface
├── style.css                    # Apple design system styling
├── script.js                    # Client-side validation logic & UI controller
├── password_checker.py          # Modular Python strength validation engine
├── password checking.py         # Original entrypoint (preserved & upgraded)
├── requirements.txt             # Development & testing dependencies
├── README.md                    # Project documentation
├── .gitignore                   # Git ignore specifications
│
└── tests/
    ├── test_password_checker.py # Python unittest test suite
    ├── test_password_checker.js # Node.js test suite for JS parity
    └── verify_parity.py         # Automated cross-language parity tester
```

---

## Technologies Used

- **Python 3**: Standard library (`re`, `typing`, `unittest`, `sys`, `os`).
- **HTML5**: Semantic, accessible markup (`aria-live`, `aria-describedby`, `role="progressbar"`).
- **CSS3**: Custom properties, Apple SF font stack, flexbox, smooth cubic-bezier transitions.
- **JavaScript (ES6+)**: Vanilla client-side JS with zero external framework dependencies.

---

## Installation & Execution

### Running the Python Program

The Python engine requires Python 3.8 or newer with standard library support.

1. Clone or download the repository:
   ```bash
   git clone https://github.com/mohamedshafars19/password-strength-checker.git
   cd password-strength-checker
   ```

2. Run the interactive password checker:
   ```bash
   python password_checker.py
   ```
   *(You can also run the original file `python "password checking.py"` which is fully preserved and forwards to the upgraded engine).*

3. Example terminal session:
   ```text
   =============================================
           PASSWORD STRENGTH CHECKER
   =============================================

   Password Rules:
   - Minimum 8 characters
   - At least one uppercase letter
   - At least one lowercase letter
   - At least one digit
   - At least one special character
   - 12+ characters recommended for maximum security

   Enter your password: weak
   Password Strength: POOR ❌ (Weak)
   Criteria Satisfied: 1/5

   Recommendations:
     • Make your password at least 8 characters long.
     • Include at least one uppercase letter (A-Z).
     • Add at least one numeric digit (0-9).
     • Include at least one special character (!@#$%^&*...).

   Please change your password to make it stronger.

   Enter your password: K9#mQ2$vL5!x
   Password Strength: EXCELLENT ✅ (Excellent)
   Criteria Satisfied: 5/5

   🎉 Password accepted successfully!
   ```

---

## Testing

Comprehensive test suites verify both the Python and JavaScript implementations for 100% parity across all edge cases.

### Running Python Unit Tests
```bash
python -m unittest discover -s tests -v
```

### Running JavaScript Unit Tests (Node.js)
```bash
node tests/test_password_checker.js
```

### Running Cross-Language Parity Verification
```bash
python tests/verify_parity.py
```
This automated verification suite evaluates 23 distinct password patterns across both Python and JavaScript and guarantees that every attribute matches identically.

---

## GitHub Pages Deployment

The static web application is designed to be hosted directly on GitHub Pages with zero build step.

### Step-by-Step Deployment Instructions

1. Open your repository on GitHub:
   [https://github.com/mohamedshafars19/password-strength-checker](https://github.com/mohamedshafars19/password-strength-checker)
2. Navigate to **Settings** → **Pages** (under the "Code and automation" section).
3. Under **Build and deployment**:
   - **Source**: Select `Deploy from a branch`.
   - **Branch**: Select `main`.
   - **Folder**: Select `/ (root)`.
4. Click **Save**.
5. GitHub will trigger a workflow and deploy the site to:
   **`https://mohamedshafars19.github.io/password-strength-checker/`**

---

## Limitations

- **Heuristic Scope**: The local common passwords list covers frequently targeted combinations. It does not replace massive multi-gigabyte breach databases like *Have I Been Pwned* (which would require external API queries or gigabytes of storage, compromising the zero-dependency, client-side offline privacy model).
- **Entropy Estimation**: While length and character sets are strictly enforced, mathematically rigorous information-theoretic entropy (e.g. zxcvbn dictionary modeling) is intentionally simplified into clean, predictable rules to preserve transparency and maintainability.
- **Human Factor**: A password classified as "Excellent" should never be reused across multiple services. We recommend pairing strong passwords with multi-factor authentication (MFA) and a trusted password manager.

---

## License

This project is open-source and available under the [MIT License](LICENSE).

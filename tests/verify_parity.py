"""Cross-language parity verification script between Python and JavaScript."""

import json
import subprocess
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from password_checker import check_password_strength

TEST_PASSWORDS = [
    "",
    "a",
    "1234567",
    "abcdefgh",
    "ABCDEFGH",
    "12345678",
    "!@#$%^&*",
    "Ab1!",
    "Abcdef1!",
    "lowercase1!",
    "UPPERCASE1!",
    "NoNumberSpecial!",
    "NoSpecialChar123",
    "password",
    "password123",
    "Password123!",
    "admin12345",
    "aaaBBB111!@#",
    "Abc12345!#",
    "qwerty123!A",
    "K9#mQ2$vL5!x",
    "SecureP@ssw0rd2026!",
    "Xy9#wQ2$vL5!x7&pM",
]

python_results = []
for pwd in TEST_PASSWORDS:
    py_res = check_password_strength(pwd)
    python_results.append({
        "password": pwd,
        "score": py_res["score"],
        "strength": py_res["strength"],
        "legacy_strength": py_res["legacy_strength"],
        "req_length": py_res["requirements"]["length"],
        "req_upper": py_res["requirements"]["uppercase"],
        "req_lower": py_res["requirements"]["lowercase"],
        "req_digit": py_res["requirements"]["digit"],
        "req_special": py_res["requirements"]["special"],
        "req_length12": py_res["requirements"]["length_12"],
        "sec_common": py_res["security_checks"]["is_common"],
        "sec_repeated": py_res["security_checks"]["has_repeated"],
        "sec_sequential": py_res["security_checks"]["has_sequential"],
        "is_acceptable": py_res["is_acceptable"],
    })

# Run Node.js to evaluate same passwords
node_script = """
const { checkPasswordStrength } = require('./script.js');
const pwds = %s;
const results = pwds.map(pwd => {
    const res = checkPasswordStrength(pwd);
    return {
        password: pwd,
        score: res.score,
        strength: res.strength,
        legacy_strength: res.legacyStrength,
        req_length: res.requirements.length,
        req_upper: res.requirements.uppercase,
        req_lower: res.requirements.lowercase,
        req_digit: res.requirements.digit,
        req_special: res.requirements.special,
        req_length12: res.requirements.length12,
        sec_common: res.securityChecks.isCommon,
        sec_repeated: res.securityChecks.hasRepeated,
        sec_sequential: res.securityChecks.hasSequential,
        is_acceptable: res.isAcceptable
    };
});
console.log(JSON.stringify(results));
""" % json.dumps(TEST_PASSWORDS)

proc = subprocess.run(
    ["node", "-e", node_script],
    capture_output=True,
    text=True,
    check=True
)
js_results = json.loads(proc.stdout)

all_match = True
for py, js in zip(python_results, js_results):
    assert py["password"] == js["password"]
    for key in py:
        if py[key] != js[key]:
            print(f"MISMATCH for '{py['password']}' on key '{key}': Python={py[key]}, JS={js[key]}")
            all_match = False

if all_match:
    print(f"SUCCESS: Perfect parity across all {len(TEST_PASSWORDS)} test cases between Python and JavaScript!")
else:
    sys.exit(1)

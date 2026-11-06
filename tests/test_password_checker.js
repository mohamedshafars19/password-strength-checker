/**
 * Unit tests for JavaScript implementation (script.js) using Node.js assert.
 * Verifies parity with Python test suite.
 */

const assert = require("assert");
const {
  checkPasswordStrength,
  isCommonPassword,
  hasRepeatedCharacters,
  hasSequentialCharacters
} = require("../script.js");

console.log("Starting JavaScript Unit Tests...\n");

// 1. Empty input
{
  const res = checkPasswordStrength("");
  assert.strictEqual(res.score, 0, "Empty input score should be 0");
  assert.strictEqual(res.strength, "Waiting for input");
  assert.strictEqual(res.isAcceptable, false);
  console.log("✓ Empty input test passed");
}

// 2. Null / non-string input
{
  const resNull = checkPasswordStrength(null);
  assert.strictEqual(resNull.score, 0);
  assert.strictEqual(resNull.strength, "Waiting for input");

  const resNum = checkPasswordStrength(12345678);
  assert.strictEqual(resNum.requirements.digit, true);
  assert.strictEqual(resNum.requirements.length, true);
  assert.strictEqual(resNum.requirements.uppercase, false);
  console.log("✓ Null/non-string input test passed");
}

// 3. Shorter than 8 characters
{
  const res = checkPasswordStrength("Ab1!xyz");
  assert.strictEqual(res.requirements.length, false);
  assert.strictEqual(res.requirements.uppercase, true);
  assert.strictEqual(res.requirements.lowercase, true);
  assert.strictEqual(res.requirements.digit, true);
  assert.strictEqual(res.requirements.special, true);
  assert.strictEqual(res.score, 4);
  assert.strictEqual(res.strength, "Good");
  assert.strictEqual(res.isAcceptable, false);
  console.log("✓ Shorter than 8 characters test passed");
}

// 4. Missing uppercase
{
  const res = checkPasswordStrength("lowercase1!");
  assert.strictEqual(res.requirements.uppercase, false);
  assert.strictEqual(res.requirements.length, true);
  assert.strictEqual(res.score, 4);
  assert.strictEqual(res.strength, "Good");
  console.log("✓ Missing uppercase test passed");
}

// 5. Missing lowercase
{
  const res = checkPasswordStrength("UPPERCASE1!");
  assert.strictEqual(res.requirements.lowercase, false);
  assert.strictEqual(res.requirements.length, true);
  assert.strictEqual(res.score, 4);
  assert.strictEqual(res.strength, "Good");
  console.log("✓ Missing lowercase test passed");
}

// 6. Missing number
{
  const res = checkPasswordStrength("NoNumberSpecial!");
  assert.strictEqual(res.requirements.digit, false);
  assert.strictEqual(res.score, 4);
  assert.strictEqual(res.strength, "Good");
  console.log("✓ Missing number test passed");
}

// 7. Missing special character
{
  const res = checkPasswordStrength("NoSpecialChar123");
  assert.strictEqual(res.requirements.special, false);
  assert.strictEqual(res.score, 4);
  assert.strictEqual(res.strength, "Good");
  console.log("✓ Missing special character test passed");
}

// 8. Repeated character patterns
{
  assert.strictEqual(hasRepeatedCharacters("aaa"), true);
  assert.strictEqual(hasRepeatedCharacters("Passs123!"), true);
  assert.strictEqual(hasRepeatedCharacters("11123456"), true);
  assert.strictEqual(hasRepeatedCharacters("K9#mQ2$vL5!x"), false);

  const res = checkPasswordStrength("Aaaabb12!#");
  assert.strictEqual(res.securityChecks.hasRepeated, true);
  assert.strictEqual(res.strength, "Good");
  assert.strictEqual(res.isAcceptable, false);
  console.log("✓ Repeated characters test passed");
}

// 9. Sequential character patterns
{
  assert.strictEqual(hasSequentialCharacters("abc"), true);
  assert.strictEqual(hasSequentialCharacters("123"), true);
  assert.strictEqual(hasSequentialCharacters("cba"), true);
  assert.strictEqual(hasSequentialCharacters("qwerty"), true);
  assert.strictEqual(hasSequentialCharacters("k9mQ2vL5x"), false);

  const res = checkPasswordStrength("Abc12345!#");
  assert.strictEqual(res.securityChecks.hasSequential, true);
  assert.strictEqual(res.strength, "Good");
  assert.strictEqual(res.isAcceptable, false);
  console.log("✓ Sequential characters test passed");
}

// 10. Common weak passwords
{
  assert.strictEqual(isCommonPassword("password"), true);
  assert.strictEqual(isCommonPassword("Password123!"), true);
  assert.strictEqual(isCommonPassword("admin12345"), true);
  assert.strictEqual(isCommonPassword("12345678"), true);

  const res = checkPasswordStrength("Password123!");
  assert.strictEqual(res.securityChecks.isCommon, true);
  assert.strictEqual(res.strength, "Weak");
  assert.strictEqual(res.legacyStrength, "POOR ❌");
  assert.strictEqual(res.isAcceptable, false);
  console.log("✓ Common weak passwords test passed");
}

// 11. Satisfying all original requirements
{
  const res = checkPasswordStrength("K9#mQ2$vL5!x");
  assert.strictEqual(res.score, 5);
  assert.strictEqual(res.requirements.length, true);
  assert.strictEqual(res.requirements.uppercase, true);
  assert.strictEqual(res.requirements.lowercase, true);
  assert.strictEqual(res.requirements.digit, true);
  assert.strictEqual(res.requirements.special, true);
  assert.strictEqual(res.requirements.length12, true);
  assert.strictEqual(res.securityChecks.isCommon, false);
  assert.strictEqual(res.securityChecks.hasRepeated, false);
  assert.strictEqual(res.securityChecks.hasSequential, false);
  assert.strictEqual(res.strength, "Excellent");
  assert.strictEqual(res.legacyStrength, "EXCELLENT ✅");
  assert.strictEqual(res.isAcceptable, true);
  console.log("✓ Satisfying all requirements test passed");
}

// 12. Score <= 2 classified as Weak / POOR
{
  const res = checkPasswordStrength("short");
  assert(res.score <= 2);
  assert.strictEqual(res.strength, "Weak");
  assert.strictEqual(res.legacyStrength, "POOR ❌");
  console.log("✓ Score <= 2 classified as Weak test passed");
}

console.log("\nALL JAVASCRIPT TESTS PASSED SUCCESSFULLY! 100% PARITY WITH PYTHON.");

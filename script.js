/**
 * Password Strength Checker - Core Logic & Convertly-Inspired UI Controller
 * 100% Client-Side, Zero Tracking, Zero Network Calls.
 */

// Common weak passwords list (identical to Python implementation)
const COMMON_WEAK_PASSWORDS = new Set([
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
  "changeme123"
]);

const SPECIAL_CHARACTERS = new Set("!@#$%^&*()_+-=[]{}|;:',.<>?/`~\"\\");

/**
 * Check if the password matches a known common weak password.
 */
function isCommonPassword(password) {
  if (!password) return false;
  return COMMON_WEAK_PASSWORDS.has(password.trim().toLowerCase());
}

/**
 * Detect consecutive identical characters of length >= threshold (case-insensitive).
 */
function hasRepeatedCharacters(password, threshold = 3) {
  if (!password || password.length < threshold) return false;
  const lower = password.toLowerCase();
  let count = 1;
  for (let i = 1; i < lower.length; i++) {
    if (lower[i] === lower[i - 1]) {
      count++;
      if (count >= threshold) return true;
    } else {
      count = 1;
    }
  }
  return false;
}

/**
 * Detect ascending or descending sequential patterns (letters, digits, keyboard).
 */
function hasSequentialCharacters(password, threshold = 3) {
  if (!password || password.length < threshold) return false;
  const lower = password.toLowerCase();

  for (let i = 0; i <= lower.length - threshold; i++) {
    const windowStr = lower.substring(i, i + threshold);

    // Digits sequence (e.g. 123, 321)
    if (/^\d+$/.test(windowStr)) {
      const diffs = [];
      for (let j = 0; j < threshold - 1; j++) {
        diffs.push(Number(windowStr[j + 1]) - Number(windowStr[j]));
      }
      if (diffs.every(d => d === 1) || diffs.every(d => d === -1)) {
        return true;
      }
    }

    // Alphabetical sequence (e.g. abc, cba)
    else if (/^[a-z]+$/.test(windowStr)) {
      const diffs = [];
      for (let j = 0; j < threshold - 1; j++) {
        diffs.push(windowStr.charCodeAt(j + 1) - windowStr.charCodeAt(j));
      }
      if (diffs.every(d => d === 1) || diffs.every(d => d === -1)) {
        return true;
      }
    }
  }

  // Common keyboard row sequences
  const keyboardSequences = ["qwerty", "asdfgh", "zxcvbn"];
  for (const seq of keyboardSequences) {
    for (let i = 0; i <= seq.length - threshold; i++) {
      const sub = seq.substring(i, i + threshold);
      const revSub = sub.split("").reverse().join("");
      if (lower.includes(sub) || lower.includes(revSub)) {
        return true;
      }
    }
  }

  return false;
}

/**
 * Generate actionable improvement suggestions based on analysis.
 */
function getRecommendations(requirements, securityChecks, score) {
  const recommendations = [];

  if (!requirements.length) {
    recommendations.push("Make your password at least 8 characters long.");
  }
  if (!requirements.uppercase) {
    recommendations.push("Include at least one uppercase letter (A-Z).");
  }
  if (!requirements.lowercase) {
    recommendations.push("Include at least one lowercase letter (a-z).");
  }
  if (!requirements.digit) {
    recommendations.push("Add at least one numeric digit (0-9).");
  }
  if (!requirements.special) {
    recommendations.push("Include at least one special character (!@#$%^&*...).");
  }

  if (securityChecks.isCommon) {
    recommendations.push("This password is very common and easily guessed. Choose a more unique phrase.");
  }
  if (securityChecks.hasRepeated) {
    recommendations.push("Avoid repeating identical characters 3 or more times (e.g. 'aaa' or '111').");
  }
  if (securityChecks.hasSequential) {
    recommendations.push("Avoid sequential patterns (e.g. '123', 'abc', or keyboard rows).");
  }

  if (
    score === 5 &&
    !requirements.length12 &&
    !securityChecks.hasRepeated &&
    !securityChecks.hasSequential &&
    !securityChecks.isCommon
  ) {
    recommendations.push("Consider extending to 12+ characters for enhanced security.");
  }

  return recommendations;
}

/**
 * Evaluate password strength with 100% parity to Python implementation.
 */
function checkPasswordStrength(password) {
  if (password === null || password === undefined) {
    password = "";
  } else if (typeof password !== "string") {
    password = String(password);
  }

  const length = password.length;

  if (length === 0) {
    return {
      passwordLength: 0,
      requirements: {
        length: false,
        uppercase: false,
        lowercase: false,
        digit: false,
        special: false,
        length12: false
      },
      securityChecks: {
        isCommon: false,
        hasRepeated: false,
        hasSequential: false
      },
      score: 0,
      maxScore: 5,
      scorePercent: 0,
      strength: "Waiting for input",
      legacyStrength: "POOR ❌",
      recommendations: ["Enter a password to evaluate its strength."],
      isAcceptable: false
    };
  }

  const requirements = {
    length: length >= 8,
    uppercase: false,
    lowercase: false,
    digit: false,
    special: false,
    length12: length >= 12
  };

  for (let i = 0; i < length; i++) {
    const ch = password[i];
    if (ch >= "A" && ch <= "Z") {
      requirements.uppercase = true;
    } else if (ch >= "a" && ch <= "z") {
      requirements.lowercase = true;
    } else if (ch >= "0" && ch <= "9") {
      requirements.digit = true;
    } else if (SPECIAL_CHARACTERS.has(ch)) {
      requirements.special = true;
    }
  }

  const baseCriteria = ["length", "uppercase", "lowercase", "digit", "special"];
  const score = baseCriteria.reduce((acc, key) => acc + (requirements[key] ? 1 : 0), 0);

  const isCommon = isCommonPassword(password);
  const hasRepeated = hasRepeatedCharacters(password);
  const hasSequential = hasSequentialCharacters(password);

  const securityChecks = {
    isCommon,
    hasRepeated,
    hasSequential
  };

  let strength;
  let legacyStrength;

  if (isCommon || score <= 2) {
    strength = "Weak";
    legacyStrength = "POOR ❌";
  } else if (score <= 4) {
    strength = "Good";
    legacyStrength = "GOOD ⚠️";
  } else {
    if (hasRepeated || hasSequential) {
      strength = "Good";
      legacyStrength = "GOOD ⚠️";
    } else {
      strength = "Excellent";
      legacyStrength = "EXCELLENT ✅";
    }
  }

  const scorePercent = Math.round((score / 5) * 100);
  const recommendations = getRecommendations(requirements, securityChecks, score);
  const isAcceptable = strength === "Excellent";

  return {
    passwordLength: length,
    requirements,
    securityChecks,
    score,
    maxScore: 5,
    scorePercent,
    strength,
    legacyStrength,
    recommendations,
    isAcceptable
  };
}

// Export for Node.js unit testing (if in Node environment)
if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    checkPasswordStrength,
    isCommonPassword,
    hasRepeatedCharacters,
    hasSequentialCharacters,
    getRecommendations,
    COMMON_WEAK_PASSWORDS,
    SPECIAL_CHARACTERS
  };
}

// Convertly-Inspired UI Controller
if (typeof window !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById("password-input");
    const togglePasswordBtn = document.getElementById("toggle-password-btn");
    const clearInputBtn = document.getElementById("clear-input-btn");
    const charCounter = document.getElementById("char-counter");

    const strengthBadge = document.getElementById("strength-badge");
    const strengthScore = document.getElementById("strength-score");
    const progressBar = document.getElementById("strength-progress-fill");
    const strengthStatusText = document.getElementById("strength-status-text");

    const metricStatus = document.getElementById("metric-status");
    const metricTypes = document.getElementById("metric-types");
    const metricLength = document.getElementById("metric-length");
    const requirementsCounter = document.getElementById("requirements-counter");
    const tierBadgeText = document.getElementById("tier-badge-text");

    const chipCommon = document.getElementById("chip-common");
    const chipRepeated = document.getElementById("chip-repeated");
    const chipSequential = document.getElementById("chip-sequential");
    const recommendationsList = document.getElementById("recommendations-list");

    // Clear password input on initial page load as required
    if (passwordInput) {
      passwordInput.value = "";
    }

    function updateTagChip(chip, isTriggered, triggerLabel, cleanLabel) {
      if (!chip) return;
      chip.className = "tag-state";
      if (!passwordInput.value) {
        chip.classList.add("state-neutral");
        chip.textContent = "Clean";
      } else if (isTriggered) {
        chip.classList.add("state-warning");
        chip.textContent = triggerLabel;
      } else {
        chip.classList.add("state-passed");
        chip.textContent = cleanLabel;
      }
    }

    function renderUI() {
      const val = passwordInput.value;
      const result = checkPasswordStrength(val);
      const len = val.length;

      // Character count
      if (charCounter) {
        charCounter.textContent = `${len} character${len === 1 ? "" : "s"}`;
      }

      // Clear button visibility
      if (clearInputBtn) {
        clearInputBtn.style.opacity = len > 0 ? "1" : "0";
        clearInputBtn.style.pointerEvents = len > 0 ? "auto" : "none";
      }

      // Requirements Counter
      if (requirementsCounter) {
        requirementsCounter.textContent = `${result.score} of 5 Passed`;
      }

      // Metrics Snapshot
      if (metricLength) {
        metricLength.textContent = `${len} / 8 min`;
      }

      let typesCount = 0;
      if (result.requirements.uppercase) typesCount++;
      if (result.requirements.lowercase) typesCount++;
      if (result.requirements.digit) typesCount++;
      if (result.requirements.special) typesCount++;

      if (metricTypes) {
        metricTypes.textContent = `${typesCount} of 4 Types`;
      }

      // Strength Badge & Progress Bar
      strengthBadge.className = "strength-pill";
      progressBar.className = "progress-fill";

      let stateClass = "state-waiting";
      let statusDescriptor = "Waiting for input";
      let tierDescriptor = "Awaiting Input";

      if (len === 0) {
        stateClass = "state-waiting";
        statusDescriptor = "Waiting for input";
        tierDescriptor = "Awaiting Input";
        strengthScore.textContent = "0/5";
        progressBar.style.width = "0%";
        if (metricStatus) metricStatus.textContent = "Awaiting Input";
      } else {
        strengthScore.textContent = `${result.score}/5`;
        progressBar.style.width = `${result.scorePercent}%`;

        if (result.strength === "Weak") {
          stateClass = "state-weak";
          statusDescriptor = "Weak";
          tierDescriptor = "Weak (Needs Improvement)";
          if (metricStatus) metricStatus.textContent = "Weak";
        } else if (result.strength === "Good") {
          stateClass = "state-good";
          statusDescriptor = "Good";
          tierDescriptor = "Good (Solid Defense)";
          if (metricStatus) metricStatus.textContent = "Good";
        } else if (result.strength === "Excellent") {
          stateClass = "state-excellent";
          statusDescriptor = "Excellent";
          tierDescriptor = "Excellent (Resilient)";
          if (metricStatus) metricStatus.textContent = "Excellent";
        }
      }

      strengthBadge.classList.add(stateClass);
      progressBar.classList.add(stateClass);
      strengthStatusText.textContent = statusDescriptor;
      if (tierBadgeText) tierBadgeText.textContent = tierDescriptor;

      // Heuristic Checks Summary
      updateTagChip(chipCommon, result.securityChecks.isCommon, "Common Warning", "Passed");
      updateTagChip(chipRepeated, result.securityChecks.hasRepeated, "Repetition Warning", "Passed");
      updateTagChip(chipSequential, result.securityChecks.hasSequential, "Sequence Warning", "Passed");

      // Dynamic Guidance / Recommendations
      recommendationsList.innerHTML = "";
      if (len === 0) {
        const item = document.createElement("li");
        item.className = "rec-row rec-placeholder";
        item.innerHTML = `
          <span class="rec-bullet-dot"></span>
          <span>Enter a password on the left to reveal real-time security suggestions and strength metrics.</span>
        `;
        recommendationsList.appendChild(item);
      } else if (result.isAcceptable && result.requirements.length12) {
        const item = document.createElement("li");
        item.className = "rec-row tip-success";
        item.innerHTML = `
          <span class="rec-bullet-dot"></span>
          <span>Outstanding password! All requirements and security heuristics are satisfied.</span>
        `;
        recommendationsList.appendChild(item);
      } else {
        result.recommendations.forEach(rec => {
          const item = document.createElement("li");
          item.className = "rec-row";

          if (rec.includes("common") || rec.includes("Avoid")) {
            item.classList.add("tip-warning");
          }

          item.innerHTML = `
            <span class="rec-bullet-dot"></span>
            <span>${rec}</span>
          `;
          recommendationsList.appendChild(item);
        });
      }
    }

    // Toggle Password Visibility
    if (togglePasswordBtn && passwordInput) {
      togglePasswordBtn.addEventListener("click", () => {
        const isPassword = passwordInput.getAttribute("type") === "password";
        passwordInput.setAttribute("type", isPassword ? "text" : "password");
        togglePasswordBtn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");

        const eyeOpen = togglePasswordBtn.querySelector(".eye-open");
        const eyeClosed = togglePasswordBtn.querySelector(".eye-closed");
        if (eyeOpen && eyeClosed) {
          eyeOpen.style.display = isPassword ? "none" : "block";
          eyeClosed.style.display = isPassword ? "block" : "none";
        }
      });
    }

    // Clear Input Button
    if (clearInputBtn && passwordInput) {
      clearInputBtn.addEventListener("click", () => {
        passwordInput.value = "";
        passwordInput.focus();
        renderUI();
      });
    }

    // Escape Key to clear input
    passwordInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        passwordInput.value = "";
        renderUI();
      }
    });

    // Real-time input evaluation
    passwordInput.addEventListener("input", renderUI);

    // Initial render
    renderUI();
  });
}

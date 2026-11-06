/**
 * Password Strength Checker - Core Logic & UI Controller
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

// Browser UI Controller
if (typeof window !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => {
    const passwordInput = document.getElementById("password-input");
    const togglePasswordBtn = document.getElementById("toggle-password-btn");
    const clearInputBtn = document.getElementById("clear-input-btn");
    const strengthBadge = document.getElementById("strength-badge");
    const strengthScore = document.getElementById("strength-score");
    const progressBar = document.getElementById("strength-progress-fill");
    const recommendationsList = document.getElementById("recommendations-list");
    const suggestionsSection = document.getElementById("suggestions-section");
    const strengthStatusText = document.getElementById("strength-status-text");

    const reqLength = document.getElementById("req-length");
    const reqUpper = document.getElementById("req-upper");
    const reqLower = document.getElementById("req-lower");
    const reqNumber = document.getElementById("req-number");
    const reqSpecial = document.getElementById("req-special");
    const reqLength12 = document.getElementById("req-length12");

    function updateCheckmark(element, isMet) {
      if (!element) return;
      if (isMet) {
        element.classList.add("is-met");
        element.classList.remove("is-unmet");
        const icon = element.querySelector(".req-icon");
        if (icon) {
          icon.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
        }
      } else {
        element.classList.remove("is-met");
        element.classList.add("is-unmet");
        const icon = element.querySelector(".req-icon");
        if (icon) {
          icon.innerHTML = `<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"></circle></svg>`;
        }
      }
    }

    function renderUI() {
      const val = passwordInput.value;
      const result = checkPasswordStrength(val);

      // Clear button visibility
      if (clearInputBtn) {
        clearInputBtn.style.opacity = val.length > 0 ? "1" : "0";
        clearInputBtn.style.pointerEvents = val.length > 0 ? "auto" : "none";
      }

      // Update Requirements
      updateCheckmark(reqLength, result.requirements.length);
      updateCheckmark(reqUpper, result.requirements.uppercase);
      updateCheckmark(reqLower, result.requirements.lowercase);
      updateCheckmark(reqNumber, result.requirements.digit);
      updateCheckmark(reqSpecial, result.requirements.special);
      updateCheckmark(reqLength12, result.requirements.length12);

      // Update Strength Badge & State Classes
      strengthBadge.className = "strength-pill";
      progressBar.className = "progress-fill";

      let stateClass = "state-waiting";
      let statusDescriptor = "Waiting for input";

      if (val.length === 0) {
        stateClass = "state-waiting";
        statusDescriptor = "Waiting for input";
        strengthScore.textContent = "0/5";
        progressBar.style.width = "0%";
      } else {
        strengthScore.textContent = `${result.score}/5`;
        progressBar.style.width = `${result.scorePercent}%`;

        if (result.strength === "Weak") {
          stateClass = "state-weak";
          statusDescriptor = "Weak";
        } else if (result.strength === "Good") {
          stateClass = "state-good";
          statusDescriptor = "Good";
        } else if (result.strength === "Excellent") {
          stateClass = "state-excellent";
          statusDescriptor = "Excellent";
        }
      }

      strengthBadge.classList.add(stateClass);
      progressBar.classList.add(stateClass);
      strengthStatusText.textContent = statusDescriptor;

      // Update Recommendations List
      recommendationsList.innerHTML = "";
      if (val.length === 0) {
        const item = document.createElement("li");
        item.className = "recommendation-item tip-neutral";
        item.innerHTML = `
          <span class="rec-bullet">•</span>
          <span>Enter a password above to begin security evaluation.</span>
        `;
        recommendationsList.appendChild(item);
      } else if (result.isAcceptable && result.requirements.length12) {
        const item = document.createElement("li");
        item.className = "recommendation-item tip-success";
        item.innerHTML = `
          <span class="rec-icon-success">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
          </span>
          <span>Outstanding password! All requirements and security guidelines are met.</span>
        `;
        recommendationsList.appendChild(item);
      } else {
        result.recommendations.forEach(rec => {
          const item = document.createElement("li");
          item.className = "recommendation-item";

          // Icon or bullet style
          let iconSvg = `<span class="rec-bullet">•</span>`;
          if (rec.includes("common") || rec.includes("Avoid")) {
            item.classList.add("tip-warning");
            iconSvg = `<span class="rec-icon-warning"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg></span>`;
          }

          item.innerHTML = `${iconSvg}<span>${rec}</span>`;
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

    // Real-time input evaluation
    passwordInput.addEventListener("input", renderUI);

    // Initial render
    renderUI();
  });
}

// grab all the DOM elements we need up front so we're not querying on every call
const checkButton = document.getElementById("checkBtn");
const passwordInput = document.getElementById("password");
const breachToggle = document.getElementById("breachToggle");
const statusEl = document.getElementById("status");
const meterFill = document.getElementById("meterFill");
const scoreLabel = document.getElementById("scoreLabel");
const feedbackList = document.getElementById("feedbackList");
const warningList = document.getElementById("warningList");
const commonPasswordEl = document.getElementById("commonPassword");
const breachedResultEl = document.getElementById("breachedResult");
const crackTimesEl = document.getElementById("crackTimes");

// one color per zxcvbn score level (0 = red, 4 = green)
const scoreColors = ["#fb7185", "#f97316", "#facc15", "#38bdf8", "#34d399"];

/**
 * Updates the status line shown below the input field.
 * Used for things like "Checking...", "Evaluation complete.", or error messages.
 */
function setStatus(message) {
  statusEl.textContent = message;
}

/**
 * Clears all <li> items from a <ul> before we repopulate it with fresh results.
 * Called at the start of each evaluation so old results don't bleed through.
 */
function clearList(listEl) {
  listEl.innerHTML = "";
}

/**
 * Creates a new <li> with the given text and appends it to listEl.
 * Shared helper used for feedback tips, warnings, and crack-time entries.
 */
function addListItem(listEl, text) {
  const item = document.createElement("li");
  item.textContent = text;
  listEl.appendChild(item);
}

/**
 * Moves the strength meter bar to reflect the current score.
 * Score is 0-4 from zxcvbn — we convert it to a percentage (0%, 25%, ... 100%)
 * and pick the matching color from scoreColors.
 */
function updateMeter(score) {
  const percent = Math.min(Math.max(score, 0), 4) * 25;
  meterFill.style.width = `${percent}%`;
  meterFill.style.background = scoreColors[score] || scoreColors[0];
}

/**
 * Main handler — reads the password field, posts to /check, and populates
 * the results section with score, feedback, warnings, and breach info.
 *
 * Async because the fetch (especially with breach check on) can take a moment
 * while we wait for the HIBP API response.
 */
async function checkPassword() {
  const password = passwordInput.value;
  if (!password) {
    setStatus("Enter a password to evaluate.");
    return;
  }

  setStatus("Checking password strength...");
  // clear everything from the previous run before we populate new results
  clearList(feedbackList);
  clearList(warningList);
  clearList(crackTimesEl);
  commonPasswordEl.textContent = "";
  breachedResultEl.textContent = "";

  try {
    const response = await fetch("/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        password,
        check_breached: breachToggle.checked,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      setStatus(data.error || "Unable to evaluate password.");
      return;
    }

    updateMeter(data.score);
    scoreLabel.textContent = `${data.label} (score ${data.score}/4)`;
    setStatus("Evaluation complete.");

    // populate feedback tips — show a fallback message if there are none
    if (data.feedback.length === 0) {
      addListItem(feedbackList, "No specific improvement tips.");
    } else {
      data.feedback.forEach((item) => addListItem(feedbackList, item));
    }

    // populate warnings — show a fallback if none were found
    if (data.warnings.length === 0) {
      addListItem(warningList, "No major red flags found.");
    } else {
      data.warnings.forEach((item) => addListItem(warningList, item));
    }

    commonPasswordEl.textContent = data.commonPassword
      ? "Common password detected. Choose something less predictable."
      : "Not found in the common-password list.";

    // only show breach result if the user toggled the breach check on
    if (breachToggle.checked) {
      if (data.breached === true) {
        breachedResultEl.textContent = "Found in breach corpus. Do not use.";
        breachedResultEl.className = "warning";
      } else if (data.breached === false) {
        breachedResultEl.textContent = "Not found in breach corpus.";
        breachedResultEl.className = "success";
      } else {
        // null means HIBP was unreachable or HIBP_ENABLED is off server-side
        breachedResultEl.textContent = "Breached check unavailable or disabled.";
        breachedResultEl.className = "";
      }
    }

    // display zxcvbn's crack time estimates, converting underscores to spaces
    const crackTimes = data.crackTimeEstimates || {};
    Object.entries(crackTimes).forEach(([label, value]) => {
      addListItem(crackTimesEl, `${label.replaceAll("_", " ")}: ${value}`);
    });
  } catch (error) {
    setStatus("Network error while checking password.");
  }
}

checkButton.addEventListener("click", checkPassword);

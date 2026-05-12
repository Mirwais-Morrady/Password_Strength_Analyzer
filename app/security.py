from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Iterable

import requests
from zxcvbn import zxcvbn

DEFAULT_ROCKYOU_PATH = Path(__file__).resolve().parent.parent / "data" / "rockyou.txt"

# patterns we know are terrible — checked separately from zxcvbn
COMMON_PATTERNS = [
    r"^12345",
    r"password",
    r"qwerty",
    r"admin",
    r"letmein",
]

# each string is one row of a standard keyboard layout
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
# sequences we check for runs in both directions (e.g., 'abcd' or '9876')
SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789"]


def load_common_passwords(rockyou_path: str | Path | None = None) -> set[str]:
    """
    Reads the RockYou wordlist from disk and returns every entry as a
    lowercase set. Using a set means lookups are O(1) — important since
    the file has over 14 million lines.

    If the file doesn't exist we just return an empty set so the app
    still runs without the wordlist (the check is simply skipped).
    """
    # prefer explicit path arg, then env var, then the default location
    rockyou_location = rockyou_path or os.getenv("ROCKYOU_PATH", str(DEFAULT_ROCKYOU_PATH))
    rockyou_path = Path(rockyou_location).expanduser()
    # graceful fallback — the app shouldn't break just because the file isn't there
    if not rockyou_path.exists():
        return set()
    # lowercase everything so the lookup in evaluate_password is case-insensitive
    return {
        line.strip().lower()
        for line in rockyou_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip()
    }


def validate_password_input(password: str) -> tuple[bool, str | None]:
    """
    Quick sanity checks before we do any real analysis.

    The 128-char cap is there to protect the zxcvbn scorer — it gets
    progressively slower on very long inputs, and nobody needs to test
    a 10,000-character password anyway.
    """
    if not isinstance(password, str):
        return False, "Password must be a string."
    if not password:
        return False, "Password is required."
    # cap at 128 to keep zxcvbn from slowing down on huge inputs
    if len(password) > 128:
        return False, "Password is too long (max 128 characters)."
    return True, None


def has_sequence(password: str, sequence: str, min_len: int = 4) -> bool:
    """
    Checks whether the password contains a run of at least min_len
    consecutive characters from the given sequence, in either direction.

    For example, with sequence='abcdefghijklmnopqrstuvwxyz' and min_len=4,
    a password containing 'abcd' or 'dcba' would return True.
    """
    lowered = password.lower()
    seq_len = len(sequence)
    for start in range(seq_len - min_len + 1):
        for end in range(start + min_len, seq_len + 1):
            chunk = sequence[start:end]
            # check both forward and reversed so 'dcba' is caught too
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def has_keyboard_pattern(password: str, min_len: int = 4) -> bool:
    """
    Checks for runs of adjacent keys on a standard QWERTY keyboard
    (e.g., 'asdf', 'uiop', or reversed runs like 'fdsa').

    Each KEYBOARD_ROWS string is one physical row, so we slide a window
    of size min_len across it and look for that chunk in the password.
    """
    lowered = password.lower()
    for row in KEYBOARD_ROWS:
        for start in range(len(row) - min_len + 1):
            chunk = row[start : start + min_len]
            # catches 'asdf' (forward) and 'fdsa' (backward)
            if chunk in lowered or chunk[::-1] in lowered:
                return True
    return False


def rule_checks(password: str) -> tuple[list[str], list[str]]:
    """
    Runs our own rule-based checks on top of whatever zxcvbn finds.

    Returns two lists:
      - tips: things the user could add to strengthen the password
        (length, missing character types)
      - warnings: patterns that actively make it weaker
        (common strings, repeated chars, sequences, keyboard runs)

    zxcvbn handles most of the entropy scoring — these rules catch
    the simpler stuff that it doesn't always surface clearly.
    """
    tips: list[str] = []
    warnings: list[str] = []

    if len(password) < 12:
        tips.append("Use at least 12 characters.")

    # check for each character type — missing any of these is flagged
    if not re.search(r"[a-z]", password):
        tips.append("Add lowercase letters.")
    if not re.search(r"[A-Z]", password):
        tips.append("Add uppercase letters.")
    if not re.search(r"\d", password):
        tips.append("Add numbers.")
    if not re.search(r"[^A-Za-z0-9]", password):
        tips.append("Add symbols (like !@#).")

    lowered = password.lower()
    # check against our list of obviously bad patterns
    if any(re.search(pattern, lowered) for pattern in COMMON_PATTERNS):
        warnings.append("Avoid common patterns like 'password', 'qwerty', or '12345'.")

    # three or more of the same character in a row (e.g., 'aaa', '111')
    if re.search(r"(.)\1\1", password):
        warnings.append("Avoid repeated characters like 'aaa' or '111'.")

    if any(has_sequence(password, sequence) for sequence in SEQUENCES):
        warnings.append("Avoid sequential patterns like 'abcd' or '6543'.")

    if has_keyboard_pattern(password):
        warnings.append("Avoid keyboard patterns like 'qwerty' or 'asdf'.")

    return tips, warnings


def evaluate_password(password: str, common_passwords: Iterable[str]) -> dict:
    """
    Combines zxcvbn analysis with our own rule checks to produce a
    full evaluation result dictionary.

    The returned dict has:
      - score (0-4) and label (WEAK / OKAY / STRONG)
      - feedback: improvement tips from zxcvbn + our rule checks
      - warnings: red flags from zxcvbn + our rule checks
      - commonPassword: True if the password is in the RockYou list
      - breached: always None here — the route fills this in if needed
      - crackTimeEstimates: zxcvbn's time-to-crack estimates

    common_passwords is passed in (rather than loaded here) because
    it's already loaded into app config at startup.
    """
    analysis = zxcvbn(password)
    # pull zxcvbn's suggestions into our feedback list
    feedback = list(analysis.get("feedback", {}).get("suggestions", []))
    warnings = []

    # zxcvbn sometimes has a single warning (e.g., "This is a top-10 password")
    zxcvbn_warning = analysis.get("feedback", {}).get("warning")
    if zxcvbn_warning:
        warnings.append(zxcvbn_warning)

    # layer our own rule-based checks on top
    rule_feedback, rule_warnings = rule_checks(password)
    feedback.extend(rule_feedback)
    warnings.extend(rule_warnings)

    score = int(analysis.get("score", 0))
    # map zxcvbn's 0-4 integer score to a human-readable label
    if score <= 1:
        label = "WEAK"
    elif score <= 3:
        label = "OKAY"
    else:
        label = "STRONG"

    # check against the rockyou wordlist — already lowercased when loaded
    common_password = password.lower() in common_passwords
    common_password_source = "rockyou" if common_password else None
    if common_password:
        warnings.append(
            "This password appears in real-world breach lists (RockYou)."
        )

    return {
        "score": score,
        "label": label,
        "feedback": feedback,
        "warnings": warnings,
        "commonPassword": common_password,
        "commonPasswordSource": common_password_source,
        "breached": None,
        "crackTimeEstimates": analysis.get("crack_times_display", {}),
    }


def check_breached_password(password: str) -> bool | None:
    """
    Checks whether the password has appeared in a known data breach
    using the Have I Been Pwned API.

    We use k-anonymity so the full password hash is never sent:
      1. SHA-1 hash the password
      2. Send only the first 5 characters to the API
      3. HIBP returns all hashes that start with those 5 chars
      4. We check locally whether our full hash is in the list

    Returns True if breached, False if clean, None if the API is down
    or returns an unexpected status code.
    """
    # split into prefix (sent to API) and suffix (checked locally)
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        # only the 5-char prefix leaves our server — HIBP never sees the full hash
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=5,
        )
    except requests.RequestException:
        # network error — don't let it crash the whole evaluation
        return None

    if response.status_code != 200:
        return None

    # scan the returned list to see if our specific suffix is in there
    for line in response.text.splitlines():
        found_suffix, _count = line.split(":")
        if found_suffix == suffix:
            return True
    return False

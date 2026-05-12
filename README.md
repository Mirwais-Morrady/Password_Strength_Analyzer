# Password Strength Analyzer

A defensive password strength checker built with Flask for a cybersecurity and web development portfolio. The app evaluates a submitted password using entropy analysis, rule-based pattern detection, and optional breach-list lookups — without ever storing or logging what is entered.

**Live Demo:** https://password-strength-web-qf0n.onrender.com

> Educational tool. Do not enter passwords you actually use.

---

## What It Does

| Feature | Description |
|---|---|
| **Entropy scoring** | Uses the zxcvbn library to score password strength based on entropy and pattern recognition |
| **Rule-based checks** | Flags weak patterns: short length, missing character types, repeated characters, keyboard runs, and sequential strings |
| **Breach check (optional)** | Queries the Have I Been Pwned API using k-anonymity — the full password is never sent to the API |
| **Common-password check** | Checks the submitted password against the RockYou breach wordlist loaded into memory at startup |
| **Rate limiting** | Caps the `/check` endpoint at 10 requests per minute per IP using Flask-Limiter |
| **Security headers** | Sets CSP, X-Frame-Options, Referrer-Policy, and Permissions-Policy on every response |

---

## Tech Stack

- **Language:** Python 3.11+
- **Backend Framework:** Flask, Gunicorn
- **Password Analysis:** zxcvbn, hashlib (SHA-1 for k-anonymity)
- **HTTP Security:** Flask-Limiter, requests (for HIBP API)
- **Frontend:** HTML5, vanilla JavaScript, CSS custom properties
- **Deployment:** Render

---

## Project Structure

```
password_project/
├── app/
│   ├── __init__.py       # app factory and global configuration
│   ├── extensions.py     # Flask-Limiter setup
│   ├── routes.py         # API routes (/check, /healthz)
│   ├── security.py       # password analysis and breach-check logic
│   ├── static/
│   │   ├── app.js        # frontend interaction and result rendering
│   │   └── style.css     # dark-theme UI styles
│   └── templates/
│       └── index.html    # main page
├── data/
│   └── rockyou.txt       # common-password wordlist (not bundled — see Setup)
└── app.py                # entry point for local development
```

---

## Setup

1. Create and activate a virtual environment:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Download the RockYou wordlist (optional — the app works without it):
```bash
# from the SecLists mirror
curl -L -o data/rockyou.txt \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Leaked-Databases/rockyou.txt

# or from Kali if installed locally
cp /usr/share/wordlists/rockyou.txt data/rockyou.txt
```

> **Memory note:** RockYou has over 14 million entries. Loading it as a Python set can use several hundred MB of RAM — use a smaller wordlist if memory is constrained.

---

## Running Locally

```bash
export HIBP_ENABLED=false
export ROCKYOU_PATH=./data/rockyou.txt
flask --app app run --host 127.0.0.1 --port 5000
```

Open http://127.0.0.1:5000 in your browser.

To enable the Have I Been Pwned breach check:
```bash
export HIBP_ENABLED=true
```

---

## API Reference

**POST `/check`**

Request body:
```json
{
  "password": "yourTestPassword",
  "check_breached": false
}
```

Response:
```json
{
  "score": 3,
  "label": "OKAY",
  "feedback": ["Use at least 12 characters."],
  "warnings": [],
  "commonPassword": false,
  "breached": null,
  "crackTimeEstimates": { "online_throttling_100_per_hour": "3 hours", "..." : "..." }
}
```

**GET `/healthz`** — Returns app version and whether HIBP checking is active.

---

## Deployment (Render)

| Setting | Value |
|---|---|
| **Build command** | `pip install -r requirements.txt` |
| **Start command** | `gunicorn -b 0.0.0.0:$PORT "app:create_app()"` |
| `HIBP_ENABLED` | `false` (or `true` to enable breach check) |
| `SECRET_KEY` | Generate with `python3 -c "import secrets; print(secrets.token_hex(32))"` |
| `ROCKYOU_PATH` | Optional — leave unset if not deploying the wordlist |

Verify the deployment is up:
```bash
curl https://<your-app>.onrender.com/healthz
curl -X POST https://<your-app>.onrender.com/check \
  -H "Content-Type: application/json" \
  -d '{"password":"test123"}'
```

---

## Security Notes

- Passwords are processed in memory only — nothing is logged or stored at any point.
- The HIBP breach check uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent to the API, so the full hash and the original password never leave the server.
- All requests larger than 2KB are rejected before any evaluation takes place.
- Rate limiting is enforced at the route level, not middleware, so it applies only to the `/check` endpoint.

---

## Skills Demonstrated

- Building a Flask application using the app factory pattern with environment-based configuration
- Designing and securing a JSON API with input validation, rate limiting, and HTTP security headers
- Integrating the zxcvbn entropy scorer with custom rule-based password analysis
- Implementing the Have I Been Pwned k-anonymity protocol for privacy-preserving breach detection
- Loading and querying a multi-million-entry wordlist efficiently using Python sets
- Writing frontend JavaScript with async/await for real-time API interaction and dynamic DOM updates

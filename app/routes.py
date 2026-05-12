from flask import Blueprint, current_app, jsonify, render_template, request

from .extensions import limiter
from .security import check_breached_password, evaluate_password, validate_password_input

bp = Blueprint("main", __name__)


@bp.get("/")
def index():
    """Renders the main page — nothing fancy, just serves the HTML."""
    return render_template("index.html")


@bp.route("/check", methods=["POST", "GET", "PUT", "PATCH", "DELETE"])
@limiter.limit("10 per minute")
def check_password():
    """
    Main API endpoint for password evaluation.

    Expects a JSON body: { "password": "...", "check_breached": true/false }
    Returns a structured JSON response with score, label, tips, warnings,
    and optionally breach and crack-time info.

    The method/content-type/size checks at the top are all defensive
    validation — we want to return clean error responses rather than
    letting Flask throw unformatted 4xx errors.

    Rate limited to 10 requests per minute per IP via Flask-Limiter.
    """
    # only POST makes sense here; other methods get a clear error instead of a 404
    if request.method != "POST":
        return (
            jsonify(
                {
                    "error": "method_not_allowed",
                    "message": "Use POST with application/json",
                    "status": 405,
                }
            ),
            405,
        )

    # reject anything that isn't JSON before we try to parse the body
    if not request.is_json:
        return (
            jsonify(
                {
                    "error": "unsupported_media_type",
                    "message": "Use application/json",
                    "status": 415,
                }
            ),
            415,
        )
    # 2KB is way more than enough for a password — anything bigger is suspicious
    if request.content_length is not None and request.content_length > 2048:
        return (
            jsonify(
                {
                    "error": "payload_too_large",
                    "message": "Request body too large",
                    "status": 413,
                }
            ),
            413,
        )

    payload = request.get_json(silent=True) or {}
    password = payload.get("password", "")
    check_breached = bool(payload.get("check_breached", False))

    # validate before passing to the scorer
    is_valid, error = validate_password_input(password)
    if not is_valid:
        return (
            jsonify(
                {
                    "error": "bad_request",
                    "message": error,
                    "details": {"field": "password"},
                }
            ),
            400,
        )

    # common_passwords was loaded at startup and stored in app config to avoid
    # re-reading the file on every request
    common_passwords = current_app.config.get("COMMON_PASSWORDS", set())
    result = evaluate_password(password, common_passwords)

    # breach check is optional (user must toggle it) and requires HIBP_ENABLED
    breached = None
    if check_breached and current_app.config.get("HIBP_ENABLED", False):
        breached = check_breached_password(password)

    result["breached"] = breached
    return jsonify(result)


@bp.get("/healthz")
def health_check():
    """
    Simple liveness check used by Render and other deployment platforms
    to confirm the app is up. Also reports the version and whether the
    HIBP breach check is enabled.
    """
    return (
        jsonify(
            {
                "status": "ok",
                "version": current_app.config.get("VERSION", "0.1.0"),
                "hibp_enabled": bool(current_app.config.get("HIBP_ENABLED", False)),
            }
        ),
        200,
    )

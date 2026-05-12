import os

from flask import Flask, jsonify, request

from .extensions import limiter
from .routes import bp
from .security import DEFAULT_ROCKYOU_PATH, load_common_passwords


def create_app() -> Flask:
    """
    App factory — builds and returns the fully configured Flask app.

    Using the factory pattern means tests can call create_app() with
    different environment variables without touching global state.
    It also lets Gunicorn import the factory and create the app fresh
    per worker.

    The RockYou wordlist is loaded once here at startup so every
    request can do a fast set lookup without touching disk.
    """
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 2048
    # SECRET_KEY must be overridden in production via environment variable
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
    app.config["HIBP_ENABLED"] = os.getenv("HIBP_ENABLED", "false").lower() == "true"
    app.config["VERSION"] = os.getenv("APP_VERSION", "0.1.0")
    app.config["ROCKYOU_PATH"] = os.getenv("ROCKYOU_PATH", str(DEFAULT_ROCKYOU_PATH))
    # load the wordlist into memory at startup for O(1) lookups per request
    app.config["COMMON_PASSWORDS"] = load_common_passwords(app.config["ROCKYOU_PATH"])

    limiter.init_app(app)
    app.register_blueprint(bp)

    # all error handlers return the same JSON shape so the frontend can
    # handle them consistently without special-casing each status code

    @app.errorhandler(400)
    def bad_request(_error):
        return (
            jsonify(
                {
                    "error": "bad_request",
                    "message": "Bad request.",
                    "status": 400,
                }
            ),
            400,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return (
            jsonify(
                {
                    "error": "not_found",
                    "message": "Endpoint does not exist",
                    "status": 404,
                }
            ),
            404,
        )

    @app.errorhandler(413)
    def request_too_large(_error):
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

    @app.errorhandler(429)
    def rate_limited(_error):
        return (
            jsonify(
                {
                    "error": "rate_limited",
                    "message": "Too many requests",
                    "status": 429,
                }
            ),
            429,
        )

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.exception("Unhandled server error", exc_info=error)
        return (
            jsonify(
                {
                    "error": "internal_server_error",
                    "message": "Internal server error",
                    "status": 500,
                }
            ),
            500,
        )

    @app.after_request
    def add_security_headers(response):
        """
        Attaches security headers to every outgoing response.

        CORS is locked to the same origin so the /check API can't be
        called from a different domain. CSP blocks inline scripts and
        styles, which prevents most XSS vectors on the frontend.
        """
        # lock CORS to the app's own origin — no cross-origin API access
        origin = request.host_url.rstrip("/")
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "POST"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        response.headers["Vary"] = "Origin"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        # CSP restricts everything to same-origin; no inline scripts or styles allowed
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "connect-src 'self'"
        )
        return response

    return app


app = create_app()

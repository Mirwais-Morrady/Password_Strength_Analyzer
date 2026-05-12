from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# rate limiter keyed by client IP — actual limits are set per-route in routes.py
limiter = Limiter(get_remote_address)

import requests
from flask import current_app, request

TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def turnstile_passed(token: str) -> bool:
    """Verifies a Cloudflare Turnstile token server-side. Returns True
    unconditionally if RAVEN_TURNSTILE_ENABLE is off.
    """
    if not current_app.config.get("RAVEN_TURNSTILE_ENABLE"):
        return True

    secret = current_app.config.get("RAVEN_TURNSTILE_SECRET_KEY")
    if not secret:
        current_app.logger.warning("RAVEN_TURNSTILE_ENABLE is set but RAVEN_TURNSTILE_SECRET_KEY is not")
        return False

    try:
        r = requests.post(
            TURNSTILE_VERIFY_URL,
            data={
                "secret": secret,
                "response": token or "",
                "remoteip": request.remote_addr,
            },
            timeout=5,
        )
        return bool(r.json().get("success"))
    except requests.RequestException:
        current_app.logger.exception("Cloudflare Turnstile verification request failed")
        return False

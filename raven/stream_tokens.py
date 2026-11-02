"""
Signed per-path tokens for watching group-isolated video streams.

TAK clients play RTSP feeds from plain <feed> XML and send no credentials, so a stream that
belongs to groups can't be opened anonymously (see mediamtx_api.external_auth). The feed URLs
Raven hands out for such a stream carry ?st=<token> instead: an HMAC over the stream's path, the
requesting user's id and an expiry, keyed with a key derived from the app's SECRET_KEY.

external_auth checks the signature and expiry, then re-checks that the user may still see the
stream, so taking someone out of a group cuts them off even while their token is unexpired.
"""

import base64
import hashlib
import hmac
import time

from flask import current_app

# Query parameter the token travels in
PARAM = "st"

# A week: ATAK keeps the feed list it was given until it next syncs it
DEFAULT_MAX_AGE = 7 * 24 * 3600


def _key() -> bytes:
    secret = current_app.config["SECRET_KEY"]
    if isinstance(secret, str):
        secret = secret.encode()
    return hmac.new(secret, b"raven-mediamtx-stream-token", hashlib.sha256).digest()


def _signature(path: str, user_id: int, expires: int) -> str:
    mac = hmac.new(_key(), f"{path}\n{user_id}\n{expires}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def make_token(path: str, user, max_age: int | None = None) -> str:
    """A token that lets `user` watch the stream at `path` until it expires."""
    if max_age is None:
        max_age = int(current_app.config.get("RAVEN_STREAM_TOKEN_MAX_AGE", DEFAULT_MAX_AGE))
    expires = int(time.time()) + max_age
    return f"{user.id}.{expires}.{_signature(path, user.id, expires)}"


def verify_token(token: str, path: str) -> int | None:
    """The id of the user `token` was issued to for `path`, or None if it's invalid, expired
    or for another path."""
    try:
        user_id, expires, signature = token.split(".")
        user_id, expires = int(user_id), int(expires)
    except (AttributeError, ValueError):
        return None
    if expires < time.time():
        return None
    if not hmac.compare_digest(signature, _signature(path, user_id, expires)):
        return None
    return user_id

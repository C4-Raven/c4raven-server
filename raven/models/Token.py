import hashlib
import json
import os
import time
import traceback
from dataclasses import dataclass

import jwt
from flask import current_app as app
from sqlalchemy import BigInteger, Boolean, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db, logger


@dataclass
class Token(db.Model):
    __tablename__ = "tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(
        String(255), ForeignKey("user.username"), nullable=True, unique=True
    )
    max_uses: Mapped[int] = mapped_column(Integer, default=None, nullable=True)
    total_uses: Mapped[int] = mapped_column(Integer, default=0, nullable=True)
    creation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=int(time.time()))
    not_before: Mapped[int] = mapped_column(BigInteger, nullable=True)
    expiration: Mapped[int] = mapped_column(BigInteger, nullable=True)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=True)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    user = relationship("User", back_populates="tokens")

    def to_json(self, hash=False) -> dict:
        json_token = {
            "sub": self.username,
            "iat": self.creation,
            "iss": "Raven",
            "aud": "Raven",
        }

        if self.max_uses or not hash:
            json_token["max"] = self.max_uses

        if self.not_before or not hash:
            json_token["nbf"] = self.not_before

        if self.expiration or not hash:
            json_token["exp"] = self.expiration

        return json_token

    def hash_token(self, token: str = None) -> str:
        sha256 = hashlib.sha256()

        if token:
            sha256.update(token.encode())
            token_hash = sha256.hexdigest()
        else:
            sha256.update(json.dumps(self.to_json(True)).encode())
            token_hash = sha256.hexdigest()
            self.token_hash = token_hash

        return token_hash

    def generate_token(self) -> str or None:
        if not self.username:
            return None

        token = {
            "sub": self.username,
            "iat": self.creation,
            "iss": "Raven",
            "aud": "Raven",
        }

        if self.max_uses:
            token["max"] = self.max_uses

        if self.not_before:
            token["nbf"] = self.not_before

        if self.expiration:
            token["exp"] = self.expiration

        with open(
            os.path.join(
                app.config.get("RAVEN_CA_FOLDER"),
                "certs",
                "raven",
                "raven.nopass.key",
            ),
            "rb",
        ) as key:
            encoded_token = jwt.encode(token, key.read(), algorithm="RS256")
            return encoded_token

    @staticmethod
    def verify_token(token: str, username: str, consume: bool = True, check_max: bool = True) -> bool:
        """
        Verifies an enrollment token presented by ``username``.

        :param token: The encoded JWT
        :param username: The username the token was presented with. The token's ``sub`` must match it
            (case-insensitively, like Flask-Security's username lookups), otherwise one user's token
            could be used to authenticate as any other user.
        :param consume: Increment the token's use counter on success. Pass False for read-only
            checks (e.g. the onboarding data package download) that shouldn't burn a use.
        :param check_max: Reject the token once total_uses >= max. Pass False for follow-up requests
            in the same enrollment (the enrollment profile fetched right after signClient, which
            already consumed the last use).
        """
        if not token or not username:
            return False

        with open(
            os.path.join(
                app.config.get("RAVEN_CA_FOLDER"), "certs", "raven", "raven.pub"
            ),
            "r",
        ) as key:
            try:
                # Will raise InvalidTokenError on bad signature, expired, or before the nbf date
                decoded_token: dict = jwt.decode(
                    token, key.read(), algorithms=["RS256"], audience="Raven"
                )

                # Enrollment tokens never carry a scope. Anything scoped (e.g. the "onboard"
                # VPN onboarding link tokens) is not an enrollment credential.
                if "scope" in decoded_token:
                    logger.error("Rejected scoped token as an enrollment credential")
                    return False

                sub = decoded_token.get("sub")
                if not isinstance(sub, str) or sub.lower() != str(username).lower():
                    logger.error(f"Token subject does not match username {username}")
                    return False

                sha256 = hashlib.sha256()
                sha256.update(json.dumps(decoded_token).encode())
                token_hash = sha256.hexdigest()

                token_from_db = db.session.query(Token).filter_by(token_hash=token_hash).first()
                if not token_from_db:
                    logger.error(f"Token not in db: {token_hash}")
                    return False

                if not token_from_db.username or token_from_db.username.lower() != sub.lower():
                    logger.error("Token owner does not match token subject")
                    return False

                if token_from_db.disabled:
                    logger.error("Token disabled")
                    return False

                if (
                    check_max
                    and "max" in decoded_token.keys()
                    and (token_from_db.total_uses or 0) >= decoded_token["max"]
                ):
                    logger.error(f"Too many uses for token {token_hash}")
                    return False

                if consume:
                    token_from_db.total_uses = (token_from_db.total_uses or 0) + 1
                    db.session.add(token_from_db)
                    db.session.commit()

                return True

            except jwt.exceptions.InvalidTokenError as e:
                logger.error(f"Invalid token: {e}")
                logger.debug(traceback.format_exc())
                return False
            except BaseException as e:
                logger.error(f"Failed to decode token: {e}")
                logger.debug(traceback.format_exc())
                return False

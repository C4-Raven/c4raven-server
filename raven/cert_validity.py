"""How many days a user's certificates are valid for.

An admin can set a per-user lifetime (User.cert_validity_days) on the Users
page. NULL means the server default, RAVEN_CA_EXPIRATION_TIME, which is also
the upper bound: a user cert shouldn't be issued for longer than the server
issues certs (and the CA itself) for.
"""

from flask import current_app as app


def max_cert_days() -> int:
    return int(app.config.get("RAVEN_CA_EXPIRATION_TIME"))


def resolve_cert_days(user) -> int:
    """Days to issue this user's next certificate for."""
    days = getattr(user, "cert_validity_days", None) if user else None
    maximum = max_cert_days()
    if isinstance(days, int) and not isinstance(days, bool) and 1 <= days <= maximum:
        return days
    return maximum


def validate_cert_days(value) -> int | None:
    """Parse an admin-supplied validity.

    :return: the number of days, or None for "use the server default"
    :raises ValueError: if value isn't a whole number between 1 and max_cert_days()
    """
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return None

    maximum = max_cert_days()
    message = "Certificate validity must be a whole number of days between 1 and {}".format(
        maximum
    )

    if isinstance(value, bool):
        raise ValueError(message)
    if isinstance(value, int):
        days = value
    elif isinstance(value, float):
        if not value.is_integer():
            raise ValueError(message)
        days = int(value)
    elif isinstance(value, str):
        stripped = value.strip()
        if not stripped.isdigit():
            raise ValueError(message)
        days = int(stripped)
    else:
        raise ValueError(message)

    if not 1 <= days <= maximum:
        raise ValueError(message)
    return days

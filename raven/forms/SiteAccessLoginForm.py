from flask_babel import gettext
from flask_security.forms import LoginForm
from wtforms import StringField

from raven.turnstile import turnstile_passed


class SiteAccessLoginForm(LoginForm):
    """Blocks web UI login for users with site_access revoked, and, if
    RAVEN_TURNSTILE_ENABLE is set, requires a passed Cloudflare Turnstile
    challenge.

    This only gates /api/login - EUDs and TAK clients authenticate through
    separate paths (cert auth, EudHandler) and are unaffected.
    """

    turnstile_token = StringField()

    def validate(self, **kwargs):
        # Checked before credentials so that a failed/missing challenge (the
        # common bot case: wrong or no password) still calls Cloudflare's
        # siteverify - checking this only on the success path would mean
        # most bot traffic never gets verified at all.
        if not turnstile_passed(self.turnstile_token.data):
            self.form_errors.append(gettext("Please complete the human verification challenge"))
            return False

        if not super().validate(**kwargs):
            return False

        if not self.user.site_access:
            self.ifield.errors.append(
                gettext("This account does not have access to the web interface")
            )
            return False

        return True

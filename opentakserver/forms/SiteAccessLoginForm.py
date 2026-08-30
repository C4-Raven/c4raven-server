from flask_babel import gettext
from flask_security.forms import LoginForm


class SiteAccessLoginForm(LoginForm):
    """Blocks web UI login for users with site_access revoked.

    This only gates /api/login - EUDs and TAK clients authenticate through
    separate paths (cert auth, EudHandler) and are unaffected.
    """

    def validate(self, **kwargs):
        if not super().validate(**kwargs):
            return False

        if not self.user.site_access:
            self.ifield.errors.append(
                gettext("This account does not have access to the web interface")
            )
            return False

        return True

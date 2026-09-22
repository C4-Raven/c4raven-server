import tldextract
from flask_security import MailUtil

from raven.extensions import logger


class EmailValidator(MailUtil):

    def __init__(self, app):
        super().__init__(app)
        self.app = app

    def send_mail(self, template, subject, recipient, sender, body, html, **kwargs):
        # Flask-Security emails some notices on its own -- most visibly "your
        # password was changed", sent from inside the change-password request.
        # With email disabled (the default: MAIL_* still points at an
        # unauthenticated smtp.gmail.com) or for an account with no address
        # (the server-created `administrator`), that send can only fail, and
        # the exception 500s the request that triggered it. On a fresh install
        # that request is the forced first-login password change, so the new
        # password is never saved and the only account is locked out for good.
        # A notice with nowhere to go is skipped instead; real email, when
        # enabled and addressed, is sent exactly as before.
        if not self.app.config.get("RAVEN_ENABLE_EMAIL") or not recipient:
            logger.info(
                "Not sending the '{}' email: {}".format(
                    template,
                    "email is disabled" if recipient else "the account has no email address",
                )
            )
            return None
        return super().send_mail(template, subject, recipient, sender, body, html, **kwargs)

    def validate(self, email: str) -> str:
        domain_whitelist = self.app.config.get("RAVEN_EMAIL_DOMAIN_WHITELIST")
        domain_blacklist = self.app.config.get("RAVEN_EMAIL_DOMAIN_BLACKLIST")
        tld_whitelist = self.app.config.get("RAVEN_EMAIL_TLD_WHITELIST")
        tld_blacklist = self.app.config.get("RAVEN_EMAIL_TLD_BLACKLIST")

        domain = email.split("@")[-1]
        parsed_domain = tldextract.extract(domain)
        logger.debug("Got domain: {}".format(domain))

        if domain_whitelist and domain not in domain_whitelist:
            logger.error("Domain {} is not whitelisted".format(domain))
            raise ValueError("Domain {} is not whitelisted".format(domain))

        if domain_blacklist and domain in domain_blacklist:
            logger.error("Domain {} is blacklisted".format(domain))
            raise ValueError("Domain {} is blacklisted".format(domain))

        if tld_whitelist and parsed_domain.suffix not in tld_whitelist:
            logger.error("TLD {} not whitelisted".format(parsed_domain.suffix))
            raise ValueError("TLD {} not whitelisted".format(parsed_domain.suffix))

        if tld_blacklist and parsed_domain.suffix in tld_blacklist:
            logger.error("TLD {} is blacklisted".format(parsed_domain.suffix))
            raise ValueError("TLD {} is blacklisted".format(parsed_domain.suffix))

        logger.info("Looks like {} is good".format(email))
        return super().validate(email)

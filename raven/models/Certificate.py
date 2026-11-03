from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from raven.extensions import db
from raven.functions import iso8601_string_from_datetime


@dataclass
class Certificate(db.Model):
    __tablename__ = "certificates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    common_name: Mapped[str] = mapped_column(String(255))
    eud_uid: Mapped[str] = mapped_column(
        String(255), ForeignKey("euds.uid", ondelete="CASCADE"), nullable=True
    )
    data_package_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("data_packages.id"), nullable=True
    )
    callsign: Mapped[str] = mapped_column(String(255), nullable=True)
    username: Mapped[str] = mapped_column(String(255), ForeignKey("user.username"), nullable=True)
    expiration_date: Mapped[datetime] = mapped_column(DateTime)
    server_address: Mapped[str] = mapped_column(String(255))
    server_port: Mapped[int] = mapped_column(Integer)
    truststore_filename: Mapped[str] = mapped_column(String(255))
    user_cert_filename: Mapped[str] = mapped_column(String(255))
    csr: Mapped[str] = mapped_column(String(255), nullable=True)
    cert_password: Mapped[str] = mapped_column(String(255))
    # Uppercase hex, no leading zeros (raven.cert_revocation.normalize_serial). NULL for rows
    # issued before it was recorded; certificate_api fills it in from disk where it can.
    serial_number: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    revocation_reason: Mapped[str] = mapped_column(String(64), nullable=True)
    user = relationship("User", back_populates="certificate", uselist=False)
    eud = relationship("EUD", cascade="all, delete", back_populates="certificates", uselist=False)
    data_package = relationship("DataPackage", back_populates="certificates", uselist=False)

    def serialize(self):
        return {
            "callsign": self.callsign,
            "expiration_date": self.expiration_date,
            "server_address": self.server_address,
            "server_port": self.server_port,
            "truststore_filename": self.truststore_filename,
            "user_cert_filename": self.user_cert_filename,
            "cert_password": self.cert_password,
            "eud_uid": self.eud_uid,
            "serial_number": self.serial_number,
            "revoked_at": iso8601_string_from_datetime(self.revoked_at) if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
        }

    @property
    def status(self):
        if self.revoked_at:
            return "revoked"
        if self.expiration_date and self.expiration_date < datetime.now():
            return "expired"
        return "valid"

    def revocation_json(self):
        """For the admin certificate list (certificate_api). Leaves out the cert password."""
        return {
            "id": self.id,
            "common_name": self.common_name,
            "username": self.username,
            "callsign": self.callsign,
            "eud_uid": self.eud_uid,
            "serial_number": self.serial_number,
            "expiration_date": iso8601_string_from_datetime(self.expiration_date)
            if self.expiration_date
            else None,
            "revoked_at": iso8601_string_from_datetime(self.revoked_at) if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
            "status": self.status,
        }

    def to_json(self):
        return {
            "callsign": self.callsign,
            "expiration_date": iso8601_string_from_datetime(self.expiration_date),
            "server_address": self.server_address,
            "server_port": self.server_port,
            "truststore_filename": self.truststore_filename,
            "user_cert_filename": self.user_cert_filename,
            "data_package_filename": self.data_package.filename if self.data_package else None,
            "data_package_hash": self.data_package.hash if self.data_package else None,
            "eud_uid": self.eud_uid,
            "serial_number": self.serial_number,
            "revoked_at": iso8601_string_from_datetime(self.revoked_at) if self.revoked_at else None,
            "revocation_reason": self.revocation_reason,
        }


def current_certificate(certificates):
    """Pick the current certificate out of a device's (or data package's) certificate rows,
    which accumulate one per enrollment: the newest unrevoked one, else the newest one."""
    if not certificates:
        return None
    ordered = sorted(certificates, key=lambda c: c.id or 0, reverse=True)
    for certificate in ordered:
        if not certificate.revoked_at:
            return certificate
    return ordered[0]

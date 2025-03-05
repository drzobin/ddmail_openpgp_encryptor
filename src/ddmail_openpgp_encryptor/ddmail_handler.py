import sys
import argparse
import logging
import smtplib
import re
import configparser
import os
import email
import email.mime
import email.mime.application
import email.mime.multipart
import gnupg
import asyncio
import ddmail_validators.validators as validators
import sqlalchemy as db
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, mapped_column, declarative_base, DeclarativeBase
from aiosmtpd.controller import Controller
from aiosmtpd.handlers import Message


Base = declarative_base()


# DB modul for accounts.
class Account(Base):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(100), unique=True, nullable=False)
    payment_token = db.Column(db.String(12), unique=True, nullable=False)
    funds_in_sek = db.Column(db.Integer, nullable=False)
    is_enabled = db.Column(db.Boolean, unique=False, nullable=False)
    is_gratis = db.Column(db.Boolean, unique=False, nullable=False)
    total_storage_space_g = db.Column(db.Integer, nullable=False)
    created = db.Column(db.DateTime, nullable=False)
    last_time_disabled = db.Column(db.DateTime, nullable=True)

    emails = relationship("Email", back_populates="account")
    openpgp_public_keys = relationship("Openpgp_public_key", back_populates="account")

# DB modul for emails.
class Email(Base):
    __tablename__ = 'emails'
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    account_id = db.Column(db.Integer, ForeignKey('accounts.id'),nullable=False)
    account_domain_id = db.Column(db.Integer, ForeignKey('account_domains.id'),nullable=True)
    global_domain_id = db.Column(db.Integer, ForeignKey('global_domains.id'),nullable=True)
    openpgp_public_key_id = db.orm.mapped_column(db.Integer, ForeignKey('openpgp_public_keys.id'),nullable=True)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password_hash = db.Column(db.String(2096), nullable=False)
    storage_space_mb = db.Column(db.Integer, nullable=False)

    account = db.orm.relationship("Account", back_populates="emails")
    openpgp_public_key = db.orm.relationship("Openpgp_public_key", back_populates="emails")

# DB modul for openpgp_public_keys.
class Openpgp_public_key(Base):
    __tablename__ = 'openpgp_public_keys'
    id = db.Column(db.Integer, primary_key=True,nullable=False)
    account_id = db.Column(db.Integer, ForeignKey('accounts.id'),nullable=False)
    fingerprint = db.Column(db.String(200), unique=True, nullable=False)

    account = relationship("Account", back_populates="openpgp_public_keys")
    emails = relationship("Email", back_populates="openpgp_public_key")

class Ddmail_handler():
    def __init__(self, logging, config):
        self.logging = logging
        self.config = config

    async def handle_DATA(self, server, session, envelope):
        # Get email data.
        raw_email = envelope.content.decode('utf8', errors='replace')

        # Process the email one recipient at a time.
        for recipient in envelope.rcpt_tos:
            r = self.process_mail(envelope.mail_from, recipient, raw_email)
            if r == False:
                return '501 Message receipient or sender email address validation failed'

        return '250 Message accepted for delivery'

    def process_mail(self, sender, recipient, raw_email):
        # Validate recipient email address.
        if validators.is_email_allowed(recipient) != True:
            self.logging.error("validation failed for recipient email address: " + recipient)
                
            return False

        # Validate from email address.
        if validators.is_email_allowed(sender) != True:
            self.logging.error("validation failed for sender email address: " + sender)
            
            return False

        # Log recipient email and sender email address.
        self.logging.info("parsing email recipient: " + recipient + " sender: " + sender)

        # Check if email should be encrypted. If the email should be encrypted we will encrypt it and return the encrypted email.
        if self.shall_email_be_encrypted(sender, recipient, raw_email) == True:
            self.logging.info("email should be encrypted")
            raw_email = self.encrypt_email(raw_email, recipient, self.config["DEFAULT"]["gnupg_home"])
        else:
            self.logging.info("email should not be encrypted")

        # Send email back to postfix.
        self.send_email(sender, recipient, raw_email)

        return True

    # Send email to SMTP server 127.0.0.1 port 10028
    def send_email(self, sender ,recipient, msg):
        s = smtplib.SMTP(host = self.config["DEFAULT"]["send_to_ip"], port = self.config["DEFAULT"]["send_to_port"])
        s.sendmail(sender, recipient, msg.encode("utf8"))
        s.quit()

    # Check if a email is encrypted or not.
    def is_email_encrypted(self, raw_email):
        parsed_email = email.message_from_string(raw_email)
        look_for = ["Content-Type: multipart/encrypted","Content-Type: application/pgp-encrypted"]

        for string in look_for:
            if string in raw_email:
                return True

        return False

    # Check if email should be encrypted ot not.
    def shall_email_be_encrypted(self, sender, recipient, raw_email):
        # Connect to db.
        engine = db.create_engine('mysql://' + self.config["mariadb"]["user"] + ':' + self.config["mariadb"]["password"]  + '@' + self.config["mariadb"]["host"] + '/' + self.config["mariadb"]["db"])
        Session = db.orm.sessionmaker(bind=engine)
        my_session = Session()
        r = my_session.query(Email).filter(Email.email == recipient).first()

        # Check if email recipient exist in ddmail db. If email recipient do not exist in ddmail db it should not be encrypted beacuse ddmail is not the final destination.
        if r == None:
            my_session.close()

            return False
        # If settings in ddmail db is not set to activate openpgp encryption for the email address then email should not be encrypted.
        elif r.openpgp_public_key_id == None:
            my_session.close()

            return False
        # If email already is encrypted do not encrypt it again.
        elif self.is_email_encrypted(raw_email) == True:
            my_session.close()

            return False
        # Email should be encrypted.
        else:
            my_session.close()

            return True

    # Encrypt email body with OpenPGP.
    def encrypt_email(self, raw_email, recipient, gnupg_home):
        # Location of gpg binary.
        gpg_binary_location = self.config["DEFAULT"]["gpg_binary_location"]

        # Log function arguments.
        self.logging.info("encrypt_email() recipient: " + recipient + " gnupg_home: " + gnupg_home)

        # Get openpgp public key fingerprint and keyring name from db, the keyring name is the ddmail account that ownes the current email.
        engine = db.create_engine('mysql://' + self.config["mariadb"]["user"] + ':' + self.config["mariadb"]["password"]  + '@' + self.config["mariadb"]["host"] + '/' + self.config["mariadb"]["db"])
        Session = db.orm.sessionmaker(bind=engine)
        my_session = Session()
        r = my_session.query(Email).filter(Email.email == recipient).first()

        # Validate account string used as keyring filename.
        if validators.is_account_allowed(r.account.account) != True:
            self.logging.error("encrypt_email() account_keyring: " + r.account.account + " failed validation")
            my_session.close()

            return raw_email

        # Full path to keyring file.
        account_keyring = gnupg_home + "/" + r.account.account
        self.logging.info("encrypt_email() account_keyring: " + account_keyring)

        # Check that account_keyring is a file.
        if os.path.isfile(account_keyring) != True:
            self.logging.error("encrypt_email() account_keyring: " + account_keyring + " is not a file")
            my_session.close()

            return raw_email
    
        # Check that we can read account_keyring file.
        if os.access(account_keyring, os.R_OK) != True:
            self.logging.error("encrypt_email() account_keyring: " + account_keyring + " can not be read")
            my_session.close()

            return raw_email

        # Fingerprint of OpenPGP public key to use for encryption.
        fingerprint = r.openpgp_public_key.fingerprint
        self.logging.info("encrypt_email() fingerprint: " + fingerprint)

        # Validate fingerprint from db.
        if validators.is_openpgp_key_fingerprint_allowed(fingerprint) != True:
            self.logging.error("encrypt_email() fingerprint: " + fingerprint + " failed validation")
            my_session.close()

            return raw_email
    
        parsed_email = email.message_from_string(raw_email)

        # Import public keys from account keyring.
        gpg = gnupg.GPG(gpgbinary = gpg_binary_location, keyring = account_keyring)

        # Encrypt the email.
        encrypted_email = gpg.encrypt(raw_email, fingerprint, always_trust = True)

        # Check if email encryption was succesfull otherwise return the unancrypted email and log the error.
        if encrypted_email.ok == False:
            self.logging.error("Failed to encrypt email to " + recipient + " with error message " + encrypted_email.status)
            my_session.close()

            return raw_email

        # Build the mime part needed for the new encrypted email.
        encrypted_email_mime = email.mime.application.MIMEApplication(_data=str(encrypted_email).encode(),_subtype='octet-stream',_encoder=email.encoders.encode_7or8bit)
        metadata_mime = email.mime.application.MIMEApplication(_data=b'Version: 1\n',_subtype='pgp-encrypted; name="encrypted.asc"',_encoder=email.encoders.encode_7or8bit)
        metadata_mime['Content-Disposition'] = 'inline; filename="encrypted.asc"'

        # Put the mime parts together to a new email.
        email_out = email.mime.multipart.MIMEMultipart('encrypted',protocol='application/pgp-encrypted')
        email_out.attach(metadata_mime)
        email_out.attach(encrypted_email_mime)

        # Copy headers from the incoming email to the new email.
        for key, value in parsed_email.items():
            if key.lower() in ["return-path","delivered-to","received","authentication-results","from","to","subject","bcc","x-mx","x-spamd-bar","x-spam-status"]:
                email_out[key] = value

        my_session.close()

        return email_out.as_string()

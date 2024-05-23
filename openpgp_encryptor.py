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
import sqlalchemy as db
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship, mapped_column, declarative_base

# Configure logging.
logging.basicConfig(filename="/var/log/ddmail_openpgp_encryptor.log", format='%(asctime)s: %(levelname)s: %(message)s', level=logging.INFO)
    
# Get arguments from args.
parser = argparse.ArgumentParser(description="Encrypt email with OpenPGP for ddmail service.")
parser.add_argument('--config-file', type=str, help='Full path to config file.', required=True)
parser.add_argument('--sender', type=str, help='The sender emails address.', required=True)
parser.add_argument('--recipient', type=str, help='The recipient emails address.', required=True)
args = parser.parse_args()

# Check that config file exsist and is a file.
if os.path.isfile(args.config_file) != True:
    logging.info("config file do not exist or is not a file.")
    sys.exit(1)

# Import config file.
config = configparser.ConfigParser()
conf_file = args.config_file
config.read(conf_file)

# Connect to db.
Base = declarative_base()
engine = db.create_engine('mysql://' + config["mariadb"]["user"] + ':' + config["mariadb"]["password"]  + '@' + config["mariadb"]["host"] + '/' + config["mariadb"]["db"])
Session = db.orm.sessionmaker(bind=engine)
session = Session()

# DB modul for accounts.
class Account(Base):
    __tablename__ = 'accounts'
    id = db.Column(db.Integer, primary_key=True)
    account = db.Column(db.String(100), unique=True, nullable=False)
    payment_token = db.Column(db.String(12), unique=True, nullable=False)
    assets_in_sek = db.Column(db.Integer, nullable=False)
    is_enabled = db.Column(db.Boolean, unique=False, nullable=False)
    is_gratis = db.Column(db.Boolean, unique=False, nullable=False)
    total_storage_space_mb = db.Column(db.Integer, nullable=False)
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

# Validate domain names. Only allow the following chars: a-z, 0-9 and .-
def is_domain_allowed(domain):
    if not len(domain) > 3:
        return False

    if domain.startswith('.') or domain.startswith('-'):
        return False
    if domain.endswith('.') or domain.endswith('-'):
        return False
    if '--' in domain:
        return False
    if '..' in domain:
        return False

    if domain.find(".") == -1:
        return False

    pattern = re.compile(r"[a-z0-9.-]")
    for char in domain:
        if not re.match(pattern, char):
            return False

    return True

# Validate email address. Only allow the following chars: a-z, 0-9 and @.-
def is_email_allowed(email):
    if not len(email) > 6:
        return False

    if email.count('@') != 1:
        return False
    if email.startswith('.') or email.startswith('@') or email.startswith('-'):
        return False
    if email.endswith('.') or email.endswith('@') or email.endswith('-'):
        return False

    # Validate email part of email.
    splitted_email = email.split('@')
    if splitted_email[0].startswith('.') or splitted_email[0].startswith('-'):
        return False
    if splitted_email[0].endswith('.') or splitted_email[0].endswith('-'):
        return False
    if '--' in splitted_email[0]:
        return False
    if '..' in splitted_email[0]:
        return False

    # Validate Domain part of email.
    if is_domain_allowed(splitted_email[1]) != True:
        return False

    pattern = re.compile(r"[a-z0-9@.-]")
    for char in email:
        if not re.match(pattern, char):
            return False

    return True

# Validate account string. Only allow the following chars: A-Z and 0-9
def is_account_allowed(account):
    pattern = re.compile(r"[A-Z0-9]")

    for char in account:
        if not re.match(pattern, char):
            return False

    return True

# Validate openpgp public key fingerprint string. Only allow the following chars: A-Z, 0-9
def is_fingerprint_allowed(fingerprint):
    if fingerprint == None:
        return False

    # Fingerprint string should be 40 char.
    allowed_len = 40
    if len(fingerprint) != allowed_len:
        return False

    # Only allow A-Z, 0-9
    pattern = re.compile(r"[A-Z0-9]")
    for char in fingerprint:
        if not re.match(pattern, char):
            return False

    return True

# Send email to SMTP server 127.0.0.1 port 10028
def send_email(sender ,recipient, msg):
    s = smtplib.SMTP(host = "127.0.0.1", port = 10028)
    s.sendmail(sender, recipient, msg)
    s.quit()

# Check if a email is encrypted ot not.
def is_email_encrypted(raw_email):
    parsed_email = email.message_from_string(raw_email)
    look_for = ["Content-Type: multipart/encrypted","Content-Type: application/pgp-encrypted"]

    for string in look_for:
        if string in raw_email:
            return True

    return False

# Check if email should be encrypted ot not.
def shall_email_be_encrypted(sender, recipient, raw_email):
    r = session.query(Email).filter(Email.email == recipient).first()
    
    # Check if email recipient exist in ddmail db. If email recipient do not exist in ddmail db it should not be encrypted beacuse ddmail is not the final destination.
    if r == None:
        return False
    # If settings in ddmail db is not set to activate openpgp encryption for the email address then email should not be encrypted.
    elif r.openpgp_public_key_id == None:
        return False
    # If email already is encrypted do not encrypt it again.
    elif is_email_encrypted(raw_email) == True:
        return False
    # Email should be encrypted.
    else:
        return True

# Encrypt email body with OpenPGP.
def encrypt_email(raw_email, recipient, gnupg_home):
    # Log function arguments.
    logging.info("encrypt_email() recipient: " + recipient + " gnupg_home: " + gnupg_home)

    # Get openpgp public key fingerprint and keyring name, the keyring name is the ddmail account that ownes the current email.
    r = session.query(Email).filter(Email.email == recipient).first()

    # Validate account string used as keyring filename.
    if is_account_allowed(r.account.account) != True:
        logging.error("encrypt_email() account_keyring: " + r.account.account + " failed validation")
        return raw_email

    # Full path to keyring file.
    account_keyring = gnupg_home + "/" + r.account.account
    logging.info("encrypt_email() account_keyring: " + account_keyring)

    # Check that account_keyring is a file.
    if os.path.isfile(account_keyring) != True:
        logging.error("encrypt_email() account_keyring: " + account_keyring + " is not a file")
        return raw_email
    
    # Check that we can read account_keyring file.
    if os.access(account_keyring, os.R_OK) != True:
        logging.error("encrypt_email() account_keyring: " + account_keyring + " can not be read")
        return raw_email

    # Fingerprint of OpenPGP public key to use for encryption.
    fingerprint = r.openpgp_public_key.fingerprint
    logging.info("encrypt_email() fingerprint: " + fingerprint)

    # Validate fingerprint from db.
    if is_fingerprint_allowed(fingerprint) != True:
        logging.error("encrypt_email() fingerprint: " + fingerprint + " failed validation")
        return raw_email
    
    parsed_email = email.message_from_string(raw_email)

    # Import public keys from account keyring.
    gpg = gnupg.GPG(keyring = account_keyring)

    # Encrypt the email.
    encrypted_email = gpg.encrypt(raw_email, fingerprint, always_trust = True)

    # Check if email encryption was succesfull otherwise return the unancrypted email and log the error.
    if encrypted_email.ok == False:
        logging.error("Failed to encrypt email to " + recipient + " with error message " + encrypted_email.status)
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

    return email_out.as_string()

if __name__ == "__main__":
    # Get email data from stdin.
    raw_email = sys.stdin.read()

    # Get the sender and recipient emails and make the strings lower chars.
    sender = args.sender.lower()
    recipient = args.recipient.lower()

    # Validate recipient email address.
    if is_email_allowed(recipient) != True:
        logging.error("validation failed for args.email_to: " + recipient)
        send_email(sender, recipient, raw_email)
        sys.exit(0)

    # Validate from email address.
    if is_email_allowed(sender) != True:
        logging.error("validation failed for args.email_from: " + sender)
        send_email(sender, recipient, raw_email)
        sys.exit(0)

    # Log recipient email and sender email address.
    logging.info("parsing email recipient: " + recipient + " sender: " + sender)

    # Check if email should be encrypted. If the email should be encrypted we will encrypt it and return the encrypted email.
    if shall_email_be_encrypted(sender, recipient, raw_email) == True:
        logging.info("email skould be encrypted")
        raw_email = encrypt_email(raw_email, recipient, config["DEFAULT"]["gnupg_home"])
    else:
        logging.info("email should not be encrypted")

    # Send email back to postfix.
    send_email(sender, recipient, raw_email)

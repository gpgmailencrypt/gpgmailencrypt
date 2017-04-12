#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from passlib.context import CryptContext
_pwd_context=pwd_context = CryptContext(
    schemes=["bcrypt","sha512_crypt","pbkdf2_sha512"],
    deprecated="auto",
    sha512_crypt__default_rounds=1000000,
    bcrypt__default_rounds=14,
	pbkdf2_sha512__default_rounds=1000000
    )

def pw_hash(password):
	return pwd_context.hash(password)

def pw_verify(password,pwhash):
	return pwd_context.verify(password,pwhash)

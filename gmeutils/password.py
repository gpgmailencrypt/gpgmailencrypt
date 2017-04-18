#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from .version import *
from passlib.context import CryptContext
import hashlib

_pwd_context=pwd_context = CryptContext(
    schemes=["bcrypt","sha512_crypt","pbkdf2_sha512"],
    deprecated="auto",
    sha512_crypt__default_rounds=1000000,
    bcrypt__default_rounds=14,
	pbkdf2_sha512__default_rounds=1000000
    )

########
#pw_hash
########

def pw_hash(password,parent=None):
	"""
	returns a has of the password
	"""
	myhash=None
	try:
		myhash=pwd_context.hash(password)
	except:

		if parent:
			parent.log("pw_verify error","e")
			parent.log_traceback()

	return myhash

##########
#pw_verify
##########

def pw_verify(password,pwhash,parent=None):
	"""
	compares the password with an already hashed password
	returns True if password is correct, else False
	"""
	result=False

	try:
		result=pwd_context.verify(password,pwhash)
	except:

		if parent:
			parent.log("pw_verify error","e")
			parent.log_traceback()

	return result

#####################
#_depreacted_get_hash
#####################

def _deprecated_get_hash(txt):
	i=0
	r=txt

	while i<=1000:
		r=hashlib.sha512(r.encode("UTF-8",unicodeerror)).hexdigest()
		i+=1

	return r


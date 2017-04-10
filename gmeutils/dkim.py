#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import email
import os.path
from .child 			import _gmechild
from .version 			import *
from ._dbg	 			import _dbg
from .thirdparty		import dkim

#######
#mydkim
#######

class mydkim(_gmechild):

	def __init__(self,parent,selector,domain,privkey):
		_gmechild.__init__(self,parent,filename=__file__)
		self.selector=selector
		self.domain=domain
		self.privkey=None

		try:
			with open(os.path.expanduser(privkey),"rb") as f:
				self.privkey=f.read()
		except:
			self.log("Could not read DKIM key","e")
			self.log_traceback()

	def sign_mail(self,mail):
		origmail=email.message_from_string(mail)

		if "DKIM-Signature" in origmail:
			del origmail["DKIM-Signature"]

		try:
			_res=dkim.sign(	mail.encode("UTF-8",unicodeerror),
						self.selector.encode("UTF-8",unicodeerror),
						self.domain.encode("UTF-8",unicodeerror),
						self.privkey).decode("UTF-8",unicodeerror)
			msg=_res.split(":",1)[1]
			origmail["DKIM-Signature"]=msg
			return origmail.as_string()
		except:
			self.log("Error executing dkim.sign_mail","e")
			self.log_traceback()
			return mail



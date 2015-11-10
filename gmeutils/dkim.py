#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from .child 			import _gmechild 
from .version 			import *
from ._dbg	 			import _dbg
from .thirdparty		import dkim

class _mydkim(_gmechild):

	def __init__(self,parent,selector,domain,privkey):
		_gmechild.__init__(self,parent,filename=__file__)
		self.selector=selector
		self.domain=domain
		self.privkey=None

		try:
			with open(privkey,"rb") as f:
				self.privkey=f.read()
		except:
			self.log("Could not read DKIM key","e")
			self.log_traceback()
		
	def sign_mail(self,mail):
		
		try:
			_res=dkim.sign(	mail.encode("UTF-8",unicodeerror),
						self.selector,
						self.domain,
						self.privkey).decode("UTF-8",unicodeerror)
			return _res+mail
		except:
			self.log("Error executing dkim.sign_mail","e")
			self.log_traceback()
			return mail
		


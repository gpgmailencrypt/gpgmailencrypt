#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import os
import re
import shutil
import subprocess
from	.child 				import _gmechild
from	._dbg	 			import _dbg
from	.version 			import *

S_NOSPAM=0
S_MAYBESPAM=1
S_SPAM=2

#################
#_basespamchecker
#################

class _basespamchecker(_gmechild):

	def __init__(self,parent,leveldict):
		_gmechild.__init__(self,parent=parent,filename=__file__)
		self.cmd=None

	@_dbg
	def set_leveldict(self,leveldict):
		raise NotImplementedError

	@_dbg
	def is_spam(self,mail):
		raise NotImplementedError

	def is_available(self):

		if self.cmd!= None and len(self.cmd)>0:
			return True
		else:
			return False

##############
#_SPAMASSASSIN
##############

class _SPAMASSASSIN(_basespamchecker):

	def __init__(	self,
					parent,
					leveldict):
		_basespamchecker.__init__(self,parent,leveldict)
		self._SPAMHOST="localhost"
		self._SPAMPORT=783
		self._SPAMMAXSIZE=5000000
		self.cmd=shutil.which("spamc")
		self.set_leveldict(leveldict)

	@_dbg
	def set_leveldict(self,leveldict):
		self.spamlevel=5.0
		self.spammaybelevel=2.5

		try:
			(self.spamlevel,
			self.spammaybelevel,
			self._SPAMHOST,
			self._SPAMPORT,
			self._SPAMMAXSIZE)=leveldict["SPAMASSASSIN"]
		except:
			self.log_traceback()

	@_dbg
	def is_spam(self,mail):
			spamlevel=S_NOSPAM
			p=subprocess.Popen([self.cmd,
								"-s",str(self._SPAMMAXSIZE),
								"-d",self._SPAMHOST,
								"-R",
								"-p",str(self._SPAMPORT)],
								stdin=subprocess.PIPE,
								stdout=subprocess.PIPE,
								stderr=subprocess.PIPE)
			result=p.communicate(input=mail.encode("UTF-8",
										unicodeerror))[0].decode("UTF-8",
										unicodeerror)
			scoretext=result[:result.find("\n")].split("/")[0]

			try:
				score=float(scoretext)
			except:
				self.log("Could not convert score to float","e")

			if score >self.spammaybelevel:

				if score >self.spamlevel:
					spamlevel=S_SPAM
				else:
					spamlevel=S_MAYBESPAM

			return spamlevel,score

############
#_BOGOFILTER
############

class _BOGOFILTER(_basespamchecker):

	def __init__(self,parent,leveldict):
		_basespamchecker.__init__(self,parent,leveldict)
		self.cmd=shutil.which("bogofilter")
		self.set_leveldict(leveldict)

	@_dbg
	def set_leveldict(self,leveldict):
		pass

	@_dbg
	def is_spam(self,mail):
			self.debug("Spamcheck bogofilter")
			spamlevel=S_NOSPAM
			p=subprocess.Popen([self.cmd,
								"-T"],
								stdin=subprocess.PIPE,
								stdout=subprocess.PIPE,
								stderr=subprocess.PIPE)
			result=p.communicate(input=mail.encode("UTF-8",
										unicodeerror))[0].decode("UTF-8",
										unicodeerror)
			level,scoretext=result[:result.find("\n")].split(" ")

			try:
				score=float(scoretext)*50
			except:
				self.log("Could not convert score to float","e")

			if level =="S":
				spamlevel=S_SPAM
			elif level == "U":
				spamlevel=S_MAYBESPAM

			return spamlevel,score

################################################################################

####################
#get_spamscannerlist
####################

def get_spamscannerlist(void):
	return ["BOGOFILTER","SPAMASSASSIN"]

################
#get_spamscanner
################

def get_spamscanner(scanner,parent,leveldict):

	scanner=scanner.upper().strip()

	if scanner=="BOGOFILTER":
		_s=_BOGOFILTER(parent,leveldict)

		if _s.is_available():
			return _s

	if scanner=="SPAMASSASSIN":
		_s=_SPAMASSASSIN(parent,leveldict)

		if _s.is_available():
			return _s

	return None


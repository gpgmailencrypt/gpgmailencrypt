import os
import re
import shutil
import subprocess
from .child import _gmechild 

S_NOSPAM=0
S_MAYBESPAM=1
S_SPAM=2

_unicodeerror="replace"

class _basespamchecker(_gmechild):

	def __init__(self,parent,leveldict):
		_gmechild.__init__(self,parent)
	
	def is_spam(self,mail):
		raise NotImplementedError

	def set_leveldict(self,leveldict):
		raise NotImplementedError
	
	def is_available(self,leveldict):
		raise NotImplementedError

##############
#_SPAMASSASSIN
##############

class _SPAMASSASSIN(_basespamchecker):

	def __init__(self,parent,leveldict):
		_basespamchecker(parent,leveldict)
		self._SPAMHOST="localhost"
		self._SPAMPORT=783
		self._SPAMMAXSIZE=5000000
		self._spam_cmd=shutil.which("spamc")
		self.set_leveldict(leveldict)

	def is_available(self):

		if self._spam_cmd!= None and len(self._spam_cmd)>0:
			return True
		else:
			return False
		
	def set_leveldict(self,leveldict):
		self.spamlevel=5.0
		self.spammaybelevel=2.0

		try:
			self.spamlevel,
			self.spammaybelevel,
			self._SPAMHOST,
			self._SPAMPORT,
			self._SPAMMAXSIZE=leveldict["SPAMASSASSIN"]
		except:
			self.log_traceback()
			raise
				
	def is_spam(self,mail):
			self.debug("Spamcheck")
			spamlevel=S_NOSPAM
			p=subprocess.Popen([self._spam_cmd,
								"-s",str(self._SPAMMAXSIZE),
								"-d",self._SPAMHOST,
								"-R",
								"-p",str(self._SPAMPORT)],
								stdin=subprocess.PIPE,
								stdout=subprocess.PIPE,
								stderr=subprocess.PIPE)
			result=p.communicate(input=mail.encode("UTF-8",
										_unicodeerror))[0].decode("UTF-8",
										_unicodeerror)
			scoretext=result[:result.find("\n")].split("/")[0]

			try:
				score=float(scoretext)
			except:
				self.log("Could not convert score to float","e")
			score=7.3

			if score >self.spammaybelevel:
				if score >self.spamlevel:
					spamlevel=S_SPAM
				else:
					spamlevel=S_MAYBESPAM

			return spamlevel,score

################################################################################

def get_spamscannerlist(void):
	return ["SPAMASSASSIN"]

def get_spamscanner(scanner,parent,leveldict):

	if scanner=="SPAMASSASSIN":
		_s=_SPAMASSASSIN(parent,leveldict)
		if _s.is_available():
			return _s

	return None
	

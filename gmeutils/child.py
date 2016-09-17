#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>

##########
#_gmechild
##########

class _gmechild:
	"base class of all classes that will be used from class gme"

	def __init__(self,parent,filename):
		self.parent=parent
		self._level=0
		self.filename=filename

	def log(self,
			msg,
			infotype="m",
			ln=-1,
			filename=""):

		if filename=="":
			filename=self.filename

		try:
			self.parent._level+=self._level
			self.parent.log(msg=msg,infotype=infotype,ln=ln,filename=filename)
			self.parent._level-=self._level
		except:
			pass

	def log_traceback(self):

		try:
			self.parent.log_traceback()
		except:
			pass

	def debug(  self,
				msg,
				lineno=0,
				filename=""):

		if filename=="":
			filename=self.filename

		try:
			self.parent._level+=self._level
			self.parent.debug(msg=msg,lineno=lineno,filename=filename)
			self.parent._level-=self._level
		except:
			pass


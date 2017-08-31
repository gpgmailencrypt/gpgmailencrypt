#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>

##########
#_gmechild
##########

class _gmechild:
	"base class of all classes that will be used from class gme"

	#########
	#__init__
	#########

	def __init__(self,parent,filename):
		self.parent=parent
		self._level=1
		self.filename=filename

	####
	#log
	####

	def log(self,
			msg,
			infotype="m",
			ln=-1,
			filename="",
			force=False):

		if filename=="":
			filename=self.filename

		try:
			self.parent._logger._level+=self._level
			self.parent.log(	msg=msg,
								infotype=infotype,
								ln=ln,
								filename=filename,
								force=force)
			self.parent._logger._level-=self._level
		except:
			pass

	##############
	#log_traceback
	##############

	def log_traceback(self):

		try:
			self.parent.log_traceback()
		except:
			pass


	######
	#error
	######

	def error(	self,
				msg,
				lineno=0,
				filename=""):
		"""logs as error message. When logging is disabled,
		this will log to stderr"""
		self.log(msg,infotype="e",lineno=lineno,filename=filename,force=True)

	######
	#debug
	######

	def debug(  self,
				msg,
				lineno=0,
				filename=""):

		if filename=="":
			filename=self.filename

		try:
			self.parent._logger._level+=self._level
			self.parent.debug(msg=msg,lineno=lineno,filename=filename)
			self.parent._logger._level-=self._level
		except:
			pass


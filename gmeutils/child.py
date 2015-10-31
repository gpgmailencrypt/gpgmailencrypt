##########
#_gmechild
##########

class _gmechild:
	"base class of all classes that will be used from class gme"
	
	def __init__(self,parent):
		self.parent=parent
		self._level=0

	def log(self,
			msg,
			infotype="m",
			ln=-1):

		try:
			self.parent._level+=self._level
			self.parent.log(msg=msg,infotype=infotype,ln=ln)
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
				lineno=0):

		try:
			self.parent._level+=self._level
			self.parent.debug(msg=msg,lineno=lineno)
			self.parent._level-=self._level
		except:
			pass


##########
#_gmechild
##########

class _gmechild:
	"base class of all classes that will be used from class gme"
	
	def __init__(self,parent):
		self.parent=parent

	def log(self,
			msg,
			infotype="m",
			ln=-1):

		try:
			self.parent.log(msg,infotype,ln)
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
			self.parent.debug(msg,lineno)
		except:
			pass


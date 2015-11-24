#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from gmeutils.child 			import _gmechild 
from gmeutils.version			import *
from gmeutils._dbg 				import _dbg

#############
#base_storage
#############

class base_storage(_gmechild):

	def __init__(self,parent):
		_gmechild.__init__(self,parent=parent,filename=__file__)
		self.init()
	
	#####
	#init
	#####
 
	@_dbg
	def init(self):
		pass

	################
	#read_configfile
	################
 
	@_dbg
	def read_configfile(self,cfg):
		raise NotImplementedError

	########
	#usermap
	########
 
	@_dbg
	def usermap(self, user):
		raise NotImplementedError

#############
#text_backend
#############

class text_backend(base_storage):

	#####
	#init
	#####
 
	@_dbg
	def init(self):
		self._addressmap = dict()

	################
	#read_configfile
	################
 
	@_dbg
	def read_configfile(self,cfg):

		if cfg.has_section('usermap'):

			for (name, value) in cfg.items('usermap'):
					self._addressmap[name] = value

	########
	#usermap
	########
 
	@_dbg
	def usermap(self, user):

		try:
			to_addr=self._addressmap[user]
		except:
			raise KeyError(user)

		return to_addr
		
################################################################################
def get_backendlist():
	return ["TEXT"]

def get_backend(backend,parent):
		backend=backend.upper().strip()
		
		if backend=="MYSQL":
			try:
				return mysql_backend(parent=parent)
			except:
				pass

		if backend=="TEXT":
			try:
				return text_backend(parent=parent)
			except:
				pass
		
		return None

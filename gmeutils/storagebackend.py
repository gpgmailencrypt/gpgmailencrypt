#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from gmeutils.child 			import _gmechild 
from gmeutils.version			import *
from gmeutils._dbg 				import _dbg
import os.path

__all__ =["get_backend","get_backendlist"]

##############
#_base_storage
##############

class _base_storage(_gmechild):

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

	##############
	#encryptionmap
	##############
 
	@_dbg
	def encryptionmap(self, user):
		raise NotImplementedError

##############
#_TEXT_BACKEND
##############

class _TEXT_BACKEND(_base_storage):

	#####
	#init
	#####
 
	@_dbg
	def init(self):
		self._addressmap = dict()
		self._encryptionmap = dict()

	################
	#read_configfile
	################
 
	@_dbg
	def read_configfile(self,cfg):

		if cfg.has_section('usermap'):

			for (name, value) in cfg.items('usermap'):
					self._addressmap[name] = value

		if cfg.has_section('encryptionmap'):

			for (name, value) in cfg.items('encryptionmap'):
					self._encryptionmap[name] = value.split(":")

	########
	#usermap
	########
 
	@_dbg
	def usermap(self, user):

		try:
			to_addr=self._addressmap[user]
		except:
			raise KeyError(user)

		self.debug("textbackend usermap %s=>%s"%(user,to_addr))
		return to_addr

	##############
	#encryptionmap
	##############
 
	@_dbg
	def encryptionmap(self, user):

		try:
			self.debug("get_preferred encryptionmap %s"%user)
			encryption=self._encryptionmap[user]
		except:
			raise KeyError(user)

		self.debug("textbackend encryptionmap %s=>%s"%(user,encryption))
		return encryption
		
#################
#_SQLITE3_BACKEND
#################

class _SQLITE3_BACKEND(_base_storage):

	#####
	#init
	#####
 
	@_dbg
	def init(self):
		self._DATABASE="gpgmailencrypt"
		self._USERMAPSQL="SELECT to_user FROM usermap WHERE user=?"
		self._ENCRYPTIONMAPSQL="SELECT encrypt FROM encryptionmap WHERE user=?"
		self._db=None

	################
	#read_configfile
	################
 
	@_dbg
	def read_configfile(self,cfg):

		import sqlite3

		if cfg.has_section('sql'):

			try:
				self._DATABASE=os.path.expanduser(cfg.get('sql','database'))
			except:
				pass
			
			self._db=sqlite3.connect(self._DATABASE)

			try:
				self._USERMAPSQL=cfg.get('sql','usermapsql')
			except:
				pass

			try:
				self._ENCRYPTIONMAPSQL=_cfg.get('sql','encryptionmapsql')
			except:
				pass

	########
	#usermap
	########
 
	@_dbg
	def usermap(self, user):
		conn=self._db.execute(self._USERMAPSQL,(user,))
		r=conn.fetchone()

		if r==None:
			raise KeyError(user)
		
		self.debug("sqlitebackend usermap %s=>%s"%(user,r[0]))
		return r[0]

	##############
	#encryptionmap
	##############
 
	@_dbg
	def encryptionmap(self, user):
		conn=self._db.execute(self._ENCRYPTIONMAPSQL,(user,))
		r=conn.fetchone()

		if r==None:
			raise KeyError(user)

		self.debug("sqlitebackend encryptionmap %s=>%s"%(user,r[0]))
		return r[0].split(":")

################################################################################

################
#get_backendlist
################

def get_backendlist():
	return ["TEXT","SQLITE3"]

############
#get_backend
############

def get_backend(backend,parent):
		backend=backend.upper().strip()

		if backend=="MYSQL":

			try:
				return _MYSQL_BACKEND(parent=parent)
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")
				
		if backend=="SQLITE3":

			try:
				return _SQLITE3_BACKEND(parent=parent)
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")
				
		else:
			# default backend=="TEXT":
			return _TEXT_BACKEND(parent=parent)


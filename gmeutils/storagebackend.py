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

	def __init__(self,parent,backend):
		_gmechild.__init__(self,parent=parent,filename=__file__)
		self._backend=backend
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

	##########
	#smimeuser
	##########
 
	@_dbg
	def smimeuser(self, user):
		raise NotImplementedError

	#################
	#smimepublic_keys
	#################
 
	@_dbg
	def smimepublic_keys(self):
		raise NotImplementedError

	##################
	#smimeprivate_keys
	##################
 
	@_dbg
	def smimeprivate_keys(self):
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
		self._smimeuser = dict()

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

		if cfg.has_section('smimeuser'):
			self._smimeuser = dict()
			privatepath=None

			for (name, value) in cfg.items('smimeuser'):
				user=value.split(",")
				cipher=self.parent._SMIMECIPHER

				if len(user)>1:
					tmpcipher=user[1].upper().strip()

					if len(tmpcipher)>0 and tmpcipher!="DEFAULT":
						cipher=tmpcipher

				if len(user)>2:
					upath=os.path.join(self.parent._SMIMEKEYHOME,user[2])
					privatepath=os.path.expanduser(upath)

				upath=os.path.join(self.parent._SMIMEKEYHOME,user[0])
				publicpath=os.path.expanduser(upath)

				if os.path.isfile(publicpath):
					self._smimeuser[name] = [publicpath,cipher,privatepath]

		s=self.parent.smime_factory()
		self._smimeuser.update(s.create_keylist(self.parent._SMIMEKEYHOME))

		for u in self._smimeuser:
			self.debug("SMimeuser: '%s %s'"%(u,self._smimeuser[u]))

	########
	#usermap
	########

	@_dbg
	def usermap(self, user):
		exception=False

		try:
			to_addr=self._addressmap[user]
		except:
			exception=True

		if exception:
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
			self.debug("No encryption map for user '%s' found"%user)
			raise KeyError(user)

		self.debug("textbackend encryptionmap %s=>%s"%(user,encryption))
		return encryption

	##########
	#smimeuser
	##########
 
	@_dbg
	def smimeuser(self, user):
		self.debug("textbackend smimeuser check ",user)

		try:
			self.debug("smimeuser %s"%user)
			smime=self._smimeuser[user]
		except:
			self.debug("No smime user '%s' found"%user)
			raise KeyError(user)

		self.debug("textbackend smimeuser %s=>%s"%(user,smime))
		return smime

	#################
	#smimepublic_keys
	#################
 
	@_dbg
	def smimepublic_keys(self):
		"returns a list of all available keys"
		result=list()

		for user in self._smimeuser:
			result.append(user)

		return result
 
 	##################
	#smimeprivate_keys
	################## 

	@_dbg
	def smimeprivate_keys(self):
		"returns a list of all available private keys"
		result=list()

		for user in self._smimeuser:

			if self._smimeuser[user][2]!=None:
				result.append(user)

		return result

#############
#_sql_backend
#############

class _sql_backend(_base_storage):

	#####
	#init
	#####
 
	@_dbg
	def init(self):
		self._DATABASE="gpgmailencrypt"
		self._USERMAPSQL="SELECT x_gpg FROM gpgusermap WHERE username=?"
		self._ENCRYPTIONMAPSQL="SELECT encrypt FROM encryptionmap WHERE user= ?"
		self._SMIMEUSERSQL=("SELECT publickey,cipher FROM smimeusers "
							"WHERE user= ?")
		self._SMIMEPUBLICKEYSQL="SELECT user,publickey,cipher FROM smimeusers"
		self._SMIMEPRIVATEKEYSQL=("SELECT user,privatekey,cipher FROM "
									"smimeusers WHERE privatekey IS NOT NULL")
		self._USER="gpgmailencrypt"
		self._PASSWORD=""
		self._HOST="127.0.0.1"
		self._PORT=4711
		self._USE_SQLUSERMAP=True
		self._USE_SQLENCRYPTIONMAP=True
		self._USE_SQLSMIME=True
		self._db=None
		self._cursor=None
		self.placeholder="?"
		self._textbackend=get_backend("TEXT",self.parent)

	########
	#connect
	########

	def connect(self):
		raise NotImplementedError
	
	################
	#read_configfile
	################
 
	@_dbg
	def read_configfile(self,cfg):

		if cfg.has_section('sql'):

			try:
				self._DATABASE=os.path.expanduser(cfg.get('sql','database'))
			except:
				pass

			try:
				self._USERMAPSQL=cfg.get('sql','usermapsql')
			except:
				pass

			try:
				self._ENCRYPTIONMAPSQL=cfg.get('sql','encryptionmapsql')
			except:
				pass

			try:
				self._SMIMEUSERSQL=cfg.get('sql','smimeusersql')
			except:
				pass

			try:
				self._SMIMEPUBLICKEYSQL=cfg.get('sql','smimepublickeysql')
			except:
				pass

			try:
				self._SMIMEPRIVATEKEYSQL=cfg.get('sql','smimeprivatekeysql')
			except:
				pass

			try:
				self._USER=cfg.get('sql','user')
			except:
				pass

			try:
				self._PASSWORD=cfg.get('sql','password')
			except:
				pass

			try:
				self._HOST=cfg.get('sql','host')
			except:
				pass

			try:
				self._PORT=cfg.getint('sql','port')
			except:
				pass

			try:
				self._USE_SQLUSERMAP=cfg.getboolean('sql','use_sqlusermap')
			except:
				pass

			try:
				self._USE_SQLENCRYPTIONMAP=cfg.getboolean('sql',
														'use_sqlencryptionmap')
			except:
				pass

			try:
				self._USE_SQLSMIME=cfg.getboolean('sql',
														'use_sqlsmime')
			except:
				pass

		self._textbackend.read_configfile(cfg)
		self.connect()

	########
	#usermap
	########
 
	@_dbg
	def usermap(self, user):

		if not self._USE_SQLUSERMAP:
			return self._textbackend.usermap(user)
		
		self.debug(self._USERMAPSQL.replace("?",user))

		if not self.execute(self._USERMAPSQL,user):
			return ""
			
		r=self._cursor.fetchone()

		try:
			self._cursor.fetchall()
		except:
			pass
		
		if r==None:
			raise KeyError(user)
			
		self.debug("sqlbackend %s usermap %s=>%s"%(self._backend,user,r[0]))
		return r[0]

	########
	#execute
	########
	
	@_dbg
	def execute(self, sql,fields=None):
		
		if self._cursor== None:
			self.connect()
			self.log("Try to reconnect to database server","w")

			if self._cursor== None:
				raise KeyError(user)
		
		try:
			f=None
			if fields!=None:
				f=(fields,)
			self._cursor.execute(sql.replace("?",self.placeholder),f)
		except:
			self.log_traceback()
			self._cursor=None
			self._db=None
			return False
		
		return True

	##############
	#encryptionmap
	##############
 
	@_dbg
	def encryptionmap(self, user):

		if not self._USE_SQLENCRYPTIONMAP:
			return self._textbackend.encryptionmap(user)
			
		if not	self.execute(self._ENCRYPTIONMAPSQL,user):
			return ""
			
		r=self._cursor.fetchone()

		try:
			self._cursor.fetchall()
		except:
			pass

		if r==None:
			raise KeyError(user)

		self.debug("sqlbackend %s encryptionmap %s=>%s"%(self._backend,
														user,
														r[0]))
		return r[0].split(":")

	##########
	#smimeuser
	##########
 
	@_dbg
	def smimeuser(self, user):

		if not self._USE_SQLSMIME:
			return self._textbackend.smimeuser(user)
		
		if not 	self.execute(self._SMIMEUSERSQL,user):
			return ""
						
		r=self._cursor.fetchone()

		try:
			self._cursor.fetchall()
		except:
			pass
		
		if r==None:
			raise KeyError(user)

		cipher=self.parent._SMIMECIPHER

		if len(user)>1:
			tmpcipher=r[1].upper().strip()

			if len(tmpcipher)>0 and tmpcipher!="DEFAULT":
				cipher=tmpcipher

		upath=os.path.join(self.parent._SMIMEKEYHOME,r[0])
		publicpath=os.path.expanduser(upath)
		
		result= [publicpath,cipher]
		self.debug("sqlbackend %s smimuser %s=>%s"%(self._backend,
														user,
														result))
		return result
		
	#################
	#smimepublic_keys
	#################
 
	@_dbg
	def smimepublic_keys(self):

		if not self._USE_SQLSMIME:
			return self._textbackend.smimepublic_keys()
		rows=list()

		if not 	self.execute(self._SMIMEPUBLICKEYSQL):
			return rows
						
		for r in self._cursor:

			user=r[0]
			publickey=r[1]
			cipher=self.parent._SMIMECIPHER
			tmpcipher=r[2].upper().strip()

			if len(tmpcipher)>0 and tmpcipher!="DEFAULT":
				cipher=tmpcipher

		
			result= [user,publickey,cipher]

			if publickey!=None:
				rows.append(result)

		return rows
		
	##################
	#smimeprivate_keys
	##################
 
	@_dbg
	def smimeprivate_keys(self):

		if not self._USE_SQLSMIME:
			return self._textbackend.smimepublic_keys()
		rows=list()

		if not	self.execute(self._SMIMEPRIVATEKEYSQL):
			return rows
			
		for r in self._cursor:

			user=r[0]
			privatekey=r[1]
			cipher=self.parent._SMIMECIPHER
			tmpcipher=r[2].upper().strip()

			if len(tmpcipher)>0 and tmpcipher!="DEFAULT":
				cipher=tmpcipher

		
			result= [user,privatekey,cipher]

			if privatekey!=None:
				rows.append(result)

		return rows
		
#################
#_SQLITE3_BACKEND
#################

class _SQLITE3_BACKEND(_sql_backend):

	########
	#connect
	########

	def connect(self):
		result=False

		try:
			import sqlite3
		except:
			self.log("SQLITE driver not found","e")
			self.log_traceback()
			return result
			
		if os.path.exists(self._DATABASE):
			self._db=sqlite3.connect(self._DATABASE)
			self._cursor=self._db.cursor()
			result=True
		else:
			self.log("Database '%s' does not exist"%self._DATABASE,"e")
		
		return result

###############
#_MYSQL_BACKEND
###############

class _MYSQL_BACKEND(_sql_backend):

	#####
	#init
	#####
 
	@_dbg
	def init(self):
		_sql_backend.init(self)
		self._PORT=3306
		self.placeholder="%s"
		
	########
	#connect
	########

	def connect(self):
		result=False

		try:
			import mysql.connector as mysql
			from mysql.connector import errorcode
		except:
			self.log("MYSQL (mysql.connector) driver not found","e")
			self.log_traceback()
			return result
			
		try:
			self._db=mysql.connect(	database=self._DATABASE,
									user=self._USER,
									password=self._PASSWORD,
									host=self._HOST,
									port=self._PORT)
			self._cursor=self._db.cursor()
			result=True
		except mysql.Error as err:

			if err.errno == errorcode.ER_ACCESS_DENIED_ERROR:
				self.log(	"Could not connect to database, "
							"wrong username and/or password"
							,"e")
			elif err.errno == errorcode.ER_BAD_DB_ERROR:
				self.log("database %s does not exist"%self._DATABASE,"e")

			self.log_traceback()

		return result

###############
#_ODBC_BACKEND
###############

class _ODBC_BACKEND(_sql_backend):

	#####
	#init
	#####
 
	@_dbg
	def init(self):
		_sql_backend.init(self)
		self._PORT=0
		self.placeholder="?"
		
	########
	#connect
	########

	def connect(self):
		result=False

		try:
			import pydodbc as odbc
		except:
			self.log("ODBC (pyodbc) driver not found","e")
			self.log_traceback()
			return result
			
		try:
			self._db=odbc.connect(database=self._DATABASE)
			self._cursor=self._db.cursor()
			result=True
		except :
			self.log_traceback()

		return result

####################
#_POSTGRESQL_BACKEND
####################

class _POSTGRESQL_BACKEND(_sql_backend):

	#####
	#init
	#####

	@_dbg
	def init(self):
		_sql_backend.init(self)
		self._PORT=5432
		self.placeholder="$1"

	########
	#connect
	########

	def connect(self):
		result=False

		try:
			import psycopg2 as pg
		except:
			self.log("Postqresql(psycopg2) driver not found","e")
			self.log_traceback()
			return result

		try:
			self._db=pg.connect(	database=self._DATABASE,
									user=self._USER,
									password=self._PASSWORD,
									host=self._HOST,
									port=self._PORT)
			self._cursor=self._db.cursor()
			result=True
		except:
			self.log_traceback()

		return result

###############
#_MSSQL_BACKEND
###############

class _MSSQL_BACKEND(_sql_backend):

	#####
	#init
	#####

	@_dbg
	def init(self):
		_sql_backend.init(self)
		self._PORT=1433
		self.placeholder="%s"

	########
	#connect
	########

	def connect(self):
		result=False

		try:
			import pymssql
		except:
			self.log("MS SQL Server(pymssql) driver not found","e")
			self.log_traceback()
			return result

		try:
			self._db=pymssql.connect(	database=self._DATABASE,
									user=self._USER,
									password=self._PASSWORD,
									host=self._HOST,
									port=self._PORT)
			self._cursor=self._db.cursor()
			result=True
		except:
			self.log_traceback()

		return result

################################################################################

################
#get_backendlist
################

def get_backendlist():
	return ["MSSQL","MYSQL","ODBC","POSTGRESQL","SQLITE3","TEXT"]

############
#get_backend
############

def get_backend(backend,parent):
		backend=backend.upper().strip()

		if backend=="SQLITE3":

			try:
				return _SQLITE3_BACKEND(parent=parent,backend="SQLITE3")
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")

		elif backend=="MSSQL":

			try:
				return _MSSQL_BACKEND(parent=parent,backend="MSSQL")
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")

		elif backend=="MYSQL":

			try:
				return _MYSQL_BACKEND(parent=parent,backend="MYSQL")
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")

		elif backend=="ODBC":

			try:
				return _ODBC_BACKEND(parent=parent,backend="ODBC")
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")

		if backend=="POSTGRESQL":

			try:
				return _POSTGRESQL_BACKEND(parent=parent,backend="POSTGRESQL")
			except:
				parent.log("Storage backend %s could not be loaded"%backend,"e")
				
		else:
			# default backend=="TEXT":
			return _TEXT_BACKEND(parent=parent,backend="TEXT")


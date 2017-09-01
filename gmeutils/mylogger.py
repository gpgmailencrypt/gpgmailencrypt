#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import os
from .child 			import _gmechild
from .version 			import *
from   ._dbg 			import _dbg
from   gmeutils.helpers			import *

import inspect
import time
import sys

if os.name=="nt":
	import logging
	import logging.handlers
else:
	import syslog

LOG_DEBUG=1
LOG_INFO=2
LOG_WARNING=3
LOG_ERR=4

################
# CLASS mylogger
################

class mylogger(_gmechild):
	l_none=1
	l_syslog=2
	l_file=3
	l_stderr=4

	#########
	#__init__
	#########

	def __init__(self,parent):
		self._level=0
		self.parent=parent
		self._LOGGING=self.l_none
		self._DEBUG=False
		self._systemmessages=[]
		_gmechild.__init__(self,parent=parent,filename=__file__)

		if os.name=="nt":
			self._initwindows()
		else:
			self._initlinux()

		self.init()

	#############
	#_initwindows
	#############

	@_dbg
	def _initwindows(self):
		self._logger=logging.getLogger("gpgmailencrypt")
		self._loggingformatter=logging.Formatter("%(asctime)s: %(levelname)s:"
		" %(filename)s(%(lineno)d) %(message)s",datefmt="%a %d %H:%M:%S")
		self._logginghandler=logging.FileHandler(filename="gpgmailencrypt.log")
		self._logginghandler.setFormatter(self._loggingformatter)
		self._logger.addHandler(self._logginghandler)

	###########
	#_initlinux
	###########

	@_dbg
	def _initlinux(self):
		syslog.openlog("gpgmailencrypt",syslog.LOG_PID,syslog.LOG_MAIL)

	#####
	#init
	#####

	@_dbg
	def init(self):
		self._LOGFILE=""
		self._DEBUG=False
		self._level=0
		self._logfile=None
		self._DEBUGSEARCHTEXT=[]
		self._DEBUGEXCLUDETEXT=[]

	######
	#close
	######

	@_dbg
	def close(self):

		if self._LOGGING==self.l_file and self._logfile!=None:
			self._logfile.close()

		if os.name=="nt":
			self.close_windows()
		else:
			self.close_linux()
		
	############
	#close_linux
	############

	@_dbg
	def close_linux(self):
		syslog.closelog()

	##############
	#close_windows
	##############

	@_dbg
	def close_windows(self):
		logging.shutdown()

	################
	#read_configfile
	################

	@_dbg
	def read_configfile(self,cfg):

		if cfg.has_section('logging'):

			try:
				l=cfg.get('logging','log').lower()

				if l=="syslog":
					self._LOGGING=self.l_syslog
					self._prepare_syslog()
				elif l=='file':
					self._LOGGING=self.l_file
				elif l=='stderr':
					self._LOGGING=self.l_stderr
				else:
					self._LOGGING=self.l_none

			except:
				pass

			try:
				self._LOGFILE=cfg.get('logging','file')
			except:
				pass

			try:
				self._DEBUG=cfg.getboolean('logging','debug')
			except:
				pass

			try:
				s=cfg.get('logging','debugsearchtext')

				if len(s)>0:
					self._DEBUGSEARCHTEXT=s.split(",")

			except:
				pass

			try:
				e=cfg.get('logging','debugexcludetext')

				if len(e)>0:
					self._DEBUGEXCLUDETEXT=e.split(",")

			except:
				pass

	###################
	#_parse_commandline
	###################
	
	@_dbg
	def _parse_commandline(self,_opts):
		for _opt, _arg in _opts:

			if _opt == '--version':
				print("gpgmailencrypt version %s from %s"%(VERSION,DATE))
				exit(0)

			if _opt  =='-l' or  _opt == '--log':
				self._LOGGING=self.l_stderr

				if isinstance(_arg,str):

					if _arg=="syslog":
						self._LOGGING=self.l_syslog
						if os.name!="nt":
							self._prepare_syslog()
					elif _arg=="stderr":
						self._LOGGING=self.l_stderr
					else:
						self._LOGGING=self.l_none

	################
	#_prepare_syslog
	################

	@_dbg
	def _prepare_syslog(self):
			self._LOGGING=self.l_syslog
			syslog.openlog("gpgmailencrypt",syslog.LOG_PID,syslog.LOG_MAIL)

	####
	#log
	####
	
	def log(self,
			msg,
			infotype="m",
			ln=-1,
			filename="",
			force=False):
		"prints logging information"

		if ((self._LOGGING!=self.l_none) or (force==True)):

			if infotype in ['d','m','w']:
				space=" "*self._level
			else:
				space=" "

			if ln==-1:
				ln=inspect.currentframe().f_back.f_back.f_lineno

			if filename==None or len(filename)==0:
				filename=inspect.getfile(inspect.currentframe().f_back)

			filename=os.path.split(filename)[1]
			_lftmsg=20
			prefix="Info"

			if infotype=='w':
				self.parent._systemwarnings+=1
				prefix="Warning"
			elif infotype=='e':
				self.parent._systemerrors=+1
				prefix="Error"
			elif infotype=='d':
				prefix="Debug"

			prefix=prefix.ljust(7)
			t=time.localtime(time.time())
			_lntxt="%s %s:%s"%(filename.ljust(18),str(ln).rjust(4),space)
			tm=("%02d.%02d.%04d %02d:%02d:%02d:" % (t[2],t[1],t[0],t[3],
													t[4],t[5])).ljust(_lftmsg)

			if infotype in["w","e"]:
				self._systemmessages.append([tm[:-1],infotype,msg])

			txt=splitstring(msg,800)
			c=0

			for t in txt:

				if (ln>0):
					t=_lntxt+t

				l=len(txt)

				if l>1 and c<l-1:
					t=t+"\\"

				c+=1

				if self._LOGGING==self.l_syslog:

					if os.name=="nt":
						self._syslogwindows(t,infotype,ln,filename)
					else:
						self._sysloglinux(t,infotype,ln,filename)

				elif  (self._LOGGING==self.l_file
						and self._logfile!=None
						and not self._logfile.closed):
					#write to _logfile
					self._logfile.write("%s %s:%s\n"%(tm,prefix,t ))
					self._logfile.flush()
				else: # self._LOGGING==self.l_stderr:
					# print to stderr if nothing else works
					sys.stderr.write("%s %s:%s\n"%(tm,prefix,t ))

	###############
	#_syslogwindows
	###############

	def _syslogwindows(self,msg,infotype,ln,filename):
		if infotype=='w':
			self._logger.warning(msg)
		elif infotype=='d':
			self._logger.debug(msg)
		else:
			self._logger.info(msg)

	#############
	#_sysloglinux
	#############

	def _sysloglinux(self,t,infotype,ln,filename):
		level=syslog.LOG_INFO

		if infotype=='w':
			level=syslog.LOG_WARNING
			t="WARNING "+t
		elif infotype=='e':
			level=syslog.LOG_ERR
			t="ERROR "+t
		elif infotype=='d':
			level=syslog.LOG_DEBUG
			t="DEBUG "+t

		syslog.syslog(level,t)

	######
	#debug
	######

	def debug(  self,
				msg,
				lineno=0,
				filename=""):
		"prints debugging information"

		if self._DEBUG:

			if lineno==0:
				ln=inspect.currentframe().f_back.f_lineno
			else:
				ln=lineno
			if filename==None or len(filename)==0:
				filename=inspect.getfile(inspect.currentframe().f_back)
			
			inspect.currentframe().f_back
			self.log(msg,"d",ln,filename=filename)

	############
	#set_logging
	############

	def set_logging( self, logmode):
		if isinstance(logmode,str):
			logmode=logmode.strip().lower()

			if self._LOGGING!=self.l_syslog and logmode=="syslog":
				self._LOGGING=self.l_syslog
				self._prepare_syslog()
			elif logmode=="stderr":
				self._LOGGING=self.l_stderr
			else:
				self._LOGGING=self.l_none

	############
	#get_logging
	############

	@_dbg
	def get_logging( self):
		if self._LOGGING==self.l_syslog:
			return "syslog"
		elif self._LOGGING==self.l_stderr:
			return "stderr"
		else:
			return "none"

	#############
	#_set_logmode
	#############

	@_dbg
	def _set_logmode(self):

		try:

			if self._LOGGING==self.l_file and len(self._LOGFILE)>0:
				self._logfile = open(self._LOGFILE, 
										mode='a',
										encoding="UTF-8",
										errors=unicodeerror)

		except:
			self._logfile=None
			self._LOGGING=self.l_stderr
			self.log_traceback()

	##########
	#set_debug
	##########

	@_dbg
	def set_debug(self,dbg):
		"set debug mode"

		if dbg:
			self._DEBUG=True

			if os.name=="nt":
				self._logger.setLevel(logging.DEBUG)
		else:
			self._DEBUG=False

			if os.name=="nt":
				self._logger.setLevel(logging.INFO)

	##########
	#get_debug
	##########

	@_dbg
	def get_debug(self):
		return self._DEBUG

	#############
	#is_debugging
	#############

	@_dbg
	def is_debugging(self):
		"returns True if gpgmailencrypt is in debuggin mode"
		return self._DEBUG


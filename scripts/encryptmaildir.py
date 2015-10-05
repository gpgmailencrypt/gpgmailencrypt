#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
#License GPL v3
#Author Horst Knorr 
from configparser import RawConfigParser
from io import StringIO
from os.path import expanduser
import re,sys,tempfile,os,subprocess,atexit,time,getopt,random,syslog,inspect,time,signal,gzip,bz2,shutil,socket
VERSION="1.0.0"
DATE="02.09.2015"
ZIP_EMAILS=True
#################################
#Definition of general functions#
#################################

####
#log
####
def log(msg,infotype="m",ln=-1):
	global logfile,SYSLOG
	if ln==-1:
		ln=inspect.currentframe().f_back.f_lineno
	if LOGGING:
		_lftmsg=20
		prefix="Info"
		if infotype=='w':
			prefix="Warning"
		elif infotype=='e':
			prefix="Error"
		elif infotype=='d':
			prefix="Debug"
		t=time.localtime(time.time())
		_lntxt="Line %i: "%ln
		tm=("%02d.%02d.%04d %02d:%02d:%02d:" % (t[2],t[1],t[0],t[3],t[4],t[5])).ljust(_lftmsg)
		if (ln>0):
			msg=_lntxt+str(msg)
		if SYSLOG:
			#write to syslog
			level=syslog.LOG_INFO
			if infotype=='w':
				level=syslog.LOG_WARNING
			elif infotype=='e':
				level=syslog.LOG_ERR
				msg="ERROR "+msg
			elif infotype=='d':
				level=syslog.LOG_DEBUG
				msg="DEBUG "+msg
			syslog.syslog(level,msg)
		elif  logfile!=None:
			#write to logfile
			logfile.write("%s %s: %s\n"%(tm,prefix,msg ))
		else:
			# print to stderr if nothing else works
			sys.stdout.write("%s %s: %s\n"%(tm,prefix,msg ))
######
#debug
######
def debug(msg,ln=-1):
	if ln==-1:
		ln=inspect.currentframe().f_back.f_lineno
	if DEBUG:
		log(msg,"d",ln)
#######
#lineno
#######
def lineno():
    return inspect.currentframe().f_back.f_lineno

############
#print_usage
############
def print_usage():
	print("encryptmaildir")
	print("==============")
	print("License: GPL 3")
	print("Author:  Horst Knorr")
	print("Version: %s from %s"%(VERSION,DATE))
	print("\nUsage:\n")
	print("encryptmaildir [options] directory1 [directory2 ...]")
	print("\nOptions:\n")
	print("-c f --config f: adds the configfile 'f'")
	print("-d --debug:      print debugging information into logfile")
	print("-h --help :      print this help")
	print("-k f --keyhome f:sets gpg key directory to 'f'")
	print("-u --user:	user email address")
	print("-v --dovecot:	uses Dovecot maildirlock")
	print("-x --example:    print example config file")
	print("-y --syslog:     log to syslog, otherwise to logfile")
	print("\n")
####################
#print_exampleconfig
####################
def print_exampleconfig():
	print("\n[default]")
	print("gpgmailencrypt = /usr/local/bin/gpgmailencrypt.py")
	print()
	print("[mail]")
	print("dovecot = no")
	print("maildirlock = /usr/lib/dovecot/maildirlock")
	print("\n")
###############
#prepare_syslog
###############
def prepare_syslog():
		global LOGGING,SYSLOG
		LOGGING=True
		SYSLOG=True
		syslog.openlog("encryptmaildir",syslog.LOG_PID,syslog.LOG_MAIL)
###############
#shellquote
###############
def shellquote(s):
	return s.replace("'", "'\''").replace(" ","\ ")#.replace(",","\,").replace("=","\=").replace(":","\:")
#########
#get_lock
#########
def get_lock(directory):
	global _pids
	try:
		debug ("%s %s"%(MAILDIRLOCK,directory))
		process = subprocess.Popen([MAILDIRLOCK,directory,'10'], stdout=subprocess.PIPE)
	except:
		log("get_lock: Couldn't call 'maildirlock'!","e",lineno())
		exit(1)
	output=process.stdout.read()
	pid=-1
	try:
		pid=int(output)
	except:
		log("get_lock: Couldn't get lock for '%s'" %directory,"e",lineno())
		pid=-1
	else:
		debug("get_lock: %s"%str(pid),ln=lineno())
		_pids.append(pid)
	return pid
##########
#free_lock
##########
def free_lock(pid):
	global _pids
	try:
		os.kill(pid,signal.SIGKILL)
	except:
		log("free_lock: Pid '%i' doesn't exist"%pid,"e",lineno())
	try:
		debug( "free_lock _pids.remove(%i)"%pid,ln=lineno())
		_pids.remove(pid)
	except:
		log( "free_lock _pids.remove(%i) wasn't possible"%pid,"e",lineno())
##################
#class maildirname
##################
class maildirname:
		def __init__(self):
			self._name=''
			self._leftpart=''
			self._middlepart=''
			self._rightpart=''
			self._flags=[]
			self._dovecotflags=dict()
		def __splitname(self,n):
			try:
				self._leftpart,self._middlepart,rp=n.split(".",2)
				rp=rp.split(":2,")
				self._flags=[]
				self._flags.extend(rp[1])
				self._flags.sort()
				rp=rp[0].split(",")
				self._rightpart=rp[0]
				if len(rp)>1:
					self._dovecotflags=dict()
					for f in rp[1:]:
						r=f.split("=")
						self._dovecotflags[r[0]]=r[1]
			except:
				log("Name '%s' does not fit name convention part1.part2.part3:2,<flags>"%n,"e",lineno())
		def set_name(self,n):
			self._name=n.strip()
			self.__splitname(self._name)
		def originalname(self):
			return self._name
		def name(self):
			n=self._leftpart+"."+self._middlepart+"."+self._rightpart
			dvflags=[]
			for f in list(self._dovecotflags.keys()):
				dvflags.append(f+"="+self._dovecotflags[f])
			dvflags=",".join(dvflags)
			if len(dvflags)>0:
				n=n+","+dvflags
			flag="".join(self._flags)
			n=n+":2,"+flag
			return n
		def set_leftpart(self,p)	:
			self._leftpart=p.strip()
		def leftpart(self):
			return self._leftpart
		def set_middlepart(self,p)	:
			self._middlepart=p.strip()
		def middlepart(self):
			return self._middlepart
		def set_rightpart(self,p)	:
			self._rightpart=p.strip()
		def rightpart(self):
			return self._rightpart
		def set_flags(self,fl):
				self._flags=[]
				self._flags.extend(fl)
				self._flags.sort()			
		def flags(self):
			return self._flags
		def dovecotflags(self):
			return self._dovecotflags
		def set_dovecotflags(self,df=()):
			self._dovecotflags=dict()
			if type(df)==str:
				
				r=df.split("=")
				if len(r)!=2:
					log("Flag '%s' does not fit the convention name=value"%df,"w",lineno())	
				else:			
					self._dovecotflags[r[0]]=r[1]
			else:
				for f in df:
					r=f.split("=")
					if len(r)!=2:
						print("Flag '%s' does not fit the convention name=value"%f)
					else:
						self._dovecotflags[r[0]]=r[1]
		def debug(self):
			print("name:'%s'"%self._name)
			print("left:'%s'"%self._leftpart)
			print("middle:'%s'"%self._middlepart)
			print("right:'%s'"%self._rightpart)
			print("flags:'%s'"%self._flags)
			print("dovecotflags:'%s'"%self._dovecotflags)
			if "S" in self._dovecotflags:
				print("dovecot filesize=%s"%self._dovecotflags["S"])
			if "W" in self._dovecotflags:
				print("dovecot wflag=%s"%self._dovecotflags["W"])
			print("End debug name:'%s'"%self._name)

###########
#is_gzipped
###########
def is_gzipped(fname):
	_res=True
	debug("is_gzipped:%s"%fname,lineno())
	try:
		f = gzip.open(fname, 'rb')
	except:		
		log("is_gzipped: Couldn't open file '%s'"%fname,"w",ln=lineno())
		return False
	else:
		try:
			file_content = f.read()
		except:
			_res=False
		finally:
			f.close()
	result="No"
	if _res:
		result="Yes"
	debug("is_gzipped: %s '%s'"%(result,fname),lineno())
	return _res
##########
#gzip_file
##########
def gzip_file(fname):
	_res=False
	debug("gZip '%s'"%fname,lineno())
	if is_gzipped(fname):
		log("File '%s' is already gzipped"%fname,"i",lineno())
		return True
	try:
		_times=os.stat(fname)
	except:
		log("gzip_file: File attributes for file '%s' couldn't be read"%fname,"e",ln=lineno())
		return False
	_newname=tempfile.NamedTemporaryFile(mode='wb',delete=True,prefix='mail-')
	_newname.close()
	_newname=_newname.name
	try:
		f_in = open(fname, 'rb')
	except:
		log("gzip_file: Couldn't open file '%s'"%fname,"e",ln=lineno())
		return
	else:	
		try:
			f_out = gzip.open(_newname, 'wb')
			f_out.write(f_in.read())
		except:
			log("gzip_file: Couldn't zip file '%s'" %fname,"e",ln=lineno())
		else:
			_res=True
			f_out.close()
		finally:
			f_in.close()
	if _res:
		try:
			os.utime(_newname,(_times.st_atime,_times.st_mtime))
		except:
			log("gzip_file: Fileflags of file '%s' couldn't be set"%_newname,"w",ln=lineno())
		try:
			shutil.move(_newname,fname)
		except:
			log("gzip_file: Error moving temporary file from '%(NEW)s' to '%(OLD)s'"%{"NEW":_newname,"OLD":fname},"e",lineno()) 
			log("'%(m1)s %(m2)s'"%{"m1":sys.exc_info()[0],"m2":sys.exc_info()[1]},"e",lineno())
			_res=False
	debug("gZip End '%s'"%fname,lineno())
	return _res
############
#gunzip_file
############
def gunzip_file(fname):
	_res=False
	_newname=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
	_newname.close()
	_newname=_newname.name
	debug("gUnzip '%s'"%fname,lineno())
	try:
		_times=os.stat(fname)
	except:
		log("gunzip_file: Couldn't load file attributes of file '%s'"%fname,"e",lineno())
		return False
	try:
		f_out = open(_newname, 'wb')
	except:
		log ("gunzip_file: Couldn't open tempfile '%s'"%_newname,"e",lineno())
		return False
	try:
		f_in = gzip.open(fname, 'rb')
	except:
		log ("gunzip_file: Couldn't open file '%s'"%fname,"e",lineno())
		return False
	else:	
		try:
			f_out.write(f_in.read())
		except:
			log("Couldn't gunzip '%s'"%fname,"e",ln=lineno())
			f_in.close()
			os.remove(_newname)
			return False
		_res=True
		f_out.close()
		f_in.close()
	if _res:
		try:
			os.utime(_newname,(_times.st_atime,_times.st_mtime))
		except:
			log("gzip_file: Couldn't set file flags of file '%s'"%_newname,"w",lineno())
		try:
			shutil.move(_newname,fname)
		except:
			log("gzip_file: Couldn't move temporary file '%(NEW)s' to '%(OLD)s'"%{"NEW":_newname,"OLD":fname},"e",lineno()) 
			log("'%(m1)s %(m2)s'"%{"m1":sys.exc_info()[0],"m2":sys.exc_info()[1]},"e",lineno())
			return False
	else:
		try:
			os.remove(_newname)
		except:
			log("gunzip_file: Couldn't delete temporary file '%s'"%_newname,"w",lineno())
	return True
#############
#is_bz2zipped
#############
def is_bz2zipped(fname):
	_res=True
	debug("is_bz2zipped:%s"%fname,lineno())
	try:
		f = bz2.BZ2File(fname, 'rb')
	except:		
		log("is_bz2ipped: Couldn't open file '%s'"%fname,"w",ln=lineno())
		return False
	else:
		try:
			file_content = f.read()
		except:
			_res=False
		finally:
			f.close()
	result="No"
	if _res:
		result="Yes"
	debug("is_bz2zipped: %s '%s'"%(result,fname),lineno())
	return _res
############
#bz2zip_file
############
def bz2zip_file(fname):
	_res=False
	debug("bz2Zip '%s'"%fname,lineno())
	if is_bz2zipped(fname):
		log("File '%s' is already bz2zipped"%fname,"i",lineno())
		return True
	try:
		_times=os.stat(fname)
	except:
		log("bz2zip_file: File attributes for file '%s' couldn't be read"%fname,"e",ln=lineno())
		return False
	_newname=tempfile.NamedTemporaryFile(mode='wb',delete=True,prefix='mail-')
	_newname.close()
	_newname=_newname.name
	try:
		f_in = open(fname, 'rb')
	except:
		log("bz2zip_file: Couldn't open file '%s'"%fname,"e",ln=lineno())
		return False
	else:	
		try:
			f_out = bz2.BZ2File(_newname, 'wb')
			f_out.write(f_in.read())
		except:
			log("bz2zip_file: Couldn't zip file '%s'" %fname,"e",ln=lineno())
		else:
			_res=True
			f_out.close()
		finally:
			f_in.close()
	if _res:
		try:
			os.utime(_newname,(_times.st_atime,_times.st_mtime))
		except:
			log("bz2zip_file: Fileflags of file '%s' couldn't be set"%_newname,"w",ln=lineno())
		try:
			shutil.move(_newname,fname)
		except:
			log("bz2zip_file: Error moving temporary file from '%(NEW)s' to '%(OLD)s'"%{"NEW":_newname,"OLD":fname},"e",lineno()) 
			_res=False
	debug("bz2Zip End '%s'"%fname,lineno())
	return _res
##############
#bz2unzip_file
##############
def bz2unzip_file(fname):
	_res=False
	_newname=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
	_newname.close()
	_newname=_newname.name
	debug("bz2Unzip '%s'"%fname,lineno())
	try:
		_times=os.stat(fname)
	except:
		log("bz2unzip_file: Couldn't load file attributes of file '%s'"%fname,"e",lineno())
		return False
	try:
		f_out = open(_newname, 'wb')
	except:
		log ("bz2unzip_file: Couldn't open tempfile '%s'"%_newname,"e",lineno())
		return False
	try:
		f_in = bz2.BZ2File(fname, 'rb')
	except:
		log ("bz2unzip_file: Couldn't open file '%s'"%fname,"e",lineno())
		return False
	else:	
		try:
			f_out.write(f_in.read())
		except:
			log("Couldn't unzip '%s'"%fname,"e",ln=lineno())
			f_in.close()
			os.remove(_newname)
			return False
		_res=True
		f_out.close()
		f_in.close()
	if _res:
		try:
			os.utime(_newname,(_times.st_atime,_times.st_mtime))
		except:
			log("bz2zip_file: Couldn't set file flags of file '%s'"%_newname,"w",lineno())
		try:
			shutil.move(_newname,fname)
		except:
			log("bz2zip_file: Couldn't move temporary file '%(NEW)s' to '%(OLD)s'"%{"NEW":_newname,"OLD":fname},"e",lineno()) 
			return False
	else:
		try:
			os.remove(_newname)
		except:
			log("bz2unzip_file: Couldn't delete temporary file '%s'"%_newname,"w",lineno())
	return True
###########
#do_finally
###########
def do_finally():
	global _pids
	while len(_pids)>0:
		free_lock(_pids[0])
		#log("free_lock: '%s'"%str(_pids[0]))
	if checked_files >0:
		plural=""
		if checked_files >1:
			plural="s"
		log("User %s: %i mail%s checked for encryption"%(USER,checked_files,plural))
################
#read_configfile
################	
def read_configfile():
	global cfg, DEBUG,DOVECOT,GPGMAILENCRYPT,MAILDIRLOCK
	cfg=dict()
	_cfg = RawConfigParser()
	try:
		_cfg.read(CONFIGFILE)
	except:
		log("Could not read config file '%s'."%CONFIGFILE,"e",ln=lineno())
		return
	for sect in _cfg.sections():
		cfg[sect] = dict()
		for (name, value) in _cfg.items(sect):
			cfg[sect][name] = value
	if 'default' in cfg:
		if 'gpgmailencrypt' in cfg['default']:
			GPGMAILENCRYPT=cfg['default']['gpgmailencrypt']
	if 'mail' in cfg:
		if 'dovecot' in cfg['mail'] and cfg['mail']['dovecot']=="yes":
			DOVECOT=True
		if 'maildirlock' in cfg['mail']:
			MAILDIRLOCK=cfg['mail']['maildirlock']
##################
#parse_commandline
##################
def parse_commandline():
	global to_addrs
	global CONFIGFILE,DEBUG,DOVECOT,DIRECTORIES,KEYHOME,USER,LOGFILE,LOGGING,SYSLOG
	try:
		cl=sys.argv[1:]
		_opts,_remainder=getopt.gnu_getopt(cl,'c:dhk:n:u:vxy',['config=','debug','dovecot','example', 'help', 'keyhome=' ,'user=','syslog'])
	except getopt.GetoptError as e:
		log("unknown commandline parameter '%s'"%str(e),"e",lineno())
		exit(2)
	for _opt, _arg in _opts:
		if _opt  =='-y' or  _opt == '--syslog':
		   	prepare_syslog()
	for _opt, _arg in _opts:
		if _opt  =='-d' or  _opt == '--debug':
	   		DEBUG=True
		if (_opt  =='-c' or  _opt == '--config') and _arg!=None:
	   		_arg=_arg.strip()
	   		if len(_arg)>0:
	   			CONFIGFILE=_arg
	   			break
		if _opt  =='-h' or  _opt == '--help':
	   		print_usage()
	   		exit(0)
		if _opt  =='-k' or  _opt == '--keyhome':
	   		KEYHOME=_arg
		if _opt  =='-u' or _opt == '--user':
	   		USER=_arg
		if _opt  =='-v' or _opt == '--dovecot':
	   		DOVECOT=True
		if _opt  =='-x' or  _opt == '--example':
	   		print_exampleconfig()
	   		exit(0)
		if _opt  =='-y' or  _opt == '--syslog':
		   	prepare_syslog()
	if len(_remainder)>0:
		DIRECTORIES.extend(_remainder[0:])
	else:
		log("No directories added","e",lineno())
		print_usage()
		exit(2)
#############
#encrypt_dir
#############
def encrypt_dir(arg,dirname,names):
	global mtime,newtime,checked_files
	lockdir=dirname.replace("/cur","").replace("/new","")
	if not ("/cur" in dirname.lower()) and not ("/new" in dirname.lower()):
		return
	if "courierimapkeyword" in dirname:
		return
	if DOVECOT:
		pid=get_lock(lockdir)
		if pid == -1:
			return
	mtimefile=expanduser(dirname+"/"+MTIMEFILE)
	try:
		m=open(mtimefile)
		mtime=float(m.read())
		newtime=mtime
		debug("checktime: %i"%newtime)
		m.close()
	except:
		log("Could not read Mtimefile '%s'"%mtimefile,"w",lineno())
	for n in names:
		if (DOVECOT and "dovecot" in n) or (MTIMEFILE in n) or("subscriptions" in n) or ("courierimap" in n):
			debug("Ignore '%s'"%n)
			continue
		f="%s/%s"%(dirname,n)
		filetime=os.stat(f).st_mtime
		_gzipped=False
		_bz2zipped=False
		debug("check file '%s'"%f,lineno())
		try:
			_times=os.stat(f)
		except:
			log("Couldn't load file attributes of file '%s'"%f,"e",lineno())
		if os.path.isfile(f) and filetime >mtime:
			debug( "checkfile:%s %s"%(time.ctime(os.stat(f).st_mtime),f))
			checked_files+=1
			if is_gzipped(f):
				_gzipped=True
				if not gunzip_file(f):
					log("Couldn't gunzip Mail, continue","e",lineno())
					continue
			elif is_bz2zipped(f):
				_bz2zipped=True
				if not bz2unzip_file(f):
					log("Couldn't bz2unzip Mail, continue","e",lineno())
					continue
			out=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
			out.close()
			cmd="%(CMD)s -l syslog  -a -k %(KEY)s -f '%(IN)s' -m %(OUT)s %(USER)s" %{"CMD":GPGMAILENCRYPT, "KEY":KEYHOME, "IN":f, "OUT":out.name, "USER":USER}
			_result = os.system(cmd)/256
			if _result == 0:
				try:
					new=open(f,'w')
				except:
					log ("Error opening file '%s'"%f,"e",lineno())
					continue
				try:
					out=open(out.name)
				except:
					log ("Error opening file '%s'"%out.name,"e",lineno())
					os.unlink(out.name)
					continue
				new.write(out.read())
				new.close()
				nf=new.name
				del new
				fsize=str(os.stat(nf).st_size)
				if ZIP_EMAILS:
					if _gzipped:
						gzip_file(nf)
					elif _bz2zipped:
						bz2zip_file(nf)
				if DOVECOT:
					mname=maildirname()
					mname.set_name(n)
					#mname.set_rightpart(socket.gethostname())
					mname.set_dovecotflags(("S="+fsize,"W="+fsize))
					newf="%s/%s"%(dirname,mname.name())
					os.rename(nf,newf)
					nf=newf
				try:
					os.utime(nf,(_times.st_atime,_times.st_mtime))
				except:
					log("Couldn't set file flags of file '%s'"%nf,"w",lineno())
				filetime=os.stat(nf).st_mtime
				debug("filetime: %i"%filetime,lineno())
				if filetime>newtime:
					newtime=filetime
					debug("new checktime: %i"%newtime)
			else:
				debug("Encryption ended with error %i"%_result,lineno())
				filetime=os.stat(f).st_mtime
				debug("filetime: %i"%filetime)
				if filetime>newtime:
					newtime=filetime
					debug("new checktime: %i"%newtime)
			os.unlink(out.name)
	try:
		m=open(mtimefile,'w')
		m.write(str(newtime))
		m.close()
	except:
		log("Could not open Mtimefile '%s'"%mtimefile,"w",lineno())
	if DOVECOT:
		free_lock(pid)
##################
#Main routine
##################
#Internal variables
logfile=None
cfg = dict()
_pids=[]
mtime=0
newtime=0
checked_files=0
atexit.register(do_finally)

#GLOBAL CONFIG VARIABLES
DEBUG=False
LOGGING=True
LOGFILE=""
DOVECOT=False
MAILDIRLOCK='/usr/lib/dovecot/maildirlock'
SENDSTDOUT=False
SYSLOG=False
KEYHOME="~/.gnupg"
GPGMAILENCRYPT="./gpg-mailencrypt.py"
MTIMEFILE=".encryptmaildir"
USER=''
CONFIGFILE='/etc/encryptmaildir'
DIRECTORIES=[]
#get configuration
read_configfile()
parse_commandline()
#encrypt directories
try:
	for directory in DIRECTORIES:
		debug("DIR: '%s'"%directory,lineno())
		os.walk(directory,encrypt_dir,None)
except KeyboardInterrupt:
	log("Keyboard: CTRL-C Exit ...",ln=lineno())
except:
  	log("Bug: Exception '%(m1)s %(m2)s' occured!"%{"m1":sys.exc_info()[0],"m2":sys.exc_info()[1]})
		

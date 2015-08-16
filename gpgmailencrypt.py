#!/usr/bin/python3
# -*- coding: utf-8 -*- 
#based on gpg-mailgate
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
"""
gpgmailencrypt can encrypt e-mails.
It supports
* PGP/Inline
* PGP/Mime
* S/Mime

It can be used normally as a script doing everything on command line, in daemon mode, where gpgmailencrypt acts as an encrypting smtp server or as a module for programmers. 
It takes e-mails and  returns the e-mail encrypted to another e-mail server if a encryption key exists for the receiver. Otherwise it returns the e-mail unencrypted.
The encryption method can be selected per user.
Usage:
Create a configuration file with "gpgmailencrypt.py -x > ~/gpgmailencrypt.conf"
and copy this file into the directory /etc
"""
VERSION="2.0sigma"
DATE="16.08.2015"
from configparser import ConfigParser
import email,email.message,email.mime,email.mime.base,email.mime.multipart,email.mime.application,email.mime.text,smtplib,mimetypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import email.utils as emailutils
import html.parser,base64,quopri,uu,binascii
import re,sys,tempfile,os,stat,subprocess,atexit,time,datetime,getopt,random,syslog,inspect,gzip
from email.generator import Generator
from io import StringIO as _StringIO
from io import BytesIO as _BytesIO
from os.path import expanduser
import locale,traceback,hashlib
from functools import wraps
import smtpd,asyncore, signal,ssl,asynchat,socket,select

try:
	import readline
	has_readline=True
except:
	has_readline=False
################################
#Definition of general functions
################################
#####
#_dbg
#####
_level=0
def _dbg(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		global _DEBUG
		global _level
		try:
			_DEBUG
		except:
			_DEBUG=False
		if not _DEBUG:
			return func(*args,**kwargs)
		lineno=0
		endlineno=0
		try:
			source=inspect.getsourcelines(func)
			lineno=source[1]
			endlineno=lineno+len(source[0])
		except:
			pass
		_level+=1
		debug("START %s"%func.__name__,lineno)
		result=func(*args,**kwargs)
		debug("END %s"%func.__name__,endlineno)
		_level-=1
		if _level<0:
			_level=0
		return result
	return wrapper
#####
#init
#####
@_dbg
def init():
	"initiales the module and reads the config file"
	global o_mail,o_stdout,o_file,l_none,l_syslog,l_file,l_stderr,m_daemon,m_script
	global _logfile,_addressmap,_encryptionmap,_smimeuser,_tempfiles,_deferdir
	global _mailcount
	global _encryptgpgcomment,_encryptheader
	global _encoding
	global _DEBUG,_LOGGING,_LOGFILE,_ADDHEADER,_HOST,_PORT,_DOMAINS,_CONFIGFILE
	global _INFILE,_OUTFILE,_PREFERRED_ENCRYPTION,_GPGKEYHOME,_ALLOWGPGCOMMENT,_GPGCMD
	global _SMIMEKEYHOME,_SMIMECMD,_SMIMECIPHER,_SMIMEKEYEXTRACTDIR,_SMIMEAUTOMATICEXTRACTKEYS
	global _SPAMSUBJECT,_OUTPUT, _DEBUGSEARCHTEXT,_DEBUGEXCLUDETEXT,_LOCALE,_LOCALEDB
	global _RUNMODE,_SERVERHOST,_SERVERPORT,_STATISTICS_PER_DAY, _ADMINS
	global _SMTPD_USE_SMTPS,_SMTPD_USE_AUTH,_SMTPD_PASSWORDFILE,_SMTPD_SSL_KEYFILE,_SMTPD_SSL_CERTFILE,_smtpd_passwords
	global _AUTHENTICATE,_SMTP_CREDENTIAL,_SMTP_USER,_SMTP_PASSWORD,_deferlist
	global _count_totalmails, _count_encryptedmails,_count_deferredmails,_count_alreadyencryptedmails,_count_alarms
	global _unicodeerror
	#Internal variables
	atexit.register(_do_finally_at_exit)
	_logfile=None
	_addressmap = dict()
	_encryptionmap = dict()
	_smimeuser = dict()
	_tempfiles = list()
	_mailcount=0
	o_mail=1
	o_stdout=2
	o_file=3
	l_none=1
	l_syslog=2
	l_file=3
	l_stderr=4
	m_daemon=1
	m_script=2
	_encryptgpgcomment="Encrypted by gpgmailencrypt version %s"%VERSION
	_encryptheader="X-GPGMailencrypt"
	_smtpd_passwords=dict()
	_encoding = locale.getdefaultlocale()[1]
	if _encoding==None:
		_encoding="UTF-8"
	_deferlist=os.path.expanduser("~/deferlist.txt")
	_deferdir=expanduser("~/gpgmaildirtmp")
	if not os.path.exists(_deferdir):
		os.makedirs(_deferdir)
	_count_totalmails=0
	_count_encryptedmails=0
	_count_deferredmails=0
	_count_alreadyencryptedmails=0
	_count_alarms=0
	_unicodeerror="replace"
	_STATISTICS_PER_DAY=1
	#GLOBAL CONFIG VARIABLES
	_DEBUG=False
	_LOGGING=l_none
	_LOGFILE=""
	_ADDHEADER=False
	_HOST='localhost'
	_PORT=25
	_SERVERHOST="127.0.0.1"
	_SERVERPORT=1025
	_AUTHENTICATE=False
	_SMTP_CREDENTIAL=""
	_SMTP_USER=""
	_SMTP_PASSWORD=""
	_DOMAINS=""
	_CONFIGFILE='/etc/gpgmailencrypt.conf'
	_INFILE=""
	_OUTFILE=""
	_PREFERRED_ENCRYPTION="PGPINLINE"
	_GPGKEYHOME="~/.gnupg"
	_ALLOWGPGCOMMENT=False
	_GPGCMD='/usr/bin/gpg2'
	_SMIMEKEYHOME="~/.smime"
	_SMIMEKEYEXTRACTDIR="%s/extract"%_SMIMEKEYHOME
	_SMIMECMD="/usr/bin/openssl"
	_SMIMECIPHER="DES3"
	_SMIMEAUTOMATICEXTRACTKEYS=False
	_SPAMSUBJECT="***SPAM"
	_OUTPUT=o_mail 
	_DEBUGSEARCHTEXT=[]
	_DEBUGEXCLUDETEXT=[]
	_LOCALE="EN"
	_LOCALEDB={
	#"CN":("审读","文件"),
	"DE":("Termin","Datei"),
	"EN":("appointment","file"),
	"ES":("cita","fichero"),
	"FR":("rendez-vous","fichier"),
	"IT":("appuntamento","file"),
	"NL":("Termijn","Bestand"),
	"PL":("termin","plik"),
	"PT":("hora","ficheiro"),
	"RU":("срок","файл"),
	"SE":("möte","fil"),
	}
	_RUNMODE=m_script
	_SMTPD_USE_SMTPS=False
	_SMTPD_USE_AUTH=False
	_SMTPD_PASSWORDFILE="/etc/gpgmailencrypt.pw"
	_SMTPD_SSL_KEYFILE="/etc/gpgsmtpd.key"
	_SMTPD_SSL_CERTFILE="/etc/gpgsmtpd.cert"
	_ADMINS=[]
	_read_configfile()
	if _DEBUG:
		for a in _addressmap:
			debug("_addressmap: '%s'='%s'"%(a,_addressmap[a]))
###################
#_parse_commandline
###################
def _parse_commandline():
	receiver=[]
	global _DEBUG,_CONFIGFILE,_LOGGING,_LOGFILE,_GPGKEYHOME,_ADDHEADER,_HOST,_PORT,_INFILE,_OUTFILE,_OUTPUT
	global _PREFERRED_ENCRYPTION,_RUNMODE
	try:
		cl=sys.argv[1:]
		_opts,_remainder=getopt.gnu_getopt(cl,'ac:de:f:hk:l:m:n:o:pvxy',
  		['addheader','config=','daemon','example','help','keyhome=','log=','output=','pgpmime','verbose'])
	except getopt.GetoptError as e:
		_LOGGING=l_stderr
		log("unknown commandline parameter '%s'"%e,"e")
		exit(2)

	for _opt, _arg in _opts:
		if _opt  =='-l' or  _opt == '--log':
			_LOGGING=l_stderr
			if type(_arg)==str:
				if _arg=="syslog":
					_LOGGING=l_syslog
					_prepare_syslog
				else:
					_LOGGING=l_stderr

	for _opt, _arg in _opts:
		if (_opt  =='-c' or  _opt == '--config') and _arg!=None:
	   		_arg=_arg.strip()
	   		if len(_arg)>0:
	   			_CONFIGFILE=_arg
	   			log("read new config file '%s'"%_CONFIGFILE)
	   			_read_configfile()
	   			break

	for _opt, _arg in _opts:
		if _opt  =='-a' or  _opt == '--addheader':
	   		_ADDHEADER=True
		if _opt  =='-v' or  _opt == '--verbose':
	   		_DEBUG=True
		if _opt  =='-e':
			a=_arg.lower()
			if a=="smime":
				_PREFERRED_ENCRYPTION="SMIME"
			elif a=="pgpmime":
				_PREFERRED_ENCRYPTION="PGPMIME"
			elif a=="none":
				_PREFERRED_ENCRYPTION="NONE"
			else:
				_PREFERRED_ENCRYPTION="PGPINLINE"
		debug("Set _PREFERRED_ENCRYPTION to '%s'"%_PREFERRED_ENCRYPTION)
		if _opt  =='-f':
	   		_INFILE=expanduser(_arg)
	   		debug("Set _INFILE to '%s'"%_INFILE)
		if _opt  =='-h' or  _opt == '--help':
	   		show_usage()
	   		exit(0)
		if _opt  =='-k' or  _opt == '--keyhome':
	   		_GPGKEYHOME=_arg
	   		debug("Set gpgkeyhome to '%s'"%_GPGKEYHOME)
		if _opt  =='-l' or  _opt == '--log':
			_LOGGING=l_stderr
			if type(_arg)==str:
				if _arg=="syslog":
					_LOGGING=l_syslog
				elif _arg=='file':
					_LOGGING=l_file
				else:
					_LOGGING=l_stderr

		if _opt  =='-o' or  _opt == '--output':
			if type(_arg)==str:
				if _arg=="mail":
					_OUTPUT=o_mail
				elif _arg=="stdout":
					_OUTPUT=o_stdout
				elif _arg=="file":
					_OUTPUT=o_file
				else:
					_OUTPUT=o_stdout
		if _opt  =='-m':
	   		_OUTFILE=expanduser(_arg)
	   		_OUTPUT=o_file
	   		debug("Set _OUTFILE to '%s'"%_OUTFILE)
		if (_opt  =='-s' or  _opt == '--stdout') and len(_OUTFILE)==0:
		   	_OUTPUT=o_stdout
		if (_opt  =='-d' or  _opt == '--daemon'):
		   	_RUNMODE=m_daemon
		if _opt  =='-x' or  _opt == '--example':
	   		print_exampleconfig()
	   		exit(0)
	if not _RUNMODE==m_daemon:
		if len(_remainder)>0 :
			receiver=_remainder[0:]
			debug("set addresses from commandline to '%s'"%receiver)
		else:
			_LOGGING=l_stderr
			log("gpgmailencrypt needs at least one recipient at the commandline, %i given"%len(_remainder),"e")
			exit(1)
	return receiver
###########
#show_usage
###########
def show_usage():
	"shows the command line options to stdout"
	print ("gpgmailencrypt")
	print ("===============")
	print ("based on gpg-mailgate")
	print ("License: GPL 3")
	print ("Author:  Horst Knorr <gpgmailencrypt@gmx.de>")
	print ("Version: %s from %s"%(VERSION,DATE))
	print ("\nUsage:\n")
	print ("gpgmailencrypt [options] receiver@email.address < Inputfile_from_stdin")
	print ("\nOptions:\n")
	print ("-a --addheader:  adds %s header to the mail"%_encryptheader)
	print ("-c f --config f: use configfile 'f'. Default is /etc/gpgmailencrypt.conf")
	print ("-d --daemon :    start gpgmailencrypt as smtpserver")
	print ("-e pgpinline :   preferred encryption method, either 'pgpinline','pgpmime' or 'smime'")
	print ("-f mail :        reads email file 'mail', otherwise from stdin")
	print ("-h --help :      print this help")
	print ("-k f --keyhome f:sets gpg key directory to 'f'")
	print ("-l t --log t:    print information into _logfile, with valid types 't' 'none','stderr','syslog','file'")
	print ("-n domainnames:  sets the used domain names (comma separated lists, no space), which should be encrypted, empty is all")
	print ("-m mailfile :    write email file to 'mailfile', otherwise email will be sent via smtp")
	print ("-o p --output p: valid values for p are 'mail' or 'stdout', alternatively you can set an outputfile with -m")
	print ("-p --pgpmime:    create email in PGP/MIME style")
	print ("-x --example:    print example config file")
	print ("-v --verbose:    print debugging information into _logfile")
	print ("")
####################
#print_exampleconfig
####################
def print_exampleconfig():
	"prints an example config file to stdout"
	print ("[default]")
	print ("prefered_encryption = gpginline 		# valid values are 'gpginline','gpgmime' or 'smime'")
	print ("add_header = no         			# adds a %s header to the mail"%_encryptheader)
	print ("domains =    		     			# comma separated list of domain names, \
that should be encrypted, empty is all")
	print ("spamsubject =***SPAM				# Spam recognition string, spam will not be encrypted")
	print ("output=mail 					# valid values are 'mail'or 'stdout'")
	print ("locale=en 					# DE|EN|ES|FR|IT|NL|PL|PT|RU|SE'")
	print ("")
	print ("[gpg]")
	print ("keyhome = /var/lib/gpgmailencrypt/.gnupg   	# home directory of public  gpgkeyring")
	print ("gpgcommand = /usr/bin/gpg2")
	print ("allowgpgcomment = yes				# allow a comment string in the GPG file")
	print ("")
	print ("[logging]")
	print ("log=none 					# valid values are 'none', 'syslog', 'file' or 'stderr'")
	print ("file = /tmp/gpgmailencrypt.log")
	print ("debug = no")
	print ("")
	print ("[mailserver]")
	print ("host = 127.0.0.1				#smtp host")
	print ("port = 25	    				#smtp port")
	print ("authenticate = False    			#user must authenticate")
	print ("smtpcredential =/etc/gpgmailencrypt.cfg		#file that keeps user and password information")	
	print("						#file format 'user=password'")
	print ("")
	print ("[encryptionmap]    ")
	print ("user@domain.com = PGPMIME			#PGPMIME|PGPINLINE|SMIME|NONE")
	print ("")
	print ("[usermap]")
	print ("#user_nokey@domain.com = user_key@otherdomain.com")
	print ("")
	print ("[smime]")
	print ("keyhome = ~/.smime				#home directory of S/MIME public key files")
	print ("opensslcommand = /usr/bin/openssl")
	print ("defaultcipher = DES3				#DES3|AES128|AES192|AES256")
	print ("extractkey= no					#automatically scan emails and extract smime public keys to 'keyextractdir'")
	print ("keyextractdir=~/.smime/extract")
	print ("")
	print ("[smimeuser]")
	print ("smime.user@domain.com = user.pem[,cipher]	#public S/MIME key file [,used cipher, see defaultcipher]")
	print ("")
	print ("[daemon]")
	print ("host = 127.0.0.1				#smtp host")
	print ("port = 10025    				#smtp port")
	print ("smtps = False    				#use smtps encryption")
	print ("sslkeyfile = /etc/gpgsmtp.key			#the x509 certificate key file")
	print ("sslcertfile = /etc/gpgsmtp.crt			#the x509 certificate cert file")
	print ("authenticate = False    			#users must authenticate")
	print ("smtppasswords = /etc/gpgmailencrypt.pw		#file that includes users and passwords")
	print ("						#file format 'user=password'")
	print ("statistics=1					#how often per day should statistical data be logged (0=none) max is 24")

#############
#_set_logmode
#############
@_dbg
def _set_logmode():
	""
	global _logfile,_LOGGING,_LOGFILE
	try:
		if _LOGGING==l_file and len(_LOGFILE)>0:
			_logfile = open(_LOGFILE, 'a')
	except:
		_logfile=None
		_LOGGING=l_stderr
		log_traceback()
#############
#_splitstring
#############
def _splitstring(txt,length=80):
	def chunkstring(string, length):
		return (string[0+i:length+i] for i in range(0, len(string), length))
	return list(chunkstring(txt,length))
####
#log
####
def log(msg,infotype="m",ln=-1):
	"prints logging information"
	global _logfile, _level
	if _LOGGING!=l_none:
		if infotype=='d':
			space=" "*_level
		else:
			space=" "
		if ln==-1:
			ln=inspect.currentframe().f_back.f_lineno
		_lftmsg=20
		prefix="Info"
		if infotype=='w':
			prefix="Warning"
		elif infotype=='e':
			prefix="Error"
		elif infotype=='d':
			prefix="Debug"
		t=time.localtime(time.time())
		_lntxt="Line %i:%s"%(ln,space)
		tm=("%02d.%02d.%04d %02d:%02d:%02d:" % (t[2],t[1],t[0],t[3],t[4],t[5])).ljust(_lftmsg)
		txt=_splitstring(msg,240)
		c=0
		for t in txt:
			if (ln>0):
				t=_lntxt+t
			l=len(txt)
			if l>1 and c<l-1:
				t=t+"\\"
			c+=1
			if _LOGGING==l_syslog:
				#write to syslog
				level=syslog.LOG_INFO
				if infotype=='w':
					level=syslog.LOG_WARNING
				elif infotype=='e':
					level=syslog.LOG_ERR
					t="ERROR "+t
				elif infotype=='d':
					level=syslog.LOG_DEBUG
					t="DEBUG "+t
				syslog.syslog(level,t)
			elif  _LOGGING==l_file and _logfile!=None:
				#write to _logfile
				_logfile.write("%s %s: %s\n"%(tm,prefix,t ))
				_logfile.flush()
			else:
				# print to stderr if nothing else works
				sys.stdout.write("%s %s: %s\n"%(tm,prefix,t ))
##############
#log_traceback
##############
def log_traceback():
		exc_type, exc_value, exc_tb = sys.exc_info()
		error=traceback.format_exception(exc_type, exc_value, exc_tb)
		for e in error:
			log(" ***%s"%e.replace("\n",""),"e")
######
#debug
######
def debug(msg,lineno=0):
	"prints debugging information"
	if _DEBUG:
		if lineno==0:
			ln=inspect.currentframe().f_back.f_lineno
		else:
			ln=lineno
		log(msg,"d",ln)
################
#_debug_keepmail
################
@_dbg
def _debug_keepmail(mailtext):
	searchtext=mailtext.lower()
	#return True
	for txt in _DEBUGSEARCHTEXT:
		if txt.lower() in searchtext:
			for exclude in _DEBUGEXCLUDETEXT:
				if exclude.lower() in searchtext:
					return False
			return True
	return False
#####################
#_store_temporaryfile
#####################
@_dbg
def _store_temporaryfile(message,add_deferred=False,spooldir=False,fromaddr="",toaddr=""):
	global _deferred_emails,_count_deferredmails
	debug("_store_temporaryfile add_deferred=%s"%add_deferred)
	try:
		tmpdir=None
		if add_deferred or spooldir:
			tmpdir=_deferdir
		f=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-',dir=tmpdir)
		f.write(message.encode("UTF-8",_unicodeerror))
		f.close()
		if add_deferred:
			_deferred_emails.append([f.name,fromaddr,toaddr,time.time()])
			_count_deferredmails+=1
			log("store_temporaryfile.append deferred email '%s'"%f.name)
		else:
			log("Message in temporary file '%s'"%f.name)
		return f.name
	except:
		log("Couldn't save email in temporary file, write error")
		log_traceback()
	return None
################
#_prepare_syslog
################
@_dbg
def _prepare_syslog():
		global _LOGGING
		_LOGGING=l_syslog
		syslog.openlog("gpgmailencrypt",syslog.LOG_PID,syslog.LOG_MAIL)
######################
#_read_smtpcredentials
######################	
@_dbg
def _read_smtpcredentials(pwfile):
	global _SMTP_USER,_SMTP_PASSWORD
	if not _AUTHENTICATE:
		return
	try:
		f=open(pwfile)
	except:
		log("hksmtpserver: Config file could not be read","e")
		log_traceback()
		exit(5)
	txt=f.read()
	f.close()
	c=0
	for l in txt.splitlines():
		try:
			name,passwd=l.split("=",1)
			_SMTP_USER=name.strip()
			_SMTP_PASSWORD=passwd.strip()
			c+=1
		except:
			pass
	debug("_read_smtpcredentials END read lines: %i"%c)
#################
#_read_configfile
#################	
@_dbg
def _read_configfile():
	global _addressmap,_encryptionmap,_GPGCMD,_DEBUG,_DOMAINS,_LOGGING,_LOGFILE,_GPGKEYHOME,_PREFERRED_ENCRYPTION
	global _ADDHEADER,_HOST,_PORT,_ALLOWGPGCOMMENT,_CONFIGFILE,_SPAMSUBJECT,_OUTPUT,_STATISTICS_PER_DAY
	global _smimeuser,_SMIMEKEYHOME,_SMIMECMD,_SMIMECIPHER,_SMIMEKEYEXTRACTDIR,_SMIMEAUTOMATICEXTRACTKEYS
	global _DEBUGEXCLUDETEXT,_DEBUGSEARCHTEXT
	global _LOCALE,_SERVERHOST,_SERVERPORT,_ADMINS
	global _AUTHENTICATE,_SMTP_CREDENTIAL
	global _SMTPD_USE_SMTPS,_SMTPD_USE_AUTH,_SMTPD_PASSWORDFILE,_SMTPD_SSL_KEYFILE,_SMTPD_SSL_CERTFILE,_deferlist
	
	_cfg = ConfigParser()
	try:
		_cfg.read(_CONFIGFILE)
	except:
		log("Could not read config file '%s'"%_CONFIGFILE,"e")
		return

	if _cfg.has_section('default'):
		if _cfg.has_option('default','add_header'):
			_ADDHEADER=_cfg.getboolean('default','add_header')
		if _cfg.has_option('default','output'):
			o=_cfg.get('default','output').lower().strip()
			if o=="mail":
				_OUTPUT=o_mail
			elif o=="stdout":
				_OUTPUT=o_stdout
			elif o=="file":
				_OUTPUT=o_file
			else:
				_OUTPUT=o_stdout
		if _cfg.has_option('default','locale'):
			_LOCALE=_cfg.get('default','locale').upper().strip()
		if _cfg.has_option('default','domains'):
			_DOMAINS=_cfg.get('default','domains')
		if _cfg.has_option('default','spamsubject'):
			_SPAMSUBJECT=_cfg.get('default','spamsubject')
		if _cfg.has_option('default','preferred_encryption'):
			p=_cfg.get('default','preferred_encryption').lower()
			if p=="smime":
				_PREFERRED_ENCRYPTION="SMIME"
			elif p=="pgpmime":
				_PREFERRED_ENCRYPTION="PGPMIME"
			else:
				_PREFERRED_ENCRYPTION="PGPINLINE"
	if _cfg.has_section('logging'):
		if _cfg.has_option('logging','log'):
			l=_cfg.get('logging','log').lower()
			if l=="syslog":
				_LOGGING=l_syslog
				_prepare_syslog()
			elif l=='file':
				_LOGGING=l_file
			elif l=='stderr':
				_LOGGING=l_stderr
			else:
				_LOGGING=l_none
		if _cfg.has_option('logging','file'):
			_LOGFILE=_cfg.get('logging','file')
		if _cfg.has_option('logging','debug') and  __name__ == "__main__":
			_DEBUG=_cfg.getboolean('logging','debug')
		if _cfg.has_option('logging','debugsearchtext'):
			s=_cfg.get('logging','debugsearchtext')
			if len(s)>0:
				_DEBUGSEARCHTEXT=s.split(",")
		if _cfg.has_option('logging','debugexcludetext'):
			e=_cfg.get('logging','debugexcludetext')
			if len(e)>0:
				_DEBUGEXCLUDETEXT=e.split(",")
	if _cfg.has_section('gpg'):
		if _cfg.has_option('gpg','keyhome'):
			k=_cfg.get('gpg','keyhome')
			if k!=None:
				_GPGKEYHOME=k.strip()
		if _cfg.has_option('gpg','gpgcommand'):
			_GPGCMD=_cfg.get('gpg','gpgcommand')
		if _cfg.has_option('gpg','allowgpgcomment'):
			_ALLOWGPGCOMMENT=_cfg.getboolean('gpg','allowgpgcomment')
	if _cfg.has_section('mailserver'):
		if _cfg.has_option('mailserver','host'):
			_HOST=_cfg.get('mailserver','host')
		if _cfg.has_option('mailserver','port'):
			_PORT=_cfg.getint('mailserver','port')
		if _cfg.has_option('mailserver','authenticate'):
			_AUTHENTICATE=_cfg.getboolean('mailserver','authenticate')
		if _cfg.has_option('mailserver','smtpcredential'):
			_SMTP_CREDENTIAL=_cfg.get('mailserver','smtpcredential')
	if _cfg.has_section('usermap'):
		for (name, value) in _cfg.items('usermap'):
				_addressmap[name] = value
	if _cfg.has_section('encryptionmap'):
		for (name, value) in _cfg.items('encryptionmap'):
				_encryptionmap[name] = value
	if _cfg.has_section('daemon'):
		if _cfg.has_option('daemon','host'):
			_SERVERHOST=_cfg.get('daemon','host')
		if _cfg.has_option('daemon','port'):
			_SERVERPORT=_cfg.getint('daemon','port')
		if _cfg.has_option('daemon','smtps'):
			_SMTPD_USE_SMTPS=_cfg.getboolean('daemon','smtps')
		if _cfg.has_option('daemon','sslkeyfile'):
			_SMTPD_SSL_KEYFILE=_cfg.get('daemon','sslkeyfile')
		if _cfg.has_option('daemon','sslcertfile'):
			_SMTPD_SSL_CERTFILE=_cfg.get('daemon','sslcertfile')
		if _cfg.has_option('daemon','authenticate'):
			_SMTPD_USE_AUTH=_cfg.getboolean('daemon','authenticate')
		if _cfg.has_option('daemon','smtppasswords'):
			_SMTPD_PASSWORDFILE=_cfg.get('daemon','smtppasswords')
		if _cfg.has_option('daemon','statistics'):
			_STATISTICS_PER_DAY=_cfg.getint('daemon','statistics')
			if _STATISTICS_PER_DAY >24:
				_STATISTICS_PER_DAY=24
		if _cfg.has_option('daemon','admins'):
			admins=_cfg.get('daemon','admins').split(",")
			for a in admins:
				_ADMINS.append(a.strip())
	if _cfg.has_section('smime'):
		if _cfg.has_option('smime','opensslcommand'):
			_SMIMECMD=_cfg.get('smime','opensslcommand')
		if _cfg.has_option('smime','defaultcipher'):
			_SMIMECIPHER=_cfg.get('smime','defaultcipher').upper().strip()
		if _cfg.has_option('smime','keyhome'):
			k=_cfg.get('smime','keyhome')
			if k!=None:
				_SMIMEKEYHOME=k.strip()
		if _cfg.has_option('smime','extractkey'):
			_SMIMEAUTOMATICEXTRACTKEYS=_cfg.getboolean('smime','extractkey')
		if _cfg.has_option('smime','keyextractdir'):
			k=_cfg.get('smime','keyextractdir')
			if k!=None:
				_SMIMEKEYEXTRACTDIR=k.strip()
	s=_SMIME(_SMIMEKEYHOME)
	_smimeuser.update(s.create_keylist(_SMIMEKEYHOME))
	if _cfg.has_section('smimeuser'):
		for (name, value) in _cfg.items('smimeuser'):
			user=value.split(",")
			cipher=_SMIMECIPHER
			if len(user)==2:
				cipher=user[1].upper().strip()
			path=os.path.expanduser(os.path.join(_SMIMEKEYHOME,user[0]))
			if os.path.isfile(path):
				_smimeuser[name] = [path,cipher]
	_set_logmode()
	if _DEBUG:
		for u in _smimeuser:
			debug("SMimeuser: '%s %s'"%(u,_smimeuser[u]))
	if _AUTHENTICATE:
		_read_smtpcredentials(_SMTP_CREDENTIAL)
########################
#_remove_mail_from_queue
########################
@_dbg
def _remove_mail_from_queue(m_id):
	global _email_queue
	try:
		if m_id>-1:
			mail=_email_queue[m_id]
			try:
				debug("_remove_mail_from_queue file '%s'"%mail[0])
				os.remove(mail[0])
			except:
				pass
			del _email_queue[m_id]
	except:
		log("mail %i could not be removed from queue"%m_id)
		log_traceback()
#############
#_send_rawmsg
#############
@_dbg
def _send_rawmsg(m_id,mailtext,msg,from_addr, to_addr):
	try:
		message = email.message_from_string( mailtext )
		if _ADDHEADER and not _encryptheader in message and msg:
			message.add_header(_encryptheader,msg)
		_send_msg(m_id,message,from_addr,to_addr)
	except:
		log("_send_rawmsg: exception _send_textmsg")
		log_traceback()
		_send_textmsg(m_id,mailtext,from_addr,to_addr)
##########
#_send_msg
##########
@_dbg
def _send_msg( m_id,message,from_addr,to_addr ):
	global _OUTPUT,_mailcount
	debug("_send_msg output %i"%_OUTPUT)
	if isinstance(message,str):
		_send_textmsg(m_id,message,from_addr,to_addr)
	else:
		if _ADDHEADER and not _encryptheader in message:
			message.add_header(_encryptheader,_encryptgpgcomment)
		_send_textmsg(m_id,message.as_string(),from_addr,to_addr)
##############
#_send_textmsg
##############
@_dbg
def _send_textmsg(m_id,message, from_addr,to_addr,store_deferred=True):
	global _OUTPUT,_mailcount,_email_queue
	global _AUTHENTICATE,_SMTP_USER,_SMTP_PASSWORD
	debug("_send_textmsg output %i"%_OUTPUT)
	if _OUTPUT==o_mail:
		if len(to_addr) == 0:
			log("Couldn't send email, recipient list is empty!","e")
			return False
		debug("Sending email to: <%s>" % to_addr)
		try:
			smtp = smtplib.SMTP(_HOST, _PORT)
			smtp.ehlo_or_helo_if_needed()
			try:
				if smtp.has_extn("starttls"):
					debug("_send_textmsg starttls")
					smtp.starttls()
					smtp.ehlo_or_helo_if_needed()
			except:
				debug("smtp.starttls on server failed")
			if _AUTHENTICATE and smtp.has_extn("auth"):
				debug("_send_textmsg: authenticate at smtp server with user %s"%_SMTP_USER)
				try:
					smtp.login(_SMTP_USER,_SMTP_PASSWORD)
				except smtplib.SMTPAuthenticationError:
					log("Could not send email, could not authenticate","e")
					debug("_send_textmsg: store_deferred %s" % store_deferred)
					if store_deferred:
						_store_temporaryfile(message,add_deferred=True,fromaddr=from_addr,toaddr=to_addr)
					return False
			debug("smtp.sendmail")
			message=re.sub(r'(?:\r\n|\n|\r(?!\n))', "\r\n", message)
			smtp.sendmail( from_addr, to_addr, message.encode("UTF-8") )
			_remove_mail_from_queue(m_id)
			return True
		except:
			log("Couldn't send mail!","e")
			log_traceback()
			debug("store_deferred %s"%store_deferred)
			if store_deferred:
				_store_temporaryfile(message,add_deferred=True,fromaddr=from_addr,toaddr=to_addr)
				_remove_mail_from_queue(m_id)
			return False
	elif _OUTPUT==o_file and _OUTFILE and len(_OUTFILE)>0:
		try:
			fname=_OUTFILE
			if _mailcount>0:
				fname=_OUTFILE+"."+str(_mailcount)
			f=open(fname,mode='w',encoding="UTF-8")
			f.write(message)
			f.close()
			_mailcount+=1
			return True
		except:
			log("Could not open Outputfile '%s'"%_OUTFILE,"e")
			log_traceback()
			return False
	else:
		print (message)
		return True
###################
#load_deferred_list
###################
@_dbg
def load_deferred_list():
	"loads the list with deferred emails, that have to be sent later"
	global _count_deferredmails
	global _deferred_emails
	_deferred_emails=[]
	try:
		f=open(_deferlist)
		for l in f:
			mail=l.split("|")
			mail[3]=float(mail[3])
			_deferred_emails.append(mail)
		f.close()
		_count_deferredmails=len(_deferred_emails)
	except:
		log("Couldn't load defer list '%s'"%_deferlist)
####################
#store_deferred_list
####################
@_dbg
def store_deferred_list():
	"stores the list with deferred emails, that have to be sent later"
	try:
		debug("store_deferred_list '%s'"%_deferlist)
		f=open(_deferlist,"w")
		for mail in _deferred_emails:
			mail[3]=str(mail[3])
			f.write("|".join(mail))
			f.write("\n")
		for qid in _email_queue:
			mail=_email_queue[qid]
			mail[3]=str(mail[3])
			f.write("|".join(mail))
			f.write("\n")
		f.close()
	except:
		log("Couldn't store defer list '%s'"%_deferlist)
		log_traceback()
######################
#_is_old_deferred_mail
######################
@_dbg
def _is_old_deferred_mail(mail):
	_maxage=3600*48 #48 hrs
	now=time.time()
	if (now - mail[3]) > _maxage:
		log("Deferred mail '%s' will be removed because of age"%mail[0])
		try:
			os.remove(mail[0])
		except:
			pass	
		return True
	return False
####################
#check_deferred_list
####################
@_dbg
def check_deferred_list():
	"tries to re-send deferred emails"
	global _deferred_emails,_count_deferredmails, _queue_id,email_queue
	new_list=[]
	for mail in _deferred_emails:
		try:
			f=open(mail[0])
			msg=f.read()
			f.close()
			if not _send_textmsg(-1,msg,mail[1],mail[2],store_deferred=False):
				if not _is_old_deferred_mail(mail):
					new_list.append(mail)
			else:
				log("Deferred mail successfully sent from %s to %s"%(mail[1],mail[2]))
				try:
					os.remove(mail[0])
				except:
					pass	
		except:
			log("Could not read file '%s'"%mail[0])
			if not _is_old_deferred_mail(mail):
				new_list.append(mail)	
	_deferred_emails=new_list
	debug("End check_deferred_list")		
def check_mailqueue():
	global email_queue
	for qid in _email_queue:
		mail=_email_queue[qid]
		try:
			f=open(mail[0],"rb")
			m=f.read()
			f.close()
			mailtext=m.decode("UTF-8",_unicodeerror)
			encrypt_single_mail(-1,mailtext,mail[1],mail[2])	
			del _email_queue[qid]
		except:
			log("mail couldn't be removed from email queue")
			log_traceback()
	
	
#########
#is_admin
#########
@_dbg
def is_admin(user):
	return user in _ADMINS
####################
#_do_finally_at_exit
####################
@_dbg
def _do_finally_at_exit():
	global _logfile,_tempfiles,_count_totalmails,_count_encryptedmails,_count_deferredmails
	if _RUNMODE==m_daemon:
		log("gpgmailencrypt daemon shutdown")
		_now=datetime.datetime.now()
		log("gpgmailencrypt server did run %s"%(_now-_daemonstarttime))
		_log_statistics()
	for f in _tempfiles:
		try:
			os.remove(f)
			debug("do_finally delete tempfile '%s'"%f)
		except:
			pass
	if _RUNMODE==m_daemon:
		store_deferred_list()
	if _LOGGING and _logfile!=None:
		_logfile.close()
################
#_log_statistics
################
@_dbg
def _log_statistics():
	log("Mail statistics: total: %i, encrypt: %i, were encrypted: %i, total deferred: %i, still deferred: %i" %\
	(_count_totalmails,_count_encryptedmails,_count_alreadyencryptedmails,_count_deferredmails,len(_deferred_emails)))
##############
#_new_tempfile
##############
@_dbg
def _new_tempfile():
	"creates a new tempfile"
	global _tempfiles
	f=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
	_tempfiles.append(f.name)
	debug("_new_tempfile %s"%f.name)
	return f
##############
#_del_tempfile
##############
@_dbg
def _del_tempfile(f):
	"deletes the tempfile, f is the name of the file"
	global _tempfiles
	n=""
	if type(f)!=str:
		return
	debug("_del_tempfile:%s"%f)
	try:
		_tempfiles.remove(f)
	except:
		pass
	try:
		os.remove(f)
	except:
		pass
##############
#_find_charset
##############
@_dbg
def _find_charset(msg):
	if type(msg) != str:
		return None
	find=re.search("^Content-Type:.*charset=[-_\.\'\"0-9A-Za-z]+",msg,re.I|re.MULTILINE)
	if find==None:
		return None
	charset=msg[find.start():find.end()]
	res=charset.split("=")
	if len(res)<2:
		return None
	charset=str(res[1]).replace('"','').replace("'","")
	return charset
###############
#_make_boundary
###############
@_dbg
def _make_boundary(text=None):
    _width = len(repr(sys.maxsize-1))
    _fmt = '%%0%dd' % _width    
    token = random.randrange(sys.maxsize)
    boundary = ('=' * 15) + (_fmt % token) + '=='
    if text is None:
        return boundary
    b = boundary
    counter = 0
    while True:
        cre = re.compile('^--' + re.escape(b) + '(--)?$', re.MULTILINE)
        if not cre.search(text):
            break
        b = boundary + '.' + str(counter)
        counter += 1
    return b
################
#set_output2mail
################
@_dbg
def set_output2mail():
	"outgoing email will be sent to email server"
	global _OUTFILE,_OUTPUT
	_OUTPUT=o_mail
################
#set_output2file
################
@_dbg
def set_output2file(mailfile):
	"outgoing email will be written to file 'mailfile'"
	global _OUTFILE,_OUTPUT
	if type(mailfile) != str:
		return
	_OUTFILE=expanduser(mailfile)
	_OUTPUT=o_file
##################
#set_output2stdout
##################
@_dbg
def set_output2stdout():
	"outgoing email will be written to stdout"
	global _OUTFILE,_OUTPUT
	_OUTPUT=o_stdout
###########
#get_output
###########
@_dbg
def get_output():
	"returns the output way"
	return _OUTPUT
##########
#set_debug
##########
@_dbg
def set_debug(dbg):
	"set debug mode"
	global _DEBUG
	if dbg:
		_DEBUG=True
	else:
		_DEBUG=False
###########
#set_locale
###########
@_dbg
def set_locale(l):
	"sets the locale"
	if type(l)==str:
		l=l.strip()
		if len(l)>0:
			_LOCALE=l
###############
#set_configfile
###############
@_dbg
def set_configfile(f):
	"loads the configfile f without any init"
	if not f:
		return
	cf=f.strip()
	if len(cf)>0:
		_CONFIGFILE=_arg
		log("read new config file '%s'"%_CONFIGFILE)
		_read_configfile()
###########
#get_locale
###########
@_dbg
def get_locale():
	"returns the Locale"
	return _LOCALE
###############
#get_statistics
###############
@_dbg
def get_statistics():
	"returns how many mails were handeled"
	global _count_totalmails,_count_encryptedmails,_count_deferredmails,_count_alreadyencryptedmails
	return {"total":_count_totalmails,"encrypt":_count_encryptedmails,"deferred":_count_deferredmails,"still deferred":len(_deferred_emails),"already encrypted":_count_alreadyencryptedmails}
#############
#is_debugging
#############
@_dbg
def is_debugging():
	"returns True if gpgmailencrypt is in debuggin mode"
	return _DEBUG
################################
#set_default_preferredencryption
################################
@_dbg
def set_default_preferredencryption(mode):
	"set the default preferred encryption. Valid values are SMIME,PGPMIME,PGPINLINE"
	global _PREFERRED_ENCRYPTION
	if type(mode)==str:
		m=mode.upper()
		if m in ["SMIME","PGPMIME","PGPINLINE"]:
			_PREFERRED_ENCRYPTION=mode.upper()
#########
#set_smtp
#########
@_dbg
def set_smtp(host,port,auth=False,user="",password=""):
	"sets the smtp setting for sending emails (don't mix it up with the daemon settings where the server listens)"
	_HOST=host
	_PORT=port
	_AUTHENTICATE=auth
	_SMTP_USER=user
	_SMTP_PASSWORD=password
###########
#set_daemon
###########
@_dbg
def set_daemon(host,port,smtps=False,auth=False,sslkeyfile=None,sslcertfile=None,passwordfile=None):
	"sets the smtpd daemon settings"
	_SERVERHOST=host
	_SERVERPORT=port
	_SMTPD_USE_SMTPS=smtps
	_SMTPD_USE_AUTH=auth
	if sslkeyfile:
		_SMTPD_SSL_KEYFILE=sslkeyfile
	if sslcertfile:
		_SMTPD_SSL_CERTFILE=sslcertfile
	if passwordfile:
		_SMTPD_PASSWORDFILE=passwordfile
################################
#get_default_preferredencryption
################################
def get_default_preferredencryption():
	"returns the default preferred encryption method"
	return _PREFERRED_ENCRYPTION
###################################
#Definition of encryption functions
###################################
###########
#CLASS _GPG
###########
_GPGkeys=list()
class _GPG:
	@_dbg
	def __init__(self, keyhome=None, recipient = None, counter=0):
		debug("_GPG.__init__")
		if type(keyhome)==str:
			self._keyhome = expanduser(keyhome)
		else:
			self._keyhome=expanduser('~/.gnupg')
		self._recipient = ''
		self._filename=''	
		self.count=counter
		if type(recipient) == str:
			self.set_recipient(recipient)
		debug("_GPG.__init__ end")

	@_dbg
	def set_filename(self, fname):
		if type(fname)==str:
			self._filename=fname.strip()
		else:
			self._filename=''
	
	@_dbg
	def set_keyhome(self,keyhome):
		if type(keyhome)==str:
			self._keyhome=expanduser(keyhome.strip())
		else:
			self._keyhome=''
	@_dbg
	def set_recipient(self, recipient):
		if type(recipient) == str:
			self._recipient=recipient
			global _GPGkeys
			_GPGkeys = list()
	@_dbg
	def recipient(self):
		return self._recipient	

	@_dbg
	def public_keys(self):
		if len(_GPGkeys)==0:
			self._get_public_keys()
		return _GPGkeys

	@_dbg
	def has_key(self,key):
		debug("gpg.has_key")
		if len(_GPGkeys)==0:
			self._get_public_keys()
		if type(key)!=str:
			debug("has_key, key not of type str")
			return False
		if key in _GPGkeys:	
			return True
		else:
			debug("has_key, key not in _GPGkeys")
			#debug("_GPGkeys '%s'"%str(_GPGkeys))
			return False
			
	@_dbg
	def _get_public_keys( self ):
		global _GPGkeys
		debug("_GPG._get_public_keys")
		_GPGkeys = list()
		cmd = '%s --homedir %s --list-keys --with-colons' % (_GPGCMD, self._keyhome.replace("%user",self._recipient))
		debug("_GPG.public_keys command: '%s'"%cmd)
		try:
			p = subprocess.Popen( cmd.split(' '), stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
			p.wait()
			for line in p.stdout.readlines():
				res=line.decode(_encoding,_unicodeerror).split(":")
				if res[0]=="pub" or res[0]=="uid":
					email=res[9]
					mail_id=res[4]
					try:
						found=re.search("[-a-zA-Z0-9_%\+\.]+@[-_0-9a-zA-Z\.]+\.[-_0-9a-zA-Z\.]+",email)
					except:
						log_traceback()
					if found != None:
						try:
							email=email[found.start():found.end()]
						except:
							log("splitting email didn't work","e")
							email=""
						email=email.lower()
						if len(email)>0 and _GPGkeys.count(email) == 0:
							#debug("add email address '%s'"%email)
							_GPGkeys.append(email)
						#else:
							#debug("Email '%s' already added"%email)
		except:
			log("Error opening keyring (Perhaps wrong directory '%s'?)"%self._keyhome,"e")
			log_traceback()

	@_dbg
	def encrypt_file(self,filename=None,binary=False):
		global _tempfiles,_ALLOWGPGCOMMENT
		if filename:
			set_filename(filename)
		if len(self._filename) == 0:
			log( 'Error: GPGEncryptor: filename not set',"m")
			return ''
		f=_new_tempfile()
		debug("_GPG.encrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call( ' '.join(self._command_fromfile(f.name,binary)),shell=True ) 
		debug("Encryption command: '%s'" %' '.join(self._command_fromfile(f.name,binary)))
		if _result != 0:
			log("Error executing command (Error code %d)"%_result,"e")
		if binary:
			res=open(f.name,mode="br")
			debug("GPG.encrypt_file binary open")
		else:
			res=open(f.name)
			debug("GPG.encrypt_file text open")
		encdata=res.read()
		res.close()
		_del_tempfile(f.name)
		return _result,encdata

	@_dbg
	def _command_fromfile(self,sourcefile,binary):
		cmd=[_GPGCMD, "--trust-model", "always", "-r",self._recipient,"--homedir", 
		self._keyhome.replace("%user",self._recipient), "--batch", "--yes", "--pgp7", "--no-secmem-warning", "--output",sourcefile, "-e",self._filename ]
		if _ALLOWGPGCOMMENT==True:
			cmd.insert(1,"'%s'"%_encryptgpgcomment)
			cmd.insert(1,"--comment")
		if not binary:
			cmd.insert(1,"-a")
		return cmd
#############################
#CLASS GPGENCRYPTEDATTACHMENT
#############################
class _GPGEncryptedAttachment(email.message.Message):

    def  __init__(self):
    	email.message.Message. __init__(self)
    	self._masterboundary=None
    	self._filename=None
    	self.set_type("text/plain")

    def as_string(self, unixfrom=False):
        fp = _StringIO()
        g = Generator(fp)
        g.flatten(self, unixfrom=unixfrom)
        return fp.getvalue()

    def set_filename(self,f):
    	self._filename=f

    def get_filename(self):
    	if self._filename != None:
    		return self._filename
    	else:
    		return email.message.Message.get_filename(self)

    def set_masterboundary(self,b):
    	self._masterboundary=b

    def _write_headers(self,g):
        print ('Content-Type: application/pgp-encrypted',file=g._fp)
        print ('Content-Description: PGP/MIME version identification\n\nVersion: 1\n', file=g._fp)
        print ("--%s"%self._masterboundary,file=g._fp)
        fname=self.get_filename()
        if fname == None:
        	fname="encrypted.asc"
        print ('Content-Type: application/octet-stream; name="%s"'%fname,file=g._fp)
        print ('Content-Description: OpenPGP encrypted message',file=g._fp)
        print ('Content-Disposition: inline; filename="%s"\n'%fname,file=g._fp)
##############################
#get_preferredencryptionmethod
##############################	
@_dbg
def get_preferredencryptionmethod(user):
	"returns the preferenced encryption method for user 'user'"
	debug("get_preferredencryptionmethod :'%s'"%user)
	global _PREFERRED_ENCRYPTION
	method=_PREFERRED_ENCRYPTION
	_m=""
	_u=user
	try:
		_u=_addressmap[user]
	except:
		pass
	try:
		_m=_encryptionmap[_u].upper()
	except:
		debug("get_preferredencryptionmethod User '%s' not found"%user)
		return method
	if _m in ("PGPMIME","PGPINLINE","SMIME","NONE"):
		debug("get_preferredencryptionmethod User %s (=> %s) :'%s'"%(user,_u,_m))
		return _m
	else:
		debug("get_preferredencryptionmethod: Method '%s' for user '%s' unknown" % (_m,_u))
		return method
###################
#check_gpgrecipient
###################
@_dbg
def check_gpgrecipient(gaddr):
	"returns True and the effective key-emailaddress if emails to address 'gaddr' can be GPG encrcrypted"
	global _DOMAINS
	debug("check_gpgrecipient: start '%s'"%gaddr)
	addr=gaddr.split('@')
	domain=''
	if len(addr)==2:
		domain = gaddr.split('@')[1]
	found =False
	gpg = _GPG( _GPGKEYHOME)
	try:
		gpg_to_addr=_addressmap[gaddr]
	except:
		debug("_addressmap to_addr not found")
		gpg_to_addr=gaddr
	else:
		found =True
	if gpg.has_key(gaddr):
		if (len(_DOMAINS)>0 and domain in _DOMAINS.split(',')) or len(_DOMAINS)==0:
			found=True
			debug("check_gpgrecipient: after in_key")
		else:
			debug("gpg key exists, but '%s' is not in _DOMAINS [%s]"%(domain,_DOMAINS))
	debug("check_gpgrecipient: end")
	return found,gpg_to_addr
#####################
#check_smimerecipient
#####################
@_dbg
def check_smimerecipient(saddr):
	"returns True and the effective key-emailaddress if emails to address 'saddr' can be SMIME encrcrypted"
	global _DOMAINS,_SMIMEKEYHOME
	debug("check_smimerecipient: start")
	addr=saddr.split('@')
	domain=''
	if len(addr)==2:
		domain = saddr.split('@')[1]
	found =False
	smime = _SMIME(_SMIMEKEYHOME)
	try:
		smime_to_addr=_addressmap[saddr]
	except:
		debug("smime _addressmap to_addr not found")
		smime_to_addr=saddr
	debug("check_smimerecipient '%s'"%smime_to_addr)
	if smime.has_key(smime_to_addr):
		found=True
		debug("check_smimerecipient FOUND") 
		if (len(_DOMAINS)>0 and domain in _DOMAINS.split(',')) or len(_DOMAINS)==0:
			debug("check_smimerecipient: after in_key")
		else:
			debug("smime key exists, but '%s' is not in _DOMAINS [%s]"%(domain,_DOMAINS))
			found=False
	return found, smime_to_addr
#############
#CLASS _SMIME
#############
class _SMIME:
	@_dbg
	def __init__(self, keyhome=None, recipient = None):
		global _SMIMEKEYHOME
		debug("_SMIME.__init__ %s"%_SMIMEKEYHOME)
		if type(keyhome)==str:
			self._keyhome = expanduser(keyhome)
		else:
			self._keyhome=expanduser(_SMIMEKEYHOME)
		self._recipient = ''
		self._filename=''	
		if type(recipient) == str:
			self._recipient=recipient
		debug("_SMIME.__init__ end")

	@_dbg
	def set_filename(self, fname):
		if type(fname)==str:
			self._filename=fname.strip()
		else:
			self._filename=''
	
	@_dbg
	def set_keyhome(self,keyhome):
		if type(keyhome)==str:
			self._keyhome=expanduser(keyhome.strip())
		else:
			self._keyhome=''
		
	@_dbg
	def set_recipient(self, recipient):
		if type(recipient) == str:
			self._recipient=recipient

	@_dbg
	def recipient(self):
		return self._recipient	

	@_dbg
	def has_key(self,key):
		global _smimeuser
		if type(key)!=str:
			debug("smime has_key, key not of type str")
			return False
		try:
			_u=_smimeuser[key]
		except:
			debug("smime has_key, key not found for '%s'"%key)
			return False
		return True

	@_dbg
	def encrypt_file(self,filename=None,binary=False):
		global _tempfiles
		if filename:
			set_filename(filename)
		if len(self._filename) == 0:
			log( 'Error: _SMIME: filename not set',"m")
			return ''
		f=_new_tempfile()
		debug("_SMIME.encrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call( ' '.join(self._command_fromfile(f.name,binary)),shell=True ) 
		debug("Encryption command: '%s'" %' '.join(self._command_fromfile(f.name,binary)))
		if _result != 0:
			log("Error executing command (Error code %d)"%_result,"e")
		res=open(f.name,encoding="UTF-8")
		encdata=res.read()
		res.close()
		_del_tempfile(f.name)
		m=email.message_from_string(encdata)
		return _result,m.get_payload()

	@_dbg
	def _command_fromfile(self,sourcefile,binary):
		_recipient=_smimeuser[self._recipient]
		encrypt="des3" # RFC 3583
		if _recipient[1]=="AES256":
			encrypt="aes-256-cbc"
		elif _recipient[1]=="AES128":
			encrypt="aes-128-cbc"
		elif _recipient[1]=="AES192":
			encrypt="aes-192-cbc"
		cmd=[_SMIMECMD, "smime", "-%s" %encrypt,"-encrypt", "-in",self._filename,"-out", sourcefile,  _recipient[0] ]
		return cmd

	@_dbg
	def opensslcmd(self,cmd):
		result=""
		p = subprocess.Popen( cmd.split(" "), stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
		result=p.stdout.read()
		return result, p.returncode

	@_dbg
	def get_emailaddresses(self,certfile):
		cmd=[_SMIMECMD,"x509","-in",certfile,"-text","-noout"]
		cert,returncode=self.opensslcmd(" ".join(cmd))
		cert=cert.decode("utf-8",_unicodeerror)
		email=[]
		found=re.search("(?<=emailAddress=)(.*)",cert)
		if found != None:
			try:
				email.append(cert[found.start():found.end()])
			except:
				pass
		found=re.search("(?<=email:)(.*)",cert) # get alias names
		if found != None:
			try:
				n=cert[found.start():found.end()]
				if n not in email:
					email.append(n)
			except:
				pass
		return email
	
	@_dbg
	def get_fingerprint(self,cert):
		cmd=[_SMIMECMD,"x509","-fingerprint","-in",cert,"-noout"]
		fingerprint,returncode=self.opensslcmd(" ".join(cmd))
		found= re.search("(?<=SHA1 Fingerprint=)(.*)",fingerprint.decode("UTF-8",_unicodeerror))
		if found != None:
			try:
				fingerprint=fingerprint[found.start():found.end()]
			except:
				pass
		return fingerprint
	
	@_dbg
	def extract_publickey_from_mail(self,mail,targetdir):
		debug("extract_publickey_from_mail to '%s'"%targetdir)
		f=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
		fname=f.name
		cmd=[_SMIMECMD,"smime","-in", mail,"-pk7out","2>/dev/null","|",_SMIMECMD,"pkcs7","-print_certs","-out",f.name,"2>/dev/null"]
		debug("extractcmd :'%s'"%" ".join(cmd))
		_result = subprocess.call( " ".join(cmd) ,shell=True) 
		f.close()
		size=os.path.getsize(fname)
		if size==0:
			os.remove(fname)
			return None
		fp=self.get_fingerprint(fname)
		targetname="%s/%s.pem"%(targetdir,fp)
		self._copyfile(fname,targetname)
		os.remove(fname)
		return targetname
	
	@_dbg
	def create_keylist(self,directory):
		result={}
		directory=expanduser(directory)
		try:
			_udir=os.listdir(directory)
		except:
			log("class _SMIME.create_keylist, couldn't read directory '%s'"%directory)
			return result
		_match="^(.*?).pem"
		for _i in _udir:
			  if re.match(_match,_i):
			  	f="%s/%s"%(directory,_i)
			  	emailaddress=self.get_emailaddresses(f)
			  	if len(emailaddress)>0:
			  		for e in emailaddress:
			  			result[e] = [f,_SMIMECIPHER]
		return result

	@_dbg
	def verify_certificate(self,cert):
		cmd=[_SMIMECMD,"verify",cert,"&>/dev/null"]
		_result = subprocess.call( " ".join(cmd) ,shell=True) 
		return _result==0

	@_dbg
	def _copyfile(self,src, dst):
		length=16*1024
		try:
			with open(expanduser(src), 'rb') as fsrc:
				with open(expanduser(dst), 'wb') as fdst:
				    	while 1:
				        	buf = fsrc.read(length)
				        	if not buf:
				            		break
	        				fdst.write(buf)
		except:
			log("Class smime._copyfile: Couldn't copy file!","e")
			log_traceback()
#############
#is_encrypted
#############
@_dbg
def _pgpinlineencrypted(msg):
	if msg ==None:
		return False
	if type(msg)==bytes:
		return False
	if type(msg)==email.message.Message:
		msg=msg.as_string()
	if "\n-----BEGIN PGP MESSAGE-----" in msg and "\n-----END PGP MESSAGE-----" in msg:
		return True
	else:
		return False
@_dbg
def is_pgpinlineencrypted(msg):
	"returns whether or not the email is already PGPINLINE encrypted"
	if _pgpinlineencrypted(msg):
		return True
	if type(msg)==bytes:
		return False
	if type(msg)==str:
		msg=email.message_from_string(msg)
	for m in msg.walk():
		charset=m.get_param("charset",header="Content-Type")
		cte=m["Content-Transfer-Encoding"]
		if isinstance( m.get_payload(), str):
			if _pgpinlineencrypted(_decodetxt(m.get_payload(),cte,charset)):
				return True
	return False
@_dbg
def is_pgpmimeencrypted(msg):
	"returns whether or not the email is already PGPMIME encrypted"
	if type(msg)==bytes:
		return False
	if type(msg)==str:
		msg=email.message_from_string(msg)
	contenttype=msg.get_content_type()
	if contenttype=="application/pgp-encrypted":
		return True
	else:
		return False
@_dbg
def is_smimeencrypted(msg):
	"returns whether or not the email is already SMIME encrypted"
	if type(msg)==bytes:
		return False
	if type(msg)==str:
		msg=email.message_from_string(msg)
	contenttype=msg.get_content_type()
	if contenttype=="application/pkcs7-mime":
		return True
	else:
		return False
@_dbg
def is_encrypted(msg):
	"returns whether or not the email is already encrypted"
	if is_pgpmimeencrypted(msg) or is_pgpinlineencrypted(msg) or is_smimeencrypted(msg):
		return True
	else:
		return False
#############
#_decode_html
#############
@_dbg
def _decode_html(msg):
	h=_htmldecode()
	h.feed(msg)
	return h.mydata()
_htmlname={"Acirc":"Â","acirc":"â","acute":"´","AElig":"Æ","aelig":"æ","Agrave":"À","agrave":"à","alefsym":"ℵ","Alpha":"Α",
"alpha":"α","amp":"&","and":"∧","ang":"∠","apos":"'","Aring":"Å","aring":"å","asymp":"≈","Atilde":"Ã","atilde":"ã","Auml":"Ä",
"auml":"ä","bdquo":"„","Beta":"Β","beta":"β","brvbar":"¦","bull":"•","cap":"∩","Ccedil":"Ç","ccedil":"ç","cedil":"¸","cent":"¢",
"Chi":"Χ","chi":"χ","circ":"ˆ","clubs":"♣","cong":"≅","copy":"©","crarr":"↵","cup":"∪","curren":"¤","Dagger":"‡","dagger":"†",
"dArr":"⇓","darr":"↓","deg":"°","Delta":"Δ","delta":"δ","diams":"♦","divide":"÷","Eacute":"É","eacute":"é","Ecirc":"Ê",
"ecirc":"ê","Egrave":"È","egrave":"è","empty":"∅","emsp":" ","ensp":" ","Epsilon":"Ε","epsilon":"ε","equiv":"≡","Eta":"Η",
"eta":"η","ETH":"Ð","eth":"ð","Euml":"Ë","euml":"ë","euro":"€","exist":"∃","fnof":"ƒ","forall":"∀","frac12":"½","frac14":"¼",
"frac34":"¾","frasl":"⁄","Gamma":"Γ","gamma":"γ","ge":"≥","gt":">","hArr":"⇔","harr":"↔","hearts":"♥","hellip":"…","Iacute":"Í",
"iacute":"í","Icirc":"Î","icirc":"î","iexcl":"¡","Igrave":"Ì","igrave":"ì","image":"ℑ","infin":"∞","int":"∫","Iota":"Ι","iota":"ι",
"iquest":"¿","isin":"∈","Iuml":"Ï","iuml":"ï","Kappa":"Κ","kappa":"κ","Lambda":"Λ","lambda":"λ","lang":"⟨","laquo":"«","lArr":"⇐",
"larr":"←","lceil":"⌈","ldquo":"“","le":"≤","lfloor":"⌊","lowast":"∗","loz":"◊","lrm":"‎","lsaquo":"‹","lsquo":"‘","lt":"<",
"macr":"¯","mdash":"—","micro":"µ","middot":"·","minus":"−","Mu":"Μ","mu":"μ","nabla":"∇","nbsp":" ","ndash":"–","ne":"≠","ni":"∋",
"not":"¬","notin":"∉","nsub":"⊄","Ntilde":"Ñ","ntilde":"ñ","Nu":"Ν","nu":"ν","Oacute":"Ó","oacute":"ó","Ocirc":"Ô","ocirc":"ô",
"OElig":"Œ","oelig":"œ","Ograve":"Ò","ograve":"ò","oline":"‾","Omega":"Ω","omega":"ω","Omicron":"Ο","omicron":"ο","oplus":"⊕",
"or":"∨","ordf":"ª","ordm":"º","Oslash":"Ø","oslash":"ø","Otilde":"Õ","otilde":"õ","otimes":"⊗","Ouml":"Ö","ouml":"ö","para":"¶",
"part":"∂","permil":"‰","perp":"⊥","Phi":"Φ","phi":"φ","Pi":"Π","pi":"π","piv":"ϖ","plusmn":"±","pound":"£","Prime":"″","prime":"′",
"prod":"∏","prop":"∝","Psi":"Ψ","psi":"ψ","quot":'"',"radic":"√","rang":"⟩","raquo":"»","rArr":"⇒","rarr":"→","rceil":"⌉","rdquo":"”",
"real":"ℜ","reg":"®","rfloor":"⌋","Rho":"Ρ","rho":"ρ","rlm":"‏","rsaquo":"›","rsquo":"’","sbquo":"‚","Scaron":"Š","scaron":"š",
"sdot":"⋅","sect":"§","shy":"­","Sigma":"Σ","sigma":"σ","sigmaf":"ς","sim":"∼","spades":"♠","sub":"⊂","sube":"⊆","sum":"∑",
"sup":"⊃","sup1":"¹","sup2":"²","sup3":"³","supe":"⊇","szlig":"ß","Tau":"Τ","tau":"τ","there4":"∴","Theta":"Θ","theta":"θ",
"thetasym":"ϑ","thinsp":" ","THORN":"Þ","thorn":"þ","tilde":"˜","times":"×","trade":"™","Uacute":"Ú","uacute":"ú","uArr":"⇑",
"uarr":"↑","Ucirc":"Û","ucirc":"û","Ugrave":"Ù","ugrave":"ù","uml":"¨","upsih":"ϒ","Upsilon":"Υ","upsilon":"υ","Uuml":"Ü",
"uuml":"ü","weierp":"℘","Xi":"Ξ","xi":"ξ","Yacute":"Ý","yacute":"ý","yen":"¥","Yuml":"Ÿ","yuml":"ÿ","Zeta":"Ζ","zeta":"ζ",
"zwj":"‍","zwnj":"‌"
}
#class _htmldecode
class _htmldecode(html.parser.HTMLParser):
	def __init__(self):
		html.parser.HTMLParser.__init__(self)
		self.data=""
		self.in_throwaway=0
		self.in_keep=0
		self.first_td_in_row=False
		self.dbg=False
		self.abbrtitle=None

	def get_attrvalue(self,tag,attrs):
		if attrs==None:
			return None
		for i in attrs:
			if len(i)<2:
				return None
			if i[0]==tag:
				return i[1]
		return None
				
	def handle_starttag(self, tag, attrs):
		if self.dbg:
			debug( "<%s>"%tag)
		self.handle_tag(tag,attrs)

	def handle_entityref(self, name):
		c = ""
		e=None
		try:
			e=_htmlname[name]
		except:
			pass
		if e:
			c=e
		else:
			c="&%s"%name

		self.data+=c

	def handle_endtag(self, tag):
		if self.dbg:
			debug("</%s>"%tag)
		self.handle_tag(tag,starttag=False)

	def handle_startendtag(self,tag,attrs):
		if self.dbg:
			debug("< %s/>"%tag)
		if tag=="br":
			self.handle_tag(tag,attrs,starttag=False)

	def handle_data(self, data):
		if self.in_throwaway==0:
			if self.dbg:
				debug("   data: '%s'"%data)
			if self.in_keep>0:
				self.data+=data
			elif len(data.strip())>0:
				self.data+=data.replace("\n","").replace("\r\n","")

	def handle_charref(self, name):
		if self.dbg:
			debug("handle_charref '%s'"%name)
		if name.startswith('x'):
			c = chr(int(name[1:], 16))
		else:
			c = chr(int(name))
		self.data+=c
 
	def handle_tag(self,tag,attrs=None,starttag=True):
		if tag in ("style","script","title"):
			if starttag:
				self.in_throwaway+=1
			else:
				if self.in_throwaway>0:		
					self.in_throwaway-=1
		if tag=="pre":
			if starttag:
				self.in_keep+=1
			else:
				if self.in_keep>0:		
					self.in_keep-=1
		if tag=="br":
			self.data+="\r\n"
		if len(self.data)>0:
			lastchar=self.data[len(self.data)-1]
		else:
			lastchar=""
		if tag=="hr":
			if lastchar!="\n":
				self.data+="\r\n"
			self.data+="=========================\r\n"
		if starttag:
			#Starttag
			if tag=="table":
				if lastchar!="\n":
					self.data+="\r\n"
			if tag=="tr":
				self.first_td_in_row=True
				if self.dbg:
					debug("tr first_td_in_row=True")
			if tag in ("td","th") :
				if self.dbg:
					debug("<td/th> first %s"%self.first_td_in_row)
				if  not self.first_td_in_row:
					if self.dbg:
						debug("     td/th \\t")
					self.data+="\t"
				else:
					self.first_td_in_row=False
			if tag in ("li"):
				self.data+="\r\n * "
			if tag=="q":
				self.data+="\""		
			if tag=="abbr":
				self.attrtitle=self.get_attrvalue("title",attrs)
		else:
			#Endtag
			if tag in("h1","h2","h3","h4","h5","h6","title","p","ol","ul","caption") and lastchar not in ("\n"," ","\t"):
				self.data+="\r\n"
			if tag=="tr":
				if lastchar=="\t":
					self.data=self.data[0:len(self.data)-1]
					self.data+="\r\n"
				else:
					if lastchar not in ("\n"," ","\t"):
						self.data+="\r\n"
			if tag=="abbr" and self.attrtitle!=None:
				self.data+=" [%s] "%self.attrtitle
				self.attrtitle=None
	def mydata(self):
		return self.data
############
#_split_html
############
@_dbg
def _split_html(html):
	_r=re.sub(r"(?ims)<STYLE(.*?)</STYLE>","",html)
	res=re.search('(?sim)<BODY(.*?)>',_r,re.IGNORECASE)
	result=False
	body=""
	header=""
	footer=""
	if res:
		result=True		
		header=_r[0:res.end()]
		body=_r[res.end():]
		footer=""
		res=re.search('(?sim)</BODY(.*?)>',body,re.IGNORECASE)
		if res:
			footer=body[res.start():]
			body=_decode_html(body[0:res.start()])
	else:		
		body=_decode_html(_r)
	return result,header,body,footer
####################
#guess_fileextension
####################
@_dbg
def guess_fileextension(ct):
	"returns a filetype based on its contenttype/mimetype 'ct'"
	try:
		maintype,subtype=ct.split("/")
	except:
		maintype=ct
		subtype="plain"
	if maintype=="image":
		if subtype in ("jpeg","pjpeg"):
			return "jpg"
		elif subtype=="svg+xml":
			return "svg"
		elif subtype in ("tiff","x-tiff"):
			return "tif"
		elif subtype=="x-icon":
			return "ico"
		elif subtype=="vnd.djvu":
			return "dvju"
		return subtype
	if maintype=="audio":
		if subtype=="basic":
			return "au"
		if subtype in ("vnd.rn-realaudio","x-pn-realaudio"):
			return "ra"
		elif subtype in ("vnd.wave","x-wav"):
			return "wav"
		elif subtype in ("midi","x-midi"):
			return "mid"
		elif subtype=="x-mpeg":
			return "mp2"
		elif subtype in ("mp3","mpeg","ogg","midi"):
			return subtype
	if maintype=="video":
		if subtype=="x-ms-wmv":
			return "wmv"
		elif subtype=="quicktime":
			return "mov"
		elif subtype in ("x-matroska"):
			return "mkv"
		elif subtype in ("x-msvideo"):
			return "avi"
		elif subtype in ("avi","mpeg","mp4","webm"):
			return subtype
	if maintype=="application":
		if subtype in ("javascript","x-javascript","ecmascript"):
			return "js"
		elif subtype=="postscript":
			return "ps"
		elif subtype in ("pkcs10","pkcs-10","x-pkcs10"):
			return "p10"
		elif subtype in ("pkcs12","pkcs-12","x-pkcs12"):
			return "p12"
		elif subtype in ("x-pkcs7-mime","pkcs7-mime"):
			return "p7c"
		elif subtype in ("x-pkcs7-signature","pkcs7-signature"):
			return "p7a"
		elif subtype=="x-shockwave-flash":
			return "swf"
		elif subtype=="mswrite":
			return "wri"
		elif subtype in ("msexcel","excel","vnd.ms-excel","x-excel","x-msexcel"):
			return "xls"
		elif subtype in ("msword","word","vnd.ms-word","x-word","x-msword"):
			return "doc"
		elif subtype in ("mspowerpoint","powerpoint","vnd.ms-powerpoint","x-powerpoint","x-mspowerpoint"):
			return "ppt"
		elif subtype in ("gzip","x-gzip","x-compressed"):
			return "gz"
		elif subtype=="x-bzip2":
			return "bz2"
		elif subtype=="x-gtar":
			return "gtar"
		elif subtype=="x-tar":
			return "tar"
		elif subtype=="x-dvi":
			return "dvi"
		elif subtype=="x-midi":
			return "mid"
		elif subtype in("x-lha","lha"):
			return "lha"
		elif subtype in("x-rtf","rtf","richtext"):
			return "rtf"
		elif subtype=="x-httpd-php":
			return "php"
		elif subtype in ("atom+xml","xhtml+xml","xml-dtd","xop+xml","soap+xml","rss+xml","rdf+xml","xml"):
			return "xml"
		elif subtype in ("arj","lzx","json","ogg","zip","gzip","pdf","rtc"):
			return subtype
	if maintype=="text":
		if subtype in ("plain","cmd","markdown"):
			return "txt"
		elif subtype=="javascript":
			return "js"
		elif subtype in ("comma-separated-values","csv"):
			return "csv"
		elif subtype in ("vcard","x-vcard","directory;profile=vCard","directory"):
			return "vcf"
		elif subtype=="tab-separated-values":
			return "tsv"
		elif subtype=="uri-list":
			return "uri"
		elif subtype=="x-c":
			return "c"
		elif subtype=="x-h":
			return "h"
		elif subtype=="x-vcalendar":
			return "vcs"
		elif "x-script" in subtype:
			r=subtype.split(".")
			if len(r)==2:
				return r[1]
			else:
				return "hlb"
		elif subtype in ("asp","css","html","rtf","xml"):
			return subtype
	e=mimetypes.guess_extension(ct)
	if e:
		e=e.replace(".","")
		debug("guess_fileextension '%s'=>'%s'"%(ct,e))
		return e
	else:
		return "bin"
################
#_encodefilename
################
@_dbg
def _encodefilename(name):
	n1=(emailutils.encode_rfc2231(name,"UTF-8"))
	n2="?UTF-8?B?%s"%base64.encodebytes(name.encode("UTF-8",_unicodeerror)).decode("UTF-8",_unicodeerror)[0:-1]
	return n1,n2
###########
#_decodetxt
###########
@_dbg
def _decodetxt(text,encoding,charset):
#necessary due to a bug in python 3 email module
	if not charset:
		charset="UTF-8"
	if not encoding:
		encoding="8bit"
	bytetext=text.encode(charset,_unicodeerror)
	result=bytetext
	cte=encoding.upper()
	if cte=="BASE64":
		pad_err = len(bytetext) % 4
		if pad_err:
			padded_encoded = bytetext + b'==='[:4-pad_err]
		else:
			padded_encoded = bytetext
		try:
			result= base64.b64decode(padded_encoded, validate=True)
		except binascii.Error:
			for i in 0, 1, 2, 3:
				try:
					result= base64.b64decode(bytetext+b'='*i, validate=False)
					break
				except binascii.Error:
					pass
			else:
				raise AssertionError("unexpected binascii.Error")
	elif cte=="QUOTED-PRINTABLE":
		result=quopri.decodestring(bytetext)
	elif cte in ('X-UUENCODE', 'UUENCODE', 'UUE', 'X-UUE'):
		in_file = _BytesIO(bytetext)
		out_file = _BytesIO()
		try:
			uu.decode(in_file, out_file, quiet=True)
			result=out_file.getvalue()
		except uu.Error:
			pass
	return result.decode(charset,_unicodeerror)
#################
#_encrypt_payload
#################
@_dbg
def _encrypt_payload( payload,gpguser,counter=0 ):
	global _tempfiles
	htmlheader=""
	htmlbody=""
	htmlfooter=""
	charset=payload.get_param("charset",header="Content-Type")
	is_text=payload.get_content_maintype()=="text"
	cte=payload["Content-Transfer-Encoding"]
	if not cte:
		cte="8bit"
	debug("_encrypt_payload: charset %s"%charset)
	if charset==None or charset.upper()=="ASCII" or len(charset)==0:
		charset="UTF-8"
	gpg = _GPG( _GPGKEYHOME, gpguser,counter)
	raw_payload = payload.get_payload(decode=not is_text)
	if is_text:
		raw_payload=_decodetxt(raw_payload,cte,charset)	
		payload.del_param("charset")	
		payload.set_param("charset",charset)
	contenttype=payload.get_content_type()	
	debug("nach payload.get_content_typ")	
	debug("Content-Type:'%s'"%contenttype)
	fp=_new_tempfile()
	debug("_encrypt_payload _new_tempfile %s"%fp.name)
	filename = payload.get_filename()
	tencoding="7bit"
	if contenttype=="text/html":
		res,htmlheader,htmlbody,htmlfooter=_split_html(raw_payload)
		fp.write(htmlbody.encode(charset,_unicodeerror))
	else:
		if is_text:
			try:
				raw_payload.encode("ascii")
			except:
				tencoding="8bit"
			raw_payload=raw_payload.encode(charset,_unicodeerror)

		fp.write(raw_payload)
	fp.close()
	isAttachment = payload.get_param( 'attachment', None, 'Content-Disposition' ) is not None
	isInline=payload.get_param( 'inline', None, 'Content-Disposition' ) is not None
	gpg.set_filename( fp.name )
	if is_encrypted(raw_payload):
		if _ADDHEADER:
			if not _encryptheader in payload:
				payload[_encryptheader] = 'Mail was already encrypted'
			debug("Mail was already encrypted")
		_del_tempfile(fp.name)
		if len(_OUTFILE) >0:
			return None	
		return payload
	contentmaintype=payload.get_content_maintype() 
	if isAttachment or (isInline and contentmaintype not in ("text") ):
		debug("ENCRYPT PAYLOAD ATTACHMENT")
		addPGPextension=True
		if filename==None:
			count=""
			if counter>0:
				count="%i"%counter
			try:
				f=_LOCALEDB[_LOCALE][1]
			except:
				log("wrong locale '%s'"%_LOCALE,"e")
				f=_LOCALEDB["EN"][1]
			filename=('%s%s.'%(f,count))+guess_fileextension(contenttype)
		f,e=os.path.splitext(filename)
		addPGPextension=(e.lower()!=".pgp")
		if filename and addPGPextension:
			pgpFilename = filename + ".pgp"
		else:
			pgpFilename=filename
			
		debug("Filename:'%s'"%filename)
		pgpFilenamecD,pgpFilenamecT=_encodefilename(pgpFilename)
		
		isBinaryattachment=(contentmaintype!="text")
		if addPGPextension:
			debug("addPGPextension gpg.encrypt_file")
			result,pl=gpg.encrypt_file(binary=isBinaryattachment)
		else:
			result=1
		if result==0:
			if isBinaryattachment:
				payload.set_payload(str(base64.encodebytes(pl),"ascii"))
				payload["Content-Transfer-Encoding"]="base64"
				
			else:
				payload.set_payload(pl)
				if 'Content-Transfer-Encoding' in payload:
					del payload['Content-Transfer-Encoding']
				payload["Content-Transfer-Encoding"]="8bit"
			payload.set_type( 'application/octet-stream')

			if payload["Content-Disposition"]:
				del payload["Content-Disposition"]
			payload.add_header('Content-Disposition', 'attachment; filename*="%s"' % pgpFilenamecD)
			payload.set_param( 'name', pgpFilenamecT )
	else:
		if 'Content-Transfer-Encoding' in payload:
			del payload['Content-Transfer-Encoding']
		payload["Content-Transfer-Encoding"]="8bit"
		result,pl=gpg.encrypt_file(binary=False) 
		if result==0:
			if contenttype=="text/html":
				pl=htmlheader+"\n<br>\n"+re.sub('\n',"<br>\n",pl)+"<br>\n"+htmlfooter
			if "Content-Transfer-Encoding" in payload:
				del payload["Content-Transfer-Encoding"]
			payload["Content-Transfer-Encoding"]=tencoding
			payload.set_payload(pl)
		else:
			log("Error during encryption: payload will be unencrypted!","m")	
	_del_tempfile(fp.name)
	debug("_encrypt_payload END")
	return payload
###################
#encrypt_pgpinline
###################
@_dbg
def encrypt_pgpinline(mail,gpguser,from_addr,to_addr):
	"""
	returns the string 'message' as an PGP/INLINE encrypted mail as an email.Message object
	returns None if encryption was not possible
	"""
	message=email.message_from_string(mail)
	counter=0
	attach_list=list()
	appointment="appointment"
	try:
		appointment=_LOCALEDB[_LOCALE][0]
	except:
		pass
	cal_fname="%s.ics.pgp"%appointment
	if type (message) == list:
		msg=message
	else:
		msg=message.walk()
		debug("encrypt_pgpinline vor get_content_type")
		contenttype=message.get_content_type()	
		debug("encrypt_pgpinline nach get_content_type")
		debug("CONTENTTYPE %s"%contenttype)
		if type( message.get_payload() ) == str:
			debug("encrypt_pgpinlie: type( message.get_payload() ) == str")
			charset=message.get_param("charset",header="Content-Type")
			if charset==None or charset.upper()=="ASCII":
				message.set_param("charset",charset)		
			pl=_encrypt_payload( message ,gpguser)
			if contenttype=="text/calendar":
				CAL=MIMEText(pl.get_payload(decode=True),_subtype="calendar",_charset="UTF-8")
				CAL.add_header('Content-Disposition', 'attachment', filename=cal_fname)
				CAL.set_param( 'name', cal_fname)
				pl.set_payload(None)
				pl.set_type("multipart/mixed")
				pl.attach(CAL)
			debug("encrypt_pgpinline: type( message.get_payload() ) == str END")
			return pl
	for payload in msg:
		content=payload.get_content_maintype()
		if (content in ("application","image","audio","video" )) \
		and payload.get_param( 'inline', None, 'Content-Disposition' ) is None:
			payload.add_header('Content-Disposition', 'attachment;"')
		if payload.get_content_maintype() == 'multipart':
			continue
		if( type( payload.get_payload() ) == list ):
			continue
		else:
			debug("for in schleife for _encrypt payload %s" %type(payload))
			res=_encrypt_payload( payload,gpguser,counter )
			if res and payload.get_content_type()=="text/calendar" and payload.get_param( 'attachment', None, 'Content-Disposition' ) is  None:
				CAL=MIMEText(res.get_payload(decode=True),_subtype="calendar",_charset="UTF-8")
				CAL.add_header('Content-Disposition', 'attachment', filename=cal_fname)
				CAL.set_param( 'name', cal_fname)
				payload.set_payload("")
				payload.set_type("text/plain")
				attach_list.append(CAL)
			if (content in ("application","image","audio","video" )):
				counter+=1
			debug("for schleife next")
		debug("for schleife Ende")			
	for a in attach_list:
		message.attach(a)
	return message
#################
#encrypt_pgpmime
#################
@_dbg
def encrypt_pgpmime(message,gpguser,from_addr,to_addr):
	"""
	returns the string 'message' as an PGP/MIME encrypted mail as an email.Message object
	returns None if encryption was not possible
	"""
	global _tempfiles
	raw_message=email.message_from_string(message)
	splitmsg=re.split("\n\n",message,1)
	if len(splitmsg)!=2:
		splitmsg=re.split("\r\n\r\n",message,1)
	if len(splitmsg)!=2:
		debug("Mail could not be split in header and body part (mailsize=%i)"%len(message))
		log("Error parsing email","w")
		return None
	header,body=splitmsg 
	header+="\n\n"
	try:
		newmsg=email.message_from_string( header)
	except:
		log("creating new message failed","w")
		log_traceback()
	contenttype="text/plain"
	contenttransferencoding=None
	contentboundary=None
	c=newmsg.get("Content-Type")
	if c==None:
		debug("Content-Type not set, set default 'text/plain'.")
		newmsg.set_type("text/plain")
	boundary=_make_boundary(message)
	try:
		newmsg.set_boundary(boundary)
	except:
		log("Error setting boundary")
		log_traceback()
	res= re.search("boundary=.*\n",message,re.IGNORECASE)
	if res:
		_b=message[res.start():res.end()]
		res2=re.search("\".*\"", _b)
		if res2:
			contentboundary=_b[(res2.start()+1):(res2.end()-1)]
	try:
		contenttype=newmsg.get_content_type()
		debug("Content-Type:'%s'"%str(contenttype))
		contenttransferencoding=newmsg['Content-Transfer-Encoding']
	except:
		log("contenttype and/or transerfencoding could not be found")
		log_traceback()
	newmsg.set_type("multipart/encrypted")
	newmsg.set_param("protocol","application/pgp-encrypted")
	newmsg.preamble='This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'
	if 'Content-Transfer-Encoding' in newmsg:
		del newmsg['Content-Transfer-Encoding']
	gpg = _GPG( _GPGKEYHOME, gpguser)
	fp=_new_tempfile()
	debug("encrypt_mime new tempfile %s"%fp.name)
	if contenttype ==None:
		contenttype="multipart/mixed"
	protocol=""
	if contenttype=="multipart/signed":
		protocol=" protocol=\"application/pgp-signature\";\n"
	msgheader='Content-Type: %(ctyp)s;\n%(protocol)s boundary="%(bdy)s"\n'\
		%{"bdy":contentboundary,"ctyp":contenttype,"protocol":protocol}
	if contenttransferencoding !="None":
		msgheader+=("Content-Transfer-Encoding: %s\n" %contenttransferencoding)
	bodymsg=email.message.Message()
	if "multipart" in contenttype:
		bodymsg["Content-Type"]=contenttype
	else:	
		bodymsg["Content-Type"]="multipart/mixed"
	if contenttransferencoding!="None" and contenttransferencoding!=None and len(contenttransferencoding)>0:
		bodymsg["Content-Transfer-Encoding"]=contenttransferencoding
	rawpayload=raw_message.get_payload()
	if type(rawpayload) == str:
		debug("Payload==String len=%i"%len(rawpayload))
		if contenttype ==None:
			contenttype="multipart/mixed"
		protocol=""
		charset=""
		if contenttype=="multipart/signed":
			protocol=" protocol=\"application/pgp-signature\";\n"
		_ch=_find_charset(header)
		debug("Charset:%s"%str(_ch))
		bdy=""
		if contentboundary!=None:
			bdy='boundary="%s"\n'%contentboundary
		if ("text/" in contenttype) and _ch!= None and len(_ch)>0 :
			charset="charset=\"%s\""%_ch
			debug("content-type: '%s' charset: '%s'"%(contenttype,charset))
		msgheader='Content-Type: %(ctyp)s; %(charset)s\n%(protocol)s%(bdy)s'\
		%{"bdy":bdy,"ctyp":contenttype,"protocol":protocol,"charset":charset}
		debug("msgheader:    '%s'"%str(msgheader))
		debug("new boundary: '%s'"%str(boundary))
		if contenttransferencoding !=None:
			msgheader+=("Content-Transfer-Encoding: %s\n" %contenttransferencoding)
		body=msgheader+"\n"+body	
	else:
		debug("Payload==Msg")
		for p in rawpayload:
			bodymsg.attach(p)
		body=bodymsg.as_string()	
	fp.write(body.encode("UTF-8",_unicodeerror))
	fp.close()
	gpg.set_filename( fp.name )
	attachment=_GPGEncryptedAttachment()
	if is_encrypted(message):
		_del_tempfile(fp.name)
		return None
	result,pl=gpg.encrypt_file(binary=False) 
	if result==0:
		attachment.set_payload(pl)
	else:
		log("Error during encryption pgpmime: payload will be unencrypted!","m")	
	newmsg.set_payload(attachment)
	newmsg.set_boundary(boundary)
	attachment.set_boundary(contentboundary)
	attachment.set_masterboundary(boundary)
	_del_tempfile(fp.name)
	return newmsg
##############################
#get_preferredencryptionmethod
##############################	
@_dbg
def get_preferredencryptionmethod(user):
	"returns the preferenced encryption method for user 'user'"
	debug("get_preferredencryptionmethod :'%s'"%user)
	global _PREFERRED_ENCRYPTION
	method=_PREFERRED_ENCRYPTION
	_m=""
	_u=user
	try:
		_u=_addressmap[user]
	except:
		pass
	try:
		_m=_encryptionmap[_u].upper()
	except:
		debug("get_preferredencryptionmethod User '%s' not found"%user)
		return method
	if _m in ("PGPMIME","PGPINLINE","SMIME","NONE"):
		debug("get_preferredencryptionmethod User %s (=> %s) :'%s'"%(user,_u,_m))
		return _m
	else:
		debug("get_preferredencryptionmethod: Method '%s' for user '%s' unknown" % (_m,_u))
		return method
##################
#encrypt_gpg_mail 
##################
@_dbg
def encrypt_gpg_mail(mailtext,use_pgpmime, gpguser,from_addr,to_addr):
	"""
	returns the string 'message' as an PGP encrypted mail (either PGP/INLINE or PGP/MIME depending on the configuration) as an email.Message object
	returns None if encryption was not possible
	"""
	global _count_encryptedmails,_count_alreadyencryptedmails
	raw_message=email.message_from_string(mailtext)
	msg_id=""
	if "Message-Id" in raw_message:
		msg_id="Id:%s "%raw_message["Message-Id"]
	if "Subject"  in raw_message and len(_SPAMSUBJECT.strip())>0 and _SPAMSUBJECT in raw_message["Subject"]:
		debug("message is SPAM, don't encrypt")
		return None
	if is_encrypted( raw_message ):
		debug("encrypt_gpg_mail, is already encrypted")
		_count_alreadyencryptedmails+=1
		return None
	log("Encrypting email to: %s" % to_addr )
	if use_pgpmime:
		mail = encrypt_pgpmime( mailtext,gpguser,from_addr,to_addr )
	else:
		#PGP Inline
		mail = encrypt_pgpinline( mailtext,gpguser,from_addr,to_addr )
	if mail==None:
		return None
	_count_encryptedmails+=1
	return mail
#####################
# encrypt_smime_mail 
#####################
@_dbg
def encrypt_smime_mail(mailtext,smimeuser,from_addr,to_addr):
	"""
	returns the string 'message' as an S/MIME encrypted mail as an email.Message object
	returns None if encryption was not possible
	"""
	raw_message=email.message_from_string(mailtext)
	global _tempfiles, _count_encryptedmails,_count_alreadyencryptedmails
	contenttype="text/plain"
	contenttransferencoding=None
	contentboundary=None
	if is_encrypted(raw_message):
		debug("encrypt_smime_mail:mail is already encrypted")
		debug("Mail was already encrypted")
		_count_alreadyencryptedmails+=1
		return None
	splitmsg=re.split("\n\n",mailtext,1)
	if len(splitmsg)!=2:
		splitmsg=re.split("\r\n\r\n",mailtext,1)
	if len(splitmsg)!=2:
		debug("Mail could not be split in header and body part (mailsize=%i)"%len(mailtext))
		return None
	header,body=splitmsg 
	header+="\n\n"
	try:
		newmsg=email.message_from_string( header)
	except:
		log("creating new message failed","w")
		log_traceback()
		return 
	m_id=""
	if "Message-Id" in raw_message:
		m_id="Id:%s "%raw_message["Message-Id"]
	log("Encrypting email %s to: %s" % (m_id, to_addr) )

	res= re.search("boundary=.*\n",mailtext,re.IGNORECASE)
	if res:
		_b=mailtext[res.start():res.end()]
		res2=re.search("\".*\"", _b)
		if res2:
			contentboundary=_b[(res2.start()+1):(res2.end()-1)]
	try:
		contenttype=newmsg.get_content_type()
		debug("Content-Type:'%s'"%str(contenttype))
		contenttransferencoding=newmsg['Content-Transfer-Encoding']
	except:
		log("contenttype and/or transerfencoding could not be found")
		log_traceback()
	newmsg.set_type( 'application/pkcs7-mime')
	if newmsg["Content-Disposition"]:
		del newmsg["Content-Disposition"]
	newmsg.add_header('Content-Disposition', 'attachment; filename="smime.p7m"')
	newmsg.set_param( 'smime-type', 'enveloped-data',requote=False)
	newmsg.set_param( 'name', 'smime.p7m')
	newmsg.del_param("charset")
	newmsg.del_param("boundary")
	protocol=newmsg.get_param("protocol")
	newmsg.del_param("protocol")
	if newmsg["Content-Transfer-Encoding"]:
		del newmsg["Content-Transfer-Encoding"]
	newmsg.add_header('Content-Transfer-Encoding', 'base64')
	smime = _SMIME( _SMIMEKEYHOME)
	smime.set_recipient(smimeuser)
	fp=_new_tempfile()
	debug("encrypt_smime_mail _new_tempfile %s"%fp.name)
	bodymsg=email.message.Message()
	if "multipart" in contenttype:
		bodymsg["Content-Type"]=contenttype
	else:	
		bodymsg["Content-Type"]="multipart/mixed"
	if protocol:
		bodymsg.set_param("Protocol",protocol)
	if contenttransferencoding!="None" and contenttransferencoding!=None and len(contenttransferencoding)>0:
		bodymsg["Content-Transfer-Encoding"]=contenttransferencoding
	rawpayload=raw_message.get_payload()
	if type(rawpayload) == str:
		debug("Payload==String len=%i"%len(rawpayload))
		if contenttype ==None:
			contenttype="multipart/mixed"
		protocol=""
		charset=""
		if contenttype=="multipart/signed":
			protocol=" protocol=\"application/pgp-signature\";\n"
		_ch=_find_charset(header)
		debug("Charset:%s"%str(_ch))
		bdy=""
		if contentboundary!=None:
			bdy='boundary="%s"\n'%contentboundary
		if ("text/" in contenttype) and _ch!= None and len(_ch)>0 :
			charset="charset=\"%s\""%_ch
			debug("content-type: '%s' charset: '%s'"%(contenttype,charset))
		msgheader='Content-Type: %(ctyp)s; %(charset)s\n%(protocol)s%(bdy)s'\
		%{"bdy":bdy,"ctyp":contenttype,"protocol":protocol,"charset":charset}
		debug("msgheader:    '%s'"%str(msgheader))
		if contenttransferencoding !=None:
			msgheader+=("Content-Transfer-Encoding: %s\n" %contenttransferencoding)
		body=msgheader+"\n"+body	
	else:
		debug("Payload==Msg")
		for p in rawpayload:
			bodymsg.attach(p)
		body=bodymsg.as_string()	
	fp.write(body.encode("UTF-8",_unicodeerror))
	fp.close()
	smime.set_filename(fp.name)
	result,pl=smime.encrypt_file()
	if result==0:
		debug("encrypt_smime_mail: send encrypted mail")
		_count_encryptedmails+=1
		if _ADDHEADER:
			if _encryptheader in newmsg:
				del newmsg[_encryptheader]
			newmsg[_encryptheader] = _encryptgpgcomment
		newmsg.set_payload( pl )
	else:
		debug("encrypt_smime_mail: error encrypting mail, send unencrypted")
		m=None
		newmsg=None
	_del_tempfile(fp.name)
	return newmsg

@_dbg
def encrypt_single_mail(queue_id,mailtext,from_addr,to_addr):
	global _mailcount,_PREFERRED_ENCRYPTION,_count_totalmails, _queue_id
	g_r,to_gpg=check_gpgrecipient(to_addr)
	s_r,to_smime=check_smimerecipient(to_addr)
	method=get_preferredencryptionmethod(to_addr)
	debug("GPG encrypt possible %i"%g_r)
	debug("SMIME encrypt possible %i"%s_r)
	_count_totalmails+=1
	if method=="PGPMIME":
		_prefer_gpg=True
		_pgpmime=True
	elif method=="PGPINLINE":
		_prefer_gpg=True
		_pgpmime=False
	if method=="SMIME":
		_prefer_gpg=False
	if method=="NONE":
		g_r=False
		s_r=False
	if not s_r and not g_r:
		m="Email not encrypted, public key for '%s' not found"%to_addr
		log(m,"w")
		_send_rawmsg(_queue_id,mailtext,m,from_addr,to_addr)
		return
	if is_encrypted(mailtext):
		m="Email already encrypted"
		debug(m)
		_send_rawmsg(_queue_id,mailtext,m,from_addr,to_addr)
		return
	if _prefer_gpg:
		debug("PREFER GPG")
		if g_r:
			mresult=encrypt_gpg_mail(mailtext,_pgpmime,to_gpg,from_addr,to_addr)
		else:
			mresult=encrypt_smime_mail(mailtext,to_smime,from_addr,to_addr)
	else:
		debug("PREFER S/MIME")
		if s_r:
			mresult=encrypt_smime_mail(mailtext,to_smime,from_addr,to_addr)
		else:
			mresult=encrypt_gpg_mail(mailtext,_pgpmime,to_gpg,from_addr,to_addr)
	if mresult:
		debug("send encrypted mail")
		_send_msg(queue_id,mresult,from_addr,to_addr )
	else:
		m="Email could not be encrypted"
		debug(m)
		_send_rawmsg(queue_id,mailtext,m,from_addr,to_addr)
###############
# encrypt_mails 
###############
@_dbg
def encrypt_mails(mailtext,receiver):
	"""
	Main function of this library: 
		mailtext is the mail as a string
		receiver is a list of receivers
	The emails will be encrypted if possible and sent as defined  in /etc/gpgmailencrypt.conf
	example:
	encrypt_mails(myemailtext,['agentj@mib','agentk@mib'])
	"""
	global _mailcount,_PREFERRED_ENCRYPTION,_count_totalmails, _queue_id
	try:
		if _debug_keepmail(mailtext): #DEBUG
			_store_temporaryfile(mailtext)
		if _PREFERRED_ENCRYPTION=="PGPMIME":
			_pgpmime=True
		else:
			_pgpmime=False
		if _SMIMEAUTOMATICEXTRACTKEYS:
			debug("_SMIMEAUTOMATICEXTRACTKEYS")
			f=_new_tempfile()
			f.write(mailtext.encode("UTF-8",_unicodeerror))
			f.close()
			s=_SMIME(_SMIMEKEYHOME)
			s.extract_publickey_from_mail(f.name,_SMIMEKEYEXTRACTDIR)
			_del_tempfile(f.name)
		for to_addr in receiver:
			debug("encrypt_mail for user '%s'"%to_addr)
			if _RUNMODE==m_daemon:
				fname=_store_temporaryfile(mailtext,spooldir=True)
			try:
				raw_message = email.message_from_string( mailtext )
			except:
				_store_temporaryfile(mailtext,add_deferred=True,fromaddr="UNKNOWN",toaddr=to_addr)
				log_traceback()
				return
			from_addr = raw_message['From']
			if _RUNMODE==m_daemon:
				_email_queue[_queue_id]=[fname,from_addr,to_addr,time.time()]
			else:
				_queue_id=-1
			encrypt_single_mail(_queue_id,mailtext,from_addr,to_addr)
			if _RUNMODE==m_daemon:
				_queue_id+=1
	except:
		log_traceback()
#######################################
#END definition of encryption functions
#######################################
@_dbg
def start_adminconsole(host,port):
	"starts the admin console"
	import getpass
	class gmeadmin():
		def __init__(self):
			self.smtp= smtplib.SMTP()
			self.host="localhost"
			self.port=0

		def _sendcmd(self, cmd,arg=""):
		        self.smtp.putcmd(cmd,arg)
		        (code, msg) = self.getreply()
		        print(msg.decode("UTF-8"))
		        return (code, msg)

		def getreply(self):
			return self.smtp.getreply()	
	
		def start(self,host="localhost",port=0):
			self.host=host
			self.port=port
			try:
				self.smtp.connect(host,port)
			except:
				print("Connection not possible")
				exit(1)
			user=input("User: ")
			password=getpass.getpass("Password: ")
			auth=binascii.b2a_base64(("\x00%s\x00%s"%(user,password)).encode("UTF-8"))[:-1]
			code,msg=self._sendcmd("ADMIN",auth.decode("UTF-8"))
			code,msg=self._sendcmd("AUTH PLAIN",auth.decode("UTF-8"))
			if code!=235:
				print("Authentication failed")
				exit(1)
		
			while True:
				i=input("> ").upper()
				cmd=""
				if i in ["STATISTICS","FLUSH","RELOAD","HELP","QUIT"]:
					if i=="HELP":
						self.print_help()
					else:
						self._sendcmd(i)
				else:
					print("Error: command '%s' unknown"%i)
				if i=="QUIT":
					break

		def print_help(self):
			print("Allowed commands:")
			print("statistics,flush,reload,help,quit,setuser,deluser")
	g=gmeadmin()
	g.start(host,port)

###########
#scriptmode
###########
@_dbg
def scriptmode():
	"run gpgmailencrypt a script"
	try:
		#read message
		if len(_INFILE)>0:
			try:
				f=open(_INFILE,"rb")
				m=email.message_from_binary_file(f)
				raw=m.as_string()
				f.close()
			except:
				log("Could not open Inputfile '%s'"%_INFILE,"e")
				log_traceback()
				exit(2)
		else:
			raw = sys.stdin.read()
		#do the magic
		encrypt_mails(raw,receiver)
	except SystemExit as m:
		debug("Exitcode:'%s'"%m)
		exit(int(m.code))
	except:
		log("Bug:Exception occured!","e")
		log_traceback()
		exit(4)	
	else:
		debug("Program exits without errors")
###########
#daemonmode
###########
@_dbg
def daemonmode():
	"starts the smtpd daemon"
	#####################
	#_deferredlisthandler
	#####################
	def _deferredlisthandler(signum, frame):
		global _count_alarms	
		check_deferred_list()
		store_deferred_list()
		if _count_alarms>1:
			_count_alarms-=1
		else:
			try:
				_count_alarms=24//_STATISTICS_PER_DAY
			except:
				_count_alarms=0
			if _count_alarms>0:
				_log_statistics() #log statistics every 24 hours
		signal.alarm(3600) # once every hour
	##################
	global _daemonstarttime
	_RUNMODE==m_daemon
	_daemonstarttime=datetime.datetime.now()
	global  _count_alarms,_STATISTICS_PER_DAY
	try:
		_count_alarms=24//_STATISTICS_PER_DAY
	except:
		_count_alarms=0
	signal.signal(signal.SIGALRM, _deferredlisthandler)
	signal.alarm(5)
	signal.signal(signal.SIGTERM, _sigtermhandler)
	signal.signal(signal.SIGHUP,  _sighuphandler)
	load_deferred_list()
	smtpd.__version__="gpgmailencrypt smtp server %s"%VERSION
	log("gpgmailencrypt %s starts as daemon on %s:%s"%(VERSION,_SERVERHOST,_SERVERPORT) )
	if _SMTPD_USE_AUTH:
		_read_smtpdpasswordfile(_SMTPD_PASSWORDFILE)
	try:
		server = gpgmailencryptserver(	(_SERVERHOST, _SERVERPORT),
						use_auth=_SMTPD_USE_AUTH,
						authenticate_function=file_auth,
						write_smtpdpasswordfile=write_smtpdpasswordfile,
						use_smtps=_SMTPD_USE_SMTPS,
						sslkeyfile=_SMTPD_SSL_KEYFILE,
						sslcertfile=_SMTPD_SSL_CERTFILE)
	except:
		log("Couldn't start mail server")
		log_traceback()
		exit(1)
	try:
		asyncore.loop()
	except SystemExit as m:
		exit(0)
	except:
		log("Bug:Exception occured!","e")
		log_traceback()




#####################
#gpgmailencryptserver
#####################
class gpgmailencryptserver(smtpd.SMTPServer):
	@_dbg
	def __init__(self, 
			localaddr,sslcertfile=None,
			sslkeyfile=None,
			sslversion=ssl.PROTOCOL_SSLv23,
			use_smtps=False,
			use_auth=False,
			authenticate_function=None,
			write_smtpdpasswordfile=None,
			data_size_limit=smtpd.DATA_SIZE_DEFAULT):
		try:
			smtpd.SMTPServer.__init__(self, localaddr, None,data_size_limit=data_size_limit)
		except socket.error as e:
			log("hksmtpserver: error",e)
			exit(5)
		self.sslcertfile=sslcertfile
		self.sslkeyfile=sslkeyfile
		self.sslversion=sslversion
		self.use_smtps=use_smtps
		self.use_authentication=use_auth
		self.write_smtpdpasswordfile=write_smtpdpasswordfile
		self.authenticate_function=authenticate_function
	@_dbg
	def handle_accept(self):
		pair = self.accept()
		if pair is not None:
			conn, addr = pair
			self.socket.setblocking(0)
			if self.use_smtps:
				try:
					conn=ssl.wrap_socket(conn,
						server_side=True,
						certfile=self.sslcertfile,
						keyfile=self.sslkeyfile,
						ssl_version=self.sslversion,
						do_handshake_on_connect=False
						)
					while True:
						try:
							conn.do_handshake()
							break
						except ssl.SSLWantReadError:
							select.select([conn], [], [])
						except ssl.SSLWantWriteError:
							select.select([], [conn], [])
				except:
					log("hksmtpserver: Exception: Could not start SSL connection")
					log_traceback()
					return
			debug('hksmtpserver: Incoming connection from %s' % repr(addr))
			channel = hksmtpchannel(self, 
						conn, 
						addr,
						use_auth=self.use_authentication, 
						authenticate_function=self.authenticate_function,
						write_smtpdpasswordfile=self.write_smtpdpasswordfile,	
						sslcertfile=self.sslcertfile,
						sslkeyfile=self.sslkeyfile,
						sslversion=self.sslversion)
	@_dbg
	def process_message(self, peer, mailfrom, receiver, data):
		debug("hksmtpserver: gpgmailencryptserver from '%s' to '%s'"%(mailfrom,receiver))
		try:
			encrypt_mails(data,receiver)
		except:
			log("hksmtpserver: Bug:Exception!")
			log_traceback()
		return
##############
#hksmtpchannel
##############
class hksmtpchannel(smtpd.SMTPChannel):
	def __init__(self, smtp_server, 
				newsocket, 	
				fromaddr,					
				use_auth,
				authenticate_function=None,
				write_smtpdpasswordfile=None,
				use_tls=False,
				force_tls=False,
				sslcertfile=None,
				sslkeyfile=None,
				sslversion=None):
		smtpd.SMTPChannel.__init__(self, smtp_server, newsocket, fromaddr)
		asynchat.async_chat.__init__(self, newsocket)
		self.sslcertfile=sslcertfile
		self.sslkeyfile=sslkeyfile
		self.sslversion=sslversion
		self.use_tls=use_tls
		self.starttls_available=False
		self.force_tls=force_tls
		self.tls_active=False
		self.authenticate_function=authenticate_function
		self.write_smtpdpasswordfile=write_smtpdpasswordfile
		self.is_authenticated=False
		self.is_admin=False
		self.adminmode=False
		self.use_authentication=use_auth
		self.user=""
		self.password=""
		self.seen_greeting=False
		self.data_size_limit=0
		self.fqdn=socket.getfqdn()
		if self.sslcertfile and self.sslkeyfile and self.sslversion:
			self.starttls_available=True
	@_dbg
	def smtp_HELO(self,arg):
		debug("hksmtpserver: HELO")
		if not arg:
	       		self.push('501 Syntax: HELO hostname')
	       		return
		if self.seen_greeting:
			self.push('503 Duplicate HELO/EHLO')
		else:
			self.seen_greeting = True
			self.push('250 %s' % self.fqdn)
	@_dbg
	def smtp_EHLO(self, arg):
		debug("hksmtpserver: EHLO")
		if not arg:
			self.push('501 Syntax: EHLO hostname')
			return
		if self.seen_greeting:
			self.push('503 Duplicate HELO/EHLO')
			return
		else:
			self.seen_greeting = arg
			self.extended_smtp = True
		if self.use_tls and not self.tls_active:
			self.push('250-STARTTLS')
		if self.data_size_limit:
			self.push('250-SIZE %s' % self.data_size_limit)
		if self.use_authentication and (not self.force_tls or (self.force_tls and self.tls_active)):
			self.push('250-AUTH PLAIN')
		self.push('250 %s' % self.fqdn)
	@_dbg
	def smtp_RSET(self, arg):
		debug("hksmtpserver: RSET")
		self.reset_values()
		smtpd.SMTPChannel.smtp_RSET(self,arg)
	@_dbg
	def reset_values(self):	
		self.is_authenticated=False
		self.is_admin=False
		self.user=""
		self.password=""
		self.seen_greeting=False
	@_dbg
	def smtp_AUTH(self,arg):
		debug ("hksmtpserver: AUTH")
		if not arg:
			self.push("501 Syntax error: AUTH PLAIN")
			return
		#debug("hksmtpserver: Original ARG: %s"%arg)
		res=arg.split(" ")
		if len(res)<2:
			self.push("454 Temporary authentication failure.")
			return
		command,encoded=res	
		if "PLAIN" in command.upper():
			debug("hksmtpserver: PLAIN decoding")
			try:
				d=binascii.a2b_base64(encoded).decode("UTF-8",_unicodeerror).split('\x00')
			except:
				debug("hksmtpserver: error decode base64 '%s'"%sys.exc_info()[1])
				d=[]
			if len(d)<2:
				self.push("454 Temporary authentication failure.")
				return
			while len(d)>2:
				del d[0]
			user=d[0]
			password=d[1]
			if not self.authenticate_function:
				debug("hksmtpserver: self.authenticate_function=None")
			if self.authenticate_function and self.authenticate_function(user,password):
				self.push("235 Authentication successful.")
				self.is_authenticated=True
				self.is_admin=is_admin(user)
				self.user=user
				debug("user '%s' is admin %s"%(user,self.is_admin))
			else:
				self.push("454 Temporary authentication failure.")
		else:
			self.push("454 Temporary authentication failure.")
	@_dbg
	def smtp_STATISTICS(self,arg):
		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return
		statistics=get_statistics()
		c=0
		for s in statistics:
			dash="-"
			if c==len(statistics)-1:
				dash=" "
			self.push("250%s%s %i"%(dash,s,statistics[s]) )
			c+=1
	@_dbg
	def smtp_FLUSH(self,arg):
		log("FLUSH")
		check_deferred_list()
		check_mailqueue()
		self.push("250 OK")
	@_dbg
	def smtp_RELOAD(self,arg):
		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return
		init()
		_parse_commandline()
		self.push("250 OK")
	@_dbg
	def smtp_SETUSER(self,arg):
		if not arg:
			self.push("501 Syntax error: SETUSER user password")
			return
		res=arg.split(" ")
		if len(res)!=2:
			self.push("501 Syntax error: SETUSER user password")
			return
		r=adm_set_user(res[0],res[1])
		if r:
			if self.write_smtpdpasswordfile:
				self.write_smtpdpasswordfile(_SMTPD_PASSWORDFILE)
			self.push("250 OK")
		else:
			self.push("454 User could not be set")
	@_dbg
	def smtp_DELUSER(self,arg):
		if not arg:
			self.push("501 Syntax error: DELUSER user")
			return
		res=arg.split(" ")
		if len(res)!=1:
			self.push("501 Syntax error: DELUSER user")
			return
		if self.user==res[0]:
			self.push("454 You can't delete yourself")
			return
		r=adm_del_user(res[0])
		if r:
			if self.write_smtpdpasswordfile:
				self.write_smtpdpasswordfile(_SMTPD_PASSWORDFILE)
			self.push("250 OK")
		else:
			self.push("454 User could not be deleted")
	def smtp_ADMIN(self,arg):
		self.adminmode=True
		_read_smtpdpasswordfile(_SMTPD_PASSWORDFILE)
		self.push("250 OK")
		return
	@_dbg
	def found_terminator(self):
		line = "".join(self._SMTPChannel__line)
		i = line.find(' ')
		if i < 0:
			command = line.upper()
		else:
			command = line[:i].upper()
		SIMPLECOMMANDS=["EHLO","HELO","RSET","NOOP","QUIT","STARTTLS"]
		if not self.use_authentication and not self.adminmode :
			SIMPLECOMMANDS+=["ADMIN"]
		ADMINCOMMANDS=["STATISTICS","RELOAD","FLUSH","SETUSER","DELUSER"]
		if (self.use_authentication or self.adminmode) and not self.is_authenticated:
			if not command in SIMPLECOMMANDS+["AUTH"]:
				self.push("530 Authentication required.")
				self._SMTPChannel__line=[]
				return
		
		if not self.is_admin:
			if command in ADMINCOMMANDS:
				self.push("530 Admin authentication required.")
				self._SMTPChannel__line=[]
				return
		if self.use_tls and self.force_tls and not self.tls_active:
			if not command in SIMPLECOMMANDS+ADMINCOMMANDS:
				self.push("530 STARTTLS before authentication required.")
				self._SMTPChannel__line=[]
				return
		smtpd.SMTPChannel.found_terminator(self)
	@_dbg
	def smtp_STARTTLS(self,arg):
			self.push('502 Error: command "STARTTLS" not implemented' )
			self._SMTPChannel__line=[]
			return
@_dbg
def file_auth(user,password):
	debug("hksmtpserver: file_auth")
	try:
		pw=_smtpd_passwords[user]
		if pw==_get_hash(password):
			debug("hksmtpserver: User '%s' authenticated"%user)
			return True
		else:
			debug("hksmtpserver: User '%s' incorrect password"%user)
		
	except:
		debug("hksmtpserver: No such user '%s'"%user)
		pass
	return False






#############
#adm_set_user
#############
@_dbg
def adm_set_user(user,password):
	"adds a user, if the user already exists it changes the password"
	global _smtpd_passwords
	try:
		_smtpd_passwords[user]=_get_hash(password)
		return True
	except:
		log("User could not be added","e")
		log_traceback()
		return False
	return True
#############
#adm_del_user
#############
@_dbg
def adm_del_user(user):
	"deletes a user"
	global _smtpd_passwords
	try:
		del _smtpd_passwords[user]
		return True
	except:
		log("User could not be deleted","e")
		log_traceback()
		return False
	return True
########################
#_read_smtpdpasswordfile
########################
@_dbg
def _read_smtpdpasswordfile( pwfile):
	global _smtpd_passwords
	try:
		f=open(os.path.expanduser(pwfile))
	except:
		log("hksmtpserver: Config file could not be read","e")
		log_traceback()
		exit(5)
	txt=f.read()
	f.close()
	_smtpd_passwords=dict()
	for l in txt.splitlines():
		try:
			name,passwd=l.split("=",1)
			_smtpd_passwords[name.strip()]=passwd.strip()
		except:
			pass
########################
#write_smtpdpasswordfile
########################
@_dbg
def write_smtpdpasswordfile( pwfile):
	"writes the users to the password file"
	global _smtpd_passwords
	try:
		pwfile=os.path.expanduser(pwfile)
		fileexists=os.path.exists(pwfile)
		f=open(pwfile,"w")
		if not fileexists:
			os.chmod(pwfile,0o600)
			debug("new pwfile chmod")
	except:
		log("hksmtpserver: Config file could not be written","e")
		log_traceback()
		return False
	for user in _smtpd_passwords:
		try:
			password=_smtpd_passwords[user]
			f.write(("%s=%s\n"%(user,password)))
		except:
			log_traceback()
			pass
	f.close()
#########
#_get_hash
#########
@_dbg
def _get_hash(txt):
	i=0
	r=txt
	while i<=1000:
		r=hashlib.sha512(r.encode("UTF-8",_unicodeerror)).hexdigest()
		i+=1
	return r

################
#_sigtermhandler
################
def _sigtermhandler(signum, frame):
	exit(0)
###############
#_sighuphandler
###############
def _sighuphandler(signum, frame):
	global _daemonstarttime
	_now=datetime.datetime.now()
	log("Server did run %s"%(_now-_daemonstarttime))
	_daemonstarttime=_now
	log("Signal SIGHUP: reload configuration")
	init()
#############################
# gpgmailencrypt main program
#############################
init()
_deferred_emails=[]
_email_queue={}
_queue_id=0
if __name__ == "__main__":
	receiver=_parse_commandline()
	_set_logmode()
	if _RUNMODE==m_daemon:
		daemonmode()
	else:
		scriptmode()



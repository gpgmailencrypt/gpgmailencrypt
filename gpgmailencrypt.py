#!/usr/bin/env python3
# -*- coding: utf-8 -*- 
#based on gpg-mailgate
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
"""
gpgmailencrypt is an encrypting e-mail gateway, that  can encrypt e-mails.
It supports
* PGP/Inline
* PGP/Mime
* S/Mime
* encrypted PDF

It can be used normally as a script doing everything on command line, in daemon mode, where gpgmailencrypt acts as an encrypting smtp server or as a module for programmers. 
It takes e-mails and  returns the e-mail encrypted to another e-mail server if a encryption key exists for the receiver. Otherwise it returns the e-mail unencrypted.
The encryption method can be selected per user.
Usage:
Create a configuration file with "gpgmailencrypt.py -x > ~/gpgmailencrypt.conf"
and copy this file into the directory /etc
"""
VERSION="2.1.0"
DATE="05.10.2015"
from configparser import ConfigParser
import email,email.message,email.mime,email.mime.base,email.mime.multipart,email.mime.application,email.mime.text,smtplib,mimetypes
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import email.utils as emailutils
import html.parser,base64,quopri,uu,binascii
import re,sys,tempfile,os,stat,subprocess,atexit,time,datetime,getopt,random,syslog,inspect,gzip
from email.generator import Generator
from io import StringIO as _StringIO
from io import BytesIO as _BytesIO
from os.path import expanduser
import locale,traceback,hashlib
from functools import wraps
import smtpd,asyncore, signal,ssl,asynchat,socket,select,threading
import string, random, shutil
try:
	import readline
except:
	pass
################################
#Definition of general functions
################################
_unicodeerror="replace"
#####
#_dbg
#####
def _dbg(func):
	@wraps(func)
	def wrapper(*args, **kwargs):
		parent=None
		if args:
			if isinstance(args[0],gme):
				parent=args[0]
			elif hasattr(args[0],"parent"):
				if isinstance(args[0].parent,gme):
					parent=args[0].parent
		if not parent or not parent._DEBUG:
			return func(*args,**kwargs)
		lineno=0
		endlineno=0
		try:
			source=inspect.getsourcelines(func)
			lineno=source[1]
			endlineno=lineno+len(source[0])
		except:
			pass
		parent._level+=1
		parent.debug("START %s"%func.__name__,lineno)
		result=func(*args,**kwargs)
		parent.debug("END %s"%func.__name__,endlineno)
		parent._level-=1
		if parent._level<0:
			parent._level=0
		return result
	return wrapper
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
	print ("gme.py [options] receiver@email.address < Inputfile_from_stdin")
	print ("or")
	print ("gme.py -f inputfile.eml [options] receiver@email.address")
	print ("\nOptions:\n")
	print ("-a --addheader:  adds %s header to the mail"%gme._encryptheader)
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
	print ("-x --example:    print example config file")
	print ("-v --verbose:    print debugging information into _logfile")
	print ("-z --zip:        zip attachments")
	print ("")
####################
#print_exampleconfig
####################
def print_exampleconfig():
	"prints an example config file to stdout"
	print ("[default]")
	print ("prefered_encryption = pgpinline 		# valid values are 'pgpinline','pgpmime' or 'smime'")
	print ("add_header = no         			# adds a %s header to the mail"%gme._encryptheader)
	print ("domains =    		     			# comma separated list of domain names, \
that should be encrypted, empty is all")
	print ("spamsubject =***SPAM				# Spam recognition string, spam will not be encrypted")
	print ("output=mail 					# valid values are 'mail'or 'stdout'")
	print ("locale=en 					# DE|EN|ES|FR|IT|NL|PL|PT|RU|SE'")
	print ("mailtemplatedir=/usr/share/gpgmailencrypt/mailtemplates #directory where mail templates are stored")
	print ("systemmailfrom=gpgmailencrypt@localhost		# e-mail address used when sending system mails")
	print ("alwaysencrypt=False				#if True e-mails will be sent encrypted, even if there is no key. \
Fallback encryption is encrypted pdf")
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
	print ("user@domain.com = PGPMIME			#PGPMIME|PGPINLINE|SMIME|PDF[:zipencryptionmethod]|NONE")
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
	print ("smime.user@domain.com = user.pem[,cipher]	#public S/MIME key file [,used cipher, see defaultcipher in the smime section]")
	print ("")
	print ("[pdf]")
	print ("email2pdfcommand=/usr/bin/email2pdf		#path where to find email2pdf (needed for creating pdfs,")
	print ("						#see https://github.com/andrewferrier/email2pdf)")
	print ("pdftkcommand=/usr/bin/pdftk			#path where to find pdftk (needed for encrypting pdf files")
	print ("pdfdomains=localhost				#a comma separated list of sender domains, which are allowed to use pdf-encrypt")
	print ("passwordlength=20				#Length of the automatic created password")
	print ("passwordlifetime=172800				#lifetime for autocreated passwords in seconds. Default is 48 hours")
	print ("pdfpasswords=/etc/gpgpdfpasswords.pw		#file that includes users and passwords for permanent pdf passwords")
	print ("")
	print ("[zip]")
	print ("7zipcommand=/usr/bin7za				#path where to find 7za")
	print ("defaultcipher=ZipCrypto				#ZipCrypto|AES128|AES256")
	print ("compressionlevel=5				#1,3,5,7,9  with 1:lowest compression, but very fast, 9 is ")
	print ("						# highest compression, but very slow, default is 5")
	print ("securezipcontainer=False			#attachments will be stored in an encrypted zip file. If this option is true,")
	print ("						#the directory will be also encrypted")
	print ("zipattachments=False				#if True all attachments will be zipped, independent from the encryption method")
	print ("")
	print ("[daemon]")
	print ("host = 127.0.0.1				#smtp host")
	print ("port = 10025    				#smtp port")
	print ("smtps = False    				#use smtps encryption")
	print ("sslkeyfile = /etc/gpgsmtp.key			#the x509 certificate key file")
	print ("sslcertfile = /etc/gpgsmtp.crt			#the x509 certificate cert file")
	print ("authenticate = False    			#users must authenticate")
	print ("smtppasswords = /etc/gpgmailencrypt.pw		#file that includes users and passwords")
	print ("admins=admin1,admin2				#comma separated list of admins, that can use the admin console")
	print ("statistics=1					#how often per day should statistical data be logged (0=none) max is 24")

#############
#_splitstring
#############
def _splitstring(txt,length=80):
	def chunkstring(string, length):
		return (string[0+i:length+i] for i in range(0, len(string), length))
	return list(chunkstring(txt,length))
#########
#_mytimer
#########
class _mytimer:
	def __init__(self):
		self.counter=0
		self.alarmtime=10
		self.timer=1
		self.running=False
		self.alarmfunc=None
		self.alarmfuncargs=[]
		self.kwalarmfuncargs={}
	def t_action(self):
		if self.counter==1:
			self.t_alert()
		else:
			if self.counter>0:
				self.counter-=1
			else:
				if self.alarmfunc:
					self.alarmfunc(*self.alarmfuncargs,**self.kwalarmfuncargs)
			self._create_timer()
	def t_alert(self):
		if self.alarmfunc:
			self.alarmfunc(*self.alarmfuncargs,**self.kwalarmfuncargs)
		self.running=False
	def _create_timer(self):
		self.alarm=threading.Timer(self.timer,self.t_action)
		self.running=True
		self.alarm.start()
	def is_running(self):
		return self.running
	def set_alive(self):
		self.counter=self.alarmtime
	def start(self,alarmtime=10,timerintervall=1, alarmfunction=None,alarmargs=(),kwalarmargs={}):
		self.alarmtime=alarmtime
		self.timer=timerintervall
		self.alarmfunc=alarmfunction
		self.alarmfuncargs=alarmargs
		self.kwalarmfuncargs=kwalarmargs
		self.counter=self.alarmtime
		self._create_timer()
	def stop(self):
		self.alarm.cancel()
		self.running=False
###################
#replace_variables
###################
def replace_variables(text,dictionary,startdelimiter="%",enddelimiter="%"):
	"replaces variables with the values of the dictionary. A variable is embraced of % and consists of capital letters, e.g. %MYVARIABLE%"
	result=""
	begin=0
	dictionary["COPYRIGHT"]="© 2015 Horst Knorr&lt;gpgmailencrypt@gmx.de>"
	dictionary["VERSION"]=VERSION
	dictionary["VERSIONDATE"]=DATE
	while True:
		found=re.search("%s[A-Z]+%s"%(startdelimiter,enddelimiter),text[begin:])
		if found== None:
			result+=text[begin:]
			return result
		result+=text[begin:begin+found.start()]
		key=text[begin+found.start():begin+found.end()].replace(startdelimiter,"").replace(enddelimiter,"")
		try:
			result+=dictionary[key]
		except:
			result+=startdelimiter+key+enddelimiter
			raise
		begin+=found.end()
###################################
#Definition of encryption functions
###################################
###########
#CLASS _GPG
###########
class _GPG:
	@_dbg
	def __init__(self, parent,keyhome=None, recipient = None, counter=0):
		self._recipient = ''
		self._filename=''	
		self.count=counter
		self.parent=parent
		self.parent.debug("_GPG.__init__")
		if isinstance(recipient, str):
			self.set_recipient(recipient)
		if isinstance(keyhome,str):
			self._keyhome = expanduser(keyhome)
		elif self.parent and self.parent._GPGKEYHOME:
			self._keyhome=expanduser(self.parent._GPGKEYHOME)
		else:
			self._keyhome=expanduser('~/.gnupg')
		self.parent.debug("_GPG.__init__ end")
	@_dbg
	def set_filename(self, fname):
		if isinstance(fname,str):
			self._filename=fname.strip()
		else:
			self._filename=''
	@_dbg
	def set_keyhome(self,keyhome):
		if isinstance(keyhome,str):
			self._keyhome=expanduser(keyhome.strip())
		else:
			self._keyhome=''
	@_dbg
	def set_recipient(self, recipient):
		if isinstance(recipient, str):
			self._recipient=recipient
			self.parent._GPGkeys = list()
	@_dbg
	def recipient(self):
		return self._recipient	
	@_dbg
	def public_keys(self):
		if len(self.parent._GPGkeys)==0:
			self._get_public_keys()
		return self.parent._GPGkeys
	@_dbg
	def private_keys(self):
		if len(self.parent._GPGprivatekeys)==0:
			self._get_private_keys()
		return self.parent._GPGprivatekeys
	@_dbg
	def has_public_key(self,key):
		self.parent.debug("gpg.has_public_key '%s'"%key)
		if len(self.parent._GPGkeys)==0:
			self._get_public_keys()
		if not isinstance(key,str):
			self.parent.debug("has_public_key, key not of type str")
			return False
		if key in self.parent._GPGkeys:	
			return True
		else:
			self.parent.debug("has_publickey, key not in _GPGkeys")
			self.parent.debug("_GPGkeys '%s'"%str(self.parent._GPGkeys))
			return False
	@_dbg
	def _get_public_keys( self ):
		self.parent.debug("_GPG._get_public_keys")
		self.parent._GPGkeys = list()
		cmd = '%s --homedir %s --list-keys --with-colons' % (self.parent._GPGCMD, self._keyhome.replace("%user",self._recipient))
		self.parent.debug("_GPG.public_keys command: '%s'"%cmd)
		try:
			p = subprocess.Popen( cmd.split(' '), stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
			p.wait()
			for line in p.stdout.readlines():
				res=line.decode(self.parent._encoding,_unicodeerror).split(":")
				if res[0]=="pub" or res[0]=="uid":
					email=res[9]
					mail_id=res[4]
					try:
						found=re.search("[-a-zA-Z0-9_%\+\.]+@[-_0-9a-zA-Z\.]+\.[-_0-9a-zA-Z\.]+",email)
					except:
						self.parent.log_traceback()
					if found != None:
						try:
							email=email[found.start():found.end()]
						except:
							self.parent.log("splitting email address (%s) didn't work"%email,"w")
							email=""
						email=email.lower()
						if len(email)>0 and self.parent._GPGkeys.count(email) == 0:
							#self.parent.debug("add email address '%s'"%email)
							self.parent._GPGkeys.append(email)
						#else:
							#self.parent.debug("Email '%s' already added"%email)
		except:
			self.parent.log("Error opening keyring (Perhaps wrong directory '%s'?)"%self._keyhome,"e")
			self.parent.log_traceback()
	@_dbg
	def _get_private_keys( self ):
		self.parent.debug("_GPG._get_private_keys")
		self.parent._GPGprivatekeys = list()
		cmd = '%s --homedir %s --list-secret-keys --with-colons' % (self.parent._GPGCMD, self._keyhome.replace("%user",self._recipient))
		self.parent.debug("_GPG.private_keys command: '%s'"%cmd)
		try:
			p = subprocess.Popen( cmd.split(' '), stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
			p.wait()
			for line in p.stdout.readlines():
				res=line.decode(self.parent._encoding,_unicodeerror).split(":")
				if res[0]=="pub" or res[0]=="uid":
					email=res[9]
					mail_id=res[4]
					try:
						found=re.search("[-a-zA-Z0-9_%\+\.]+@[-_0-9a-zA-Z\.]+\.[-_0-9a-zA-Z\.]+",email)
					except:
						self.parent.log_traceback()
					if found != None:
						try:
							email=email[found.start():found.end()]
						except:
							self.parent.log("splitting email address (%s) didn't work"%email,"w")
							email=""
						email=email.lower()
						if len(email)>0 and self.parent._GPGprivatekeys.count(email) == 0:
							#self.parent.debug("add email address '%s'"%email)
							self.parent._GPGprivatekeys.append(email)
						#else:
							#self.parent.debug("Email '%s' already added"%email)
		except:
			self.parent.log("Error opening keyring (Perhaps wrong directory '%s'?)"%self._keyhome,"e")
			self.parent.log_traceback()
	@_dbg
	def encrypt_file(self,filename=None,binary=False, recipient=None):
		result=False
		if filename:
			self.set_filename(filename)
		if len(self._filename) == 0:
			self.parent.log( 'Error: GPGEncrypt: filename not set',"e")
			return result,None
		if recipient:
			self.set_recipient(recipient)
		if len(self._recipient)==0:
			self.parent.log("GPG encrypt file: No recipient set!","e")
			return result,None
		f=self.parent._new_tempfile()
		self.parent.debug("_GPG.encrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call( ' '.join(self._encryptcommand_fromfile(f.name,binary)),shell=True ) 
		self.parent.debug("Encryption command: '%s'" %' '.join(self._encryptcommand_fromfile(f.name,binary)))
		if _result != 0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
			return result,None
		else:
			result=True
		if binary:
			res=open(f.name,mode="br")
			self.parent.debug("GPG.encrypt_file binary open")
		else:
			res=open(f.name)
			self.parent.debug("GPG.encrypt_file text open")
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		return result,encdata
	@_dbg
	def _encryptcommand_fromfile(self,sourcefile,binary):
		cmd=[self.parent._GPGCMD, "--trust-model", "always", "-r",self._recipient,"--homedir", 
		self._keyhome.replace("%user",self._recipient), "--batch", "--yes", "--pgp7", "-q","--no-secmem-warning",
		 "--output",sourcefile, "-e",self._filename ]
		if self.parent._ALLOWGPGCOMMENT==True:
			cmd.insert(1,"'%s'"%self.parent._encryptgpgcomment)
			cmd.insert(1,"--comment")
		if not binary:
			cmd.insert(1,"-a")
		return cmd
	@_dbg
	def decrypt_file(self,filename=None,binary=False,recipient=None):
		result=False
		if recipient:
			self.set_recipient(recipient)
		if filename:
			self.set_filename(filename)
		if len(self._filename) == 0:
			self.parent.log( 'Error: GPGDecrypt: filename not set',"e")
			return result,None
		f=self.parent._new_tempfile()
		self.parent.debug("_GPG.decrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call( ' '.join(self._decryptcommand_fromfile(f.name,binary)),shell=True ) 
		self.parent.debug("Encryption command: '%s'" %' '.join(self._decryptcommand_fromfile(f.name,binary)))
		if _result != 0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
		else:
			result=True
		if binary:
			res=open(f.name,mode="br")
			self.parent.debug("GPG.decrypt_file binary open")
		else:
			res=open(f.name)
			self.parent.debug("GPG.decrypt_file text open")
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		return result,encdata
	@_dbg
	def _decryptcommand_fromfile(self,sourcefile,binary):
		cmd=[self.parent._GPGCMD, "--trust-model", "always", "-q","-r",self._recipient,"--homedir", 
		self._keyhome.replace("%user",self._recipient), "--batch", "--yes", "--pgp7", "--no-secmem-warning", "--output",sourcefile, "-d",self._filename ]
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
#############
#CLASS _SMIME
#############
class _SMIME:
	@_dbg
	def __init__(self,parent, keyhome=None, recipient = None):
		self.parent=parent
		self.parent.debug("_SMIME.__init__ %s"%self.parent._SMIMEKEYHOME)
		if type(keyhome)==str:
			self._keyhome = expanduser(keyhome)
		else:
			self._keyhome=expanduser(self.parent._SMIMEKEYHOME)
		self._recipient = ''
		self._filename=''	
		if isinstance(recipient, str):
			self._recipient=recipient
		self.parent.debug("_SMIME.__init__ end")
	@_dbg
	def public_keys(self):
		result=list()
		for user in self.parent._smimeuser:
			result.append(user)
		return result
	@_dbg
	def private_keys(self):
		result=list()
		for user in self.parent._smimeuser:
			if self.parent._smimeuser[user][2]!=None:
			 result.append(user)
		return result
	@_dbg
	def set_filename(self, fname):
		if isinstance(fname,str):
			self._filename=fname.strip()
		else:
			self._filename=''
	@_dbg
	def set_keyhome(self,keyhome):
		if isinstance(keyhome,str):
			self._keyhome=expanduser(keyhome.strip())
		else:
			self._keyhome=''
	@_dbg
	def set_recipient(self, recipient):
		if isinstance(recipient, str):
			self._recipient=recipient
	@_dbg
	def recipient(self):
		return self._recipient	
	@_dbg
	def has_public_key(self,key):
		if not isinstance(key,str):
			self.parent.debug("smime has_public_key, key not of type str")
			return False
		try:
			_u=self.parent._smimeuser[key]
		except:
			self.parent.debug("smime has_public_key, key not found for '%s'"%key)
			return False
		return True
	@_dbg
	def encrypt_file(self,filename=None,binary=False, recipient=None):
		result=False
		if filename:
			self.set_filename(filename)
		if len(self._filename) == 0:
			self.parent.log( 'Error: _SMIME: filename not set',"m")
			return result,''
		if recipient:
			self.set_recipient(recipient)
		if len(self._recipient)==0:
			self.parent.log("SMIME encrypt file: No recipient set!","e")
			return result,None
		f=self.parent._new_tempfile()
		self.parent.debug("_SMIME.encrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call( ' '.join(self._command_encrypt_fromfile(f.name,binary)),shell=True ) 
		self.parent.debug("Encryption command: '%s'" %' '.join(self._command_encrypt_fromfile(f.name,binary)))
		if _result != 0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
			return result,None
		else:
			result=True
		res=open(f.name,encoding="UTF-8")
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		m=email.message_from_string(encdata)
		return result,m.get_payload()
	@_dbg
	def _command_encrypt_fromfile(self,sourcefile,binary):
		_recipient=self.parent._smimeuser[self._recipient]
		encrypt="des3" # RFC 3583
		if _recipient[1]=="AES256":
			encrypt="aes-256-cbc"
		elif _recipient[1]=="AES128":
			encrypt="aes-128-cbc"
		elif _recipient[1]=="AES192":
			encrypt="aes-192-cbc"
		cmd=[self.parent._SMIMECMD, "smime", "-%s" %encrypt,"-encrypt", "-in",self._filename,"-out", sourcefile,  _recipient[0] ]
		return cmd

	def decrypt_file(self,filename=None,binary=False,recipient=None):
		result=False
		if filename:
			self.set_filename(filename)
		if len(self._filename) == 0:
			self.parent.log( 'Error: _SMIME: filename not set',"m")
			return result,''
		if recipient:
			self.set_recipient(recipient)
		f=self.parent._new_tempfile()
		self.parent.debug("_SMIME.decrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call( ' '.join(self._command_decrypt_fromfile(f.name,binary)),shell=True ) 
		self.parent.debug("Decryption command: '%s'" %' '.join(self._command_decrypt_fromfile(f.name,binary)))
		if _result != 0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
		else:
			result=True
		res=open(f.name,encoding="UTF-8")
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		m=email.message_from_string(encdata)
		return result,m.get_payload()
	@_dbg
	def _command_decrypt_fromfile(self,sourcefile,binary):
		_recipient=self.parent._smimeuser[self._recipient]
		cmd=[self.parent._SMIMECMD, "smime","-decrypt", "-in",self._filename,"-out", sourcefile,"-inkey" , _recipient[2] ]
		return cmd
	@_dbg
	def opensslcmd(self,cmd):
		result=""
		p = subprocess.Popen( cmd.split(" "), stdin=None, stdout=subprocess.PIPE, stderr=subprocess.PIPE )
		result=p.stdout.read()
		return result, p.returncode
	@_dbg
	def get_certemailaddresses(self,certfile):
		cmd=[self.parent._SMIMECMD,"x509","-in",certfile,"-text","-noout"]
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
	def get_certfingerprint(self,cert):
		cmd=[self.parent._SMIMECMD,"x509","-fingerprint","-in",cert,"-noout"]
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
		self.parent.debug("extract_publickey_from_mail to '%s'"%targetdir)
		f=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
		fname=f.name
		cmd=[self.parent._SMIMECMD,"smime","-in", mail,"-pk7out","2>/dev/null","|",self.parent._SMIMECMD,"pkcs7",
		"-print_certs","-out",f.name,"2>/dev/null"]
		self.parent.debug("extractcmd :'%s'"%" ".join(cmd))
		_result = subprocess.call( " ".join(cmd) ,shell=True) 
		f.close()
		size=os.path.getsize(fname)
		if size==0:
			os.remove(fname)
			return None
		fp=self.get_certfingerprint(fname)
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
			self.parent.log("class _SMIME.create_keylist, couldn't read directory '%s'"%directory)
			return result
		_match="^(.*?).pem"
		for _i in _udir:
			  if re.match(_match,_i):
			  	f="%s/%s"%(directory,_i)
			  	emailaddress=self.get_certemailaddresses(f)
			  	if len(emailaddress)>0:
			  		for e in emailaddress:
			  			result[e] = [f,self.parent._SMIMECIPHER]
		return result
	@_dbg
	def verify_certificate(self,cert):
		cmd=[self._SMIMECMD,"verify",cert,"&>/dev/null"]
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
			self.parent.log("Class smime._copyfile: Couldn't copy file!","e")
			self.parent.log_traceback()
###########
#CLASS _PDF
###########
class _PDF:
	@_dbg
	def __init__(self, parent,keyhome=None,  counter=0):
		self._recipient = ''
		self._filename=''	
		self.count=counter
		self.parent=parent
		self.parent.debug("_PDF.__init__")
		if isinstance(keyhome,str):
			self._keyhome = expanduser(keyhome)
		elif self.parent and self.parent._GPGKEYHOME:
			self._keyhome=expanduser(self.parent._GPGKEYHOME)
		else:
			self._keyhome=expanduser('~/.gnupg')
		self.parent.debug("_PDF.__init__ end")
	@_dbg
	def set_filename(self, fname):
		if isinstance(fname,str):
			self._filename=fname.strip()
		else:
			self._filename=''
	@_dbg
	def set_keyhome(self,keyhome):
		if isinstance(keyhome,str):
			self._keyhome=expanduser(keyhome.strip())
		else:
			self._keyhome=''
	@_dbg
	def create_pdffile(self,password,filename=None):
		result=False
		if filename:
			self.set_filename(filename)
		if len(self._filename) == 0:
			self.parent.log( 'Error: create_pdffile: filename not set',"e")
			return result,None
		f=self.parent._new_tempfile(delete=True)
		self.parent.debug("_PDF.create_file _new_tempfile %s"%f.name)
		f.close()
		try:
			os.remove(f.name)
		except:
			pass
		self.parent.debug("PDF creation command: '%s'" %' '.join(self._createpdfcommand_fromfile(f.name)))
		_result = subprocess.call( ' '.join(self._createpdfcommand_fromfile(f.name)),shell=True ) 
		if _result !=0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
			return result,None
		else:
			result=True
		_res,encryptedfile=self._encrypt_pdffile(f.name,password)
		if _res==False:
			self.parent.log("Error encrypting pdf file (Error code %d)"%_res,"e")
			return False,None
		res=open(encryptedfile,mode="br")
		self.parent.debug("PDF.encrypt_file binary open")
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		self.parent._del_tempfile(encryptedfile)
		return result,encdata
	@_dbg
	def _createpdfcommand_fromfile(self,resultfile):
		cmd=[self.parent._PDFCREATECMD, "-i",self._filename, "-o",resultfile,"--headers","--overwrite","--no-attachments","--mostly-hide-warning"]
		return cmd
	@_dbg
	def _encrypt_pdffile(self,inputfilename,password):
		result=False
		f=self.parent._new_tempfile()
		self.parent.debug("_PDF.encrypt_file _new_tempfile %s"%f.name)
		self.parent.debug("Encryption command: '%s'" %' '.join(self._encryptcommand_fromfile(inputfilename,f.name,password)))
		_result = subprocess.call( ' '.join(self._encryptcommand_fromfile(inputfilename,f.name,password)),shell=True ) 
		if _result != 0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
			return result,None
		else:
			result=True
		return result,f.name
	@_dbg
	def _encryptcommand_fromfile(self,fromfile,tofile,password):
		cmd=[self.parent._PDFENCRYPTCMD,fromfile, "output",tofile,"user_pw","\"%s\""%password]
		return cmd
###########
#CLASS _ZIP
###########
class _ZIP:
	def __init__(self, parent):
		self.parent=parent
		self.zipcipher=self.parent._ZIPCIPHER
	def set_zipcipher(self,cipher):
		self.zipcipher=cipher.upper()
	@_dbg
	def create_zipfile(self,directory,password,containerfile=None):
		f=self.parent._new_tempfile()
		self.parent.debug("_PDF.create_file _new_tempfile %s"%f.name)
		f.close()
		fname=f.name
		if containerfile!=None:
			tempdir = tempfile.mkdtemp()
			fname="%s/%s"%(tempdir,containerfile)
			self.parent.debug("ZIP creation command: '%s'" %' '.join(self._createzipcommand_fromdir(fname,directory,password)))
			_result = subprocess.call( ' '.join(self._createzipcommand_fromdir(fname,directory,None,compress=False)),shell=True ) 
			directory=tempdir
			if _result !=0:
				self.parent.log("Error executing command (Error code %d)"%_result,"e")
				try:
					shutil.rmtree(tempdir)
				except:
					pass
				return result,None
		self.parent.debug("ZIP creation command: '%s'" %' '.join(self._createzipcommand_fromdir(f.name,directory,password)))
		_result = subprocess.call( ' '.join(self._createzipcommand_fromdir(f.name,directory,password)),shell=True ) 
		try:
			shutil.rmtree(tempdir)
		except:
			pass
		if _result !=0:
			self.parent.log("Error executing command (Error code %d)"%_result,"e")
			return result,None
		else:
			result=True
		res=open(f.name+".zip",mode="br")
		self.parent.debug("ZIP_file binary open")
		encdata=res.read()
		res.close()
		os.rename(f.name+".zip",f.name)
		self.parent._del_tempfile(f.name)
		return result,encdata
	@_dbg
	def _createzipcommand_fromdir(self,resultfile,directory,password, compress=True):
		cipher="ZipCrypto"
		if self.zipcipher=="AES128":
			cipher="AES128"
		elif self.zipcipher=="AES256":
			cipher="AES256"
		cmd=[self.parent._7ZIPCMD, "a",resultfile, "%s/*"%directory,"-tzip","-mem=%s"%cipher,">/dev/null"]
		if password!=None:
			cmd.insert(4,"-p%s"%password)
		if compress==True:
			cmd.insert(4,"-mx%i"%self.parent._ZIPCOMPRESSION)
		return cmd

#############
#_decode_html
#############
@_dbg
def _decode_html(parent,msg):
	h=_htmldecode(parent)
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
	def __init__(self,parent):
		html.parser.HTMLParser.__init__(self)
		self.data=""
		self.in_throwaway=0
		self.in_keep=0
		self.first_td_in_row=False
		self.dbg=False
		self.abbrtitle=None
		self.parent=parent
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
			self.parent.debug( "<%s>"%tag)
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
			self.parent.debug("</%s>"%tag)
		self.handle_tag(tag,starttag=False)
	def handle_startendtag(self,tag,attrs):
		if self.dbg:
			self.parent.debug("< %s/>"%tag)
		if tag=="br":
			self.handle_tag(tag,attrs,starttag=False)
	def handle_data(self, data):
		if self.in_throwaway==0:
			if self.dbg:
				self.parent.debug("   data: '%s'"%data)
			if self.in_keep>0:
				self.data+=data
			elif len(data.strip())>0:
				self.data+=data.replace("\n","").replace("\r\n","")
	def handle_charref(self, name):
		if self.dbg:
			self.parent.debug("handle_charref '%s'"%name)
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
					self.parent.debug("tr first_td_in_row=True")
			if tag in ("td","th") :
				if self.dbg:
					self.parent.debug("<td/th> first %s"%self.first_td_in_row)
				if  not self.first_td_in_row:
					if self.dbg:
						self.parent.debug("     td/th \\t")
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
					if lastchar not in ("\n","\t"):
						self.data+="\r\n"
			if tag=="abbr" and self.attrtitle!=None:
				self.data+=" [%s] "%self.attrtitle
				self.attrtitle=None
	def mydata(self):
		return self.data
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

class gme:
	"""
	Main class to encrypt emails
	create an instance of gme via 'with gme() as g'
	example:
	with gme() as g:
	  g.encrypt_mails(mailtext,["receiver@mail.com","receiver2@mail.com"])
	
	this will be all to encrypt and send the mails
	"""
	o_mail=1
	o_stdout=2
	o_file=3
	l_none=1
	l_syslog=2
	l_file=3
	l_stderr=4
	m_daemon=1
	m_script=2
	_LOCALEDB={
	#"CN":("审读","文件","内容","文件附件"),
	"DE":("Termin","Datei","Inhalt","Anhang"),
	"EN":("appointment","file","content","attachment"),
	"ES":("cita","fichero","contenido","apéndice"),
	"FR":("rendez-vous","fichier","contenu","attachement"),
	"IT":("appuntamento","file","capacità","allegato"),
	"NL":("Termijn","Bestand","inhoud","e-mailbijlage"),
	"PL":("termin","plik","zawartość","załącznik"),
	"PT":("hora","ficheiro","conteúdo","anexo"),
	"RU":("срок","файл","содержа́ние","прикрепление"),
	"SE":("möte","fil","innehåll","bilaga"),
	}
	_encryptheader="X-GPGMailencrypt"
	_pdfencryptheader="X-PDFEncrypted"
	#########
	#__init__
	#########
	def __init__(self):
		"class creator"
		self._deferred_emails=[]
		self._email_queue={}
		self._queue_id=0
		self._daemonstarttime=datetime.datetime.now()
		self._RUNMODE=None
		self._LOGGING=self.l_none
		self._level=0
		self.reset_statistics()
		self._DEBUG=False
		self._GPGkeys=list()
		self._GPGprivatekeys=list()
		self.init()
	#################
	#reset_statistics
	#################
	def reset_statistics(self):
		self._systemerrors=0
		self._systemwarnings=0
		self._count_totalmails=0
		self._count_encryptedmails=0
		self._count_deferredmails=0
		self._count_alreadyencryptedmails=0
		self._count_alarms=0
		self._count_smimemails=0
		self._count_pgpmimemails=0
		self._count_pgpinlinemails=0
		self._count_pdfmails=0
	###################
	#reset_pdfpasswords
	###################
	@_dbg
	def reset_pdfpasswords(self):
		self._pdfpasswords=dict()
		self._read_pdfpasswordfile(self._PDF_PASSWORDFILE)
	#####################
	#del_old_pdfpasswords
	#####################
	@_dbg
	def del_old_pdfpasswords(self,age):
		"age in seconds"
		deluser=[]
		for user in self._pdfpasswords:
			date=self._pdfpasswords[user][1]
			if date>0 and (date + age < time.time()):
				deluser.append(user)
		for user in deluser:
			del self._pdfpasswords[user]
			self.debug("Password for user '%s' deleted"%user)
	#########
	#__exit__
	#########
	def __exit__(self, exc_type, exc_value, traceback):
		"automatically cleans up tempfiles when created with the 'with' statement"
		self.close()
	##########
	#__enter__
	##########
	def __enter__(self):
		"necessary for the 'with'-creation"
		return self
	######
	#close
	######
	@_dbg
	def close(self):
		"cleans up tempfiles"
		if self._RUNMODE==self.m_daemon:
			self.log("gpgmailencrypt daemon shutdown")
			_now=datetime.datetime.now()
			self.log("gpgmailencrypt server did run %s"%(_now-self._daemonstarttime))
			self._log_statistics()
		for f in self._tempfiles:
			try:
				os.remove(f)
				self.debug("do_finally delete tempfile '%s'"%f)
			except:
				pass
		if self._RUNMODE==self.m_daemon:
			self.store_deferred_list()
		if self._LOGGING and self._logfile!=None:
			self._logfile.close()
	#####
	#init
	#####
	@_dbg
	def init(self):
		"initiales the module and reads the config file"
		#Internal variables
		self._logfile=None
		self._addressmap = dict()
		self._encryptionmap = dict()
		self._smimeuser = dict()
		self._tempfiles = list()
		self._pdfpasswords=dict()
		self._mailcount=0
		self._encryptgpgcomment="Encrypted by gpgmailencrypt version %s"%VERSION
		self._smtpd_passwords=dict()
		self._encoding = locale.getdefaultlocale()[1]
		if self._encoding==None:
			self._encoding="UTF-8"
		self._deferlist=os.path.expanduser("~/deferlist.txt")
		self._deferdir=expanduser("~/gpgmaildirtmp")
		if not os.path.exists(self._deferdir):
			os.makedirs(self._deferdir)
		#GLOBAL CONFIG VARIABLES
		self._STATISTICS_PER_DAY=1
		self._SYSTEMMAILFROM="gpgmailencrypt@localhost"
		self._ALWAYSENCRYPT=False
		self._DEBUG=False
		self._LOGGING=self.l_none
		self._LOGFILE=""
		self._ADDHEADER=False
		self._HOST='localhost'
		self._PORT=25
		self._SERVERHOST="127.0.0.1"
		self._SERVERPORT=1025
		self._AUTHENTICATE=False
		self._SMTP_CREDENTIAL=""
		self._SMTP_USER=""
		self._SMTP_PASSWORD=""
		self._DOMAINS=""
		self._CONFIGFILE='/etc/gpgmailencrypt.conf'
		self._MAILTEMPLATEDIR="/usr/share/gpgmailencrypt/mailtemplates"
		self._INFILE=""
		self._OUTFILE=""
		self._PREFERRED_ENCRYPTION="PGPINLINE"
		self._GPGKEYHOME="~/.gnupg"
		self._ALLOWGPGCOMMENT=False
		self._GPGCMD='/usr/bin/gpg2'
		self._SMIMEKEYHOME="~/.smime"
		self._SMIMEKEYEXTRACTDIR="%s/extract"%self._SMIMEKEYHOME
		self._SMIMECMD="/usr/bin/openssl"
		self._SMIMECIPHER="DES3"
		self._SMIMEAUTOMATICEXTRACTKEYS=False
		self._SPAMSUBJECT="***SPAM"
		self._OUTPUT=self.o_mail 
		self._DEBUGSEARCHTEXT=[]
		self._DEBUGEXCLUDETEXT=[]
		self._LOCALE="EN"
		self._RUNMODE=self.m_script
		self._SMTPD_USE_SMTPS=False
		self._SMTPD_USE_AUTH=False
		self._SMTPD_PASSWORDFILE="/etc/gpgmailencrypt.pw"
		self._SMTPD_SSL_KEYFILE="/etc/gpgsmtpd.key"
		self._SMTPD_SSL_CERTFILE="/etc/gpgsmtpd.cert"
		self._USEPDF=False
		self._PDFCREATECMD="/usr/local/bin/email2pdf"
		self._PDFENCRYPTCMD="/usr/bin/pdftk"
		self._PDFDOMAINS=["localhost"]
		self._PDFSECUREZIPCONTAINER=False
		self._PDFPASSWORDLENGTH=10
		self._PDFPASSWORDLIFETIME=48*60*60
		self._PDF_PASSWORDFILE="/etc/gpgpdfpasswords.pw"
		self._7ZIPCMD="/usr/bin/7za"
		self._ZIPCIPHER="ZipCrypto"
		self._ZIPCOMPRESSION=5
		self._ZIPATTACHMENTS=False
		self._ADMINS=[]
		self._read_configfile()
		if self._DEBUG:
			for a in self._addressmap:
				self.debug("_addressmap: '%s'='%s'"%(a,self._addressmap[a]))
	#################
	#_read_configfile
	#################	
	@_dbg
	def _read_configfile(self):
		_cfg = ConfigParser(inline_comment_prefixes=("#",),comment_prefixes=("#",))
		self._GPGkeys=list()
		try:
			_cfg.read(self._CONFIGFILE)
		except:
			self.log("Could not read config file '%s'"%self._CONFIGFILE,"e")
			self.log_traceback()
			return

		if _cfg.has_section('default'):
			if _cfg.has_option('default','add_header'):
				self._ADDHEADER=_cfg.getboolean('default','add_header')
			if _cfg.has_option('default','output'):
				o=_cfg.get('default','output').lower().strip()
				if o=="mail":
					self._OUTPUT=self.o_mail
				elif o=="stdout":
					self._OUTPUT=self.o_stdout
				elif o=="file":
					self._OUTPUT=self.o_file
				else:
					self._OUTPUT=self.o_stdout
			if _cfg.has_option('default','locale'):
				self._LOCALE=_cfg.get('default','locale').upper().strip()
			if _cfg.has_option('default','systemmailfrom'):
				self._SYSTEMMAILFROM=_cfg.get('default','systemmailfrom').strip
			if _cfg.has_option('default','mailtemplatedir'):
				self._MAILTEMPLATEDIR=_cfg.get('default','mailtemplatedir').strip()
			if _cfg.has_option('default','domains'):
				self._DOMAINS=_cfg.get('default','domains')
			if _cfg.has_option('default','spamsubject'):
				self._SPAMSUBJECT=_cfg.get('default','spamsubject')
			if _cfg.has_option('default','preferred_encryption'):
				p=_cfg.get('default','preferred_encryption').lower()
				if p=="smime":
					self._PREFERRED_ENCRYPTION="SMIME"
				elif p=="pgpmime":
					self._PREFERRED_ENCRYPTION="PGPMIME"
				elif p=="pdf":
					self._PREFERRED_ENCRYPTION="PDF"
				else:
					self._PREFERRED_ENCRYPTION="PGPINLINE"
			if _cfg.has_option('default','alwaysencrypt'):
				self._ALWAYSENCRYPT=_cfg.getboolean('default','alwaysencrypt')
		
		if _cfg.has_section('logging'):
			if _cfg.has_option('logging','log'):
				l=_cfg.get('logging','log').lower()
				if l=="syslog":
					self._LOGGING=self.l_syslog
					self._prepare_syslog()
				elif l=='file':
					self._LOGGING=self.l_file
				elif l=='stderr':
					self._LOGGING=self.l_stderr
				else:
					self._LOGGING=self.l_none
			if _cfg.has_option('logging','file'):
				self._LOGFILE=_cfg.get('logging','file')
			if _cfg.has_option('logging','debug') and  __name__ == "__main__":
				self._DEBUG=_cfg.getboolean('logging','debug')
			if _cfg.has_option('logging','debugsearchtext'):
				s=_cfg.get('logging','debugsearchtext')
				if len(s)>0:
					self._DEBUGSEARCHTEXT=s.split(",")
			if _cfg.has_option('logging','debugexcludetext'):
				e=_cfg.get('logging','debugexcludetext')
				if len(e)>0:
					self._DEBUGEXCLUDETEXT=e.split(",")

		if _cfg.has_section('gpg'):
			if _cfg.has_option('gpg','keyhome'):
				k=_cfg.get('gpg','keyhome')
				if k!=None:
					self._GPGKEYHOME=k.strip()
			if _cfg.has_option('gpg','gpgcommand'):
				self._GPGCMD=_cfg.get('gpg','gpgcommand')
			if _cfg.has_option('gpg','allowgpgcomment'):
				self._ALLOWGPGCOMMENT=_cfg.getboolean('gpg','allowgpgcomment')

		if _cfg.has_section('mailserver'):
			if _cfg.has_option('mailserver','host'):
				self._HOST=_cfg.get('mailserver','host')
			if _cfg.has_option('mailserver','port'):
				self._PORT=_cfg.getint('mailserver','port')
			if _cfg.has_option('mailserver','authenticate'):
				self._AUTHENTICATE=_cfg.getboolean('mailserver','authenticate')
			if _cfg.has_option('mailserver','smtpcredential'):
				self._SMTP_CREDENTIAL=_cfg.get('mailserver','smtpcredential')

		if _cfg.has_section('usermap'):
			for (name, value) in _cfg.items('usermap'):
					self._addressmap[name] = value

		if _cfg.has_section('encryptionmap'):
			for (name, value) in _cfg.items('encryptionmap'):
					self._encryptionmap[name] = value.split(":")

		if _cfg.has_section('daemon'):
			if _cfg.has_option('daemon','host'):
				self._SERVERHOST=_cfg.get('daemon','host')
			if _cfg.has_option('daemon','port'):
				self._SERVERPORT=_cfg.getint('daemon','port')
			if _cfg.has_option('daemon','smtps'):
				self._SMTPD_USE_SMTPS=_cfg.getboolean('daemon','smtps')
			if _cfg.has_option('daemon','sslkeyfile'):
				self._SMTPD_SSL_KEYFILE=_cfg.get('daemon','sslkeyfile')
			if _cfg.has_option('daemon','sslcertfile'):
				self._SMTPD_SSL_CERTFILE=_cfg.get('daemon','sslcertfile')
			if _cfg.has_option('daemon','authenticate'):
				self._SMTPD_USE_AUTH=_cfg.getboolean('daemon','authenticate')
			if _cfg.has_option('daemon','smtppasswords'):
				self._SMTPD_PASSWORDFILE=_cfg.get('daemon','smtppasswords')
			try:
				self._STATISTICS_PER_DAY=_cfg.getint('daemon','statistics')
				if self._STATISTICS_PER_DAY >24:
					self._STATISTICS_PER_DAY=24
			except:
				pass
			try:
				admins=_cfg.get('daemon','admins').split(",")
				for a in admins:
					self._ADMINS.append(a.strip())
			except:
				pass

		if _cfg.has_section('pdf'):
			try:
				self._USEPDF=_cfg.getboolean('pdf','useenryptpdf')
			except:
				pass
			if not self._USEPDF and self._PREFERRED_ENCRYPTION=="PDF":
				self._PREFERRED_ENCRYPTION="PGPINLINE"
			try:
				self._PDFCREATECMD=_cfg.get('pdf','email2pdfcommand')
			except:
				pass
			try:
				self._PDFENCRYPTCMD=_cfg.get('pdf','pdftkcommand')
			except:
				pass
			try:
				domains=_cfg.get('pdf','pdfdomains').split(",")
				self._PDFDOMAINS=[]
				for d in domains:
					self._PDFDOMAINS.append(d.lower().strip())	
			except:
				pass
			try:
				self._PDFPASSWORDLENGTH=_cfg.getint('pdf','passwordlength')
			except:
				pass
			try:
				self._PDFPASSWORDLIFETIME=_cfg.getint('pdf','passwordlifetime')
			except:
				pass
			try:
				self._PDF_PASSWORDFILE=_cfg.get('pdf','pdfpasswords')
			except:
				pass
			try:
				self._read_pdfpasswordfile(self._PDF_PASSWORDFILE)
			except:
				self.log("File '%s' could not be opened."%self._PDF_PASSWORDFILE)
				pass

		if _cfg.has_section('zip'):
			try:
				self._PDFSECUREZIPCONTAINER=_cfg.getboolean('zip','securezipcontainer')
			except:
				pass
			try:
				self._7ZIPCMD=_cfg.get('zip','7zipcommand')
			except:
				pass
			try:
				self._ZIPCIPHER=_cfg.get('zip','defaultcipher').upper().strip()
			except:
				pass
			try:
				self._ZIPCOMPRESSION=_cfg.getint('zip','compressionlevel')
				if self._ZIPCOMPRESSION not in [1,3,5,7,9]:
					self._ZIPCOMPRESSION=5
			except:
				pass
			try:
				self._ZIPATTACHMENTS=_cfg.getboolean('zip','zipattachments')
			except:
				pass
	
		if _cfg.has_section('smime'):
			if _cfg.has_option('smime','opensslcommand'):
				self._SMIMECMD=_cfg.get('smime','opensslcommand')
			if _cfg.has_option('smime','defaultcipher'):
				self._SMIMECIPHER=_cfg.get('smime','defaultcipher').upper().strip()
			if _cfg.has_option('smime','keyhome'):
				k=_cfg.get('smime','keyhome')
				if k!=None:
					self._SMIMEKEYHOME=k.strip()
			if _cfg.has_option('smime','extractkey'):
				self._SMIMEAUTOMATICEXTRACTKEYS=_cfg.getboolean('smime','extractkey')
			if _cfg.has_option('smime','keyextractdir'):
				k=_cfg.get('smime','keyextractdir')
				if k!=None:
					self._SMIMEKEYEXTRACTDIR=k.strip()
		s=_SMIME(self,self._SMIMEKEYHOME)
		self._smimeuser.update(s.create_keylist(self._SMIMEKEYHOME))
		if _cfg.has_section('smimeuser'):
			self._smimeuser = dict()
			privatepath=None
			for (name, value) in _cfg.items('smimeuser'):
				user=value.split(",")
				cipher=self._SMIMECIPHER
				if len(user)>1:
					tmpcipher=user[1].upper().strip()
					if len(tmpcipher)>0 and tmpcipher!="DEFAULT":
						cipher=tmpcipher
				if len(user)>2:
					privatepath=os.path.expanduser(os.path.join(self._SMIMEKEYHOME,user[2]))
				publicpath=os.path.expanduser(os.path.join(self._SMIMEKEYHOME,user[0]))
				if os.path.isfile(publicpath):
					self._smimeuser[name] = [publicpath,cipher,privatepath]
		self._set_logmode()
		if self._DEBUG:
			for u in self._smimeuser:
				self.debug("SMimeuser: '%s %s'"%(u,self._smimeuser[u]))
		if self._AUTHENTICATE:
			self._read_smtpcredentials(self._SMTP_CREDENTIAL)
		
	###################
	#_parse_commandline
	###################
	def _parse_commandline(self):
		receiver=[]
		try:
			cl=sys.argv[1:]
			_opts,_remainder=getopt.gnu_getopt(cl,'ac:de:f:hk:l:m:n:o:vxyz',
	  		['addheader','config=','daemon','example','help','keyhome=','log=','output=','verbose','version','zip'])
		except getopt.GetoptError as e:
			self._LOGGING=self.l_stderr
			self.log("unknown commandline parameter '%s'"%e,"e")
			exit(2)
		for _opt, _arg in _opts:
			if _opt == '--version':
				print("gpgmailencrypt version %s from %s"%(VERSION,DATE))
				exit(0)
			if _opt  =='-l' or  _opt == '--log':
				self._LOGGING=self.l_stderr
				if isinstance(_arg,str):
					if _arg=="syslog":
						self._LOGGING=self.l_syslog
						self._prepare_syslog()
					else:
						self._LOGGING=self.l_stderr
		for _opt, _arg in _opts:
			if (_opt  =='-c' or  _opt == '--config') and _arg!=None:
		   		_arg=_arg.strip()
		   		if len(_arg)>0:
		   			self._CONFIGFILE=_arg
		   			self.log("read new config file '%s'"%self._CONFIGFILE)
		   			self._read_configfile()
		   			break
		for _opt, _arg in _opts:
			if _opt  =='-a' or  _opt == '--addheader':
		   		self._ADDHEADER=True
			if _opt  =='-v' or  _opt == '--verbose':
		   		self._DEBUG=True
			if _opt  =='-e':
				a=_arg.lower()
				if a=="smime":
					self._PREFERRED_ENCRYPTION="SMIME"
				elif a=="pgpmime":
					self._PREFERRED_ENCRYPTION="PGPMIME"
				elif a=="none":
					self._PREFERRED_ENCRYPTION="NONE"
				else:
					self._PREFERRED_ENCRYPTION="PGPINLINE"
				self.debug("Set _PREFERRED_ENCRYPTION to '%s'"%self._PREFERRED_ENCRYPTION)
			if _opt  =='-f':
		   		self._INFILE=expanduser(_arg)
		   		self.debug("Set _INFILE to '%s'"%self._INFILE)
			if _opt  =='-h' or  _opt == '--help':
		   		show_usage()
		   		exit(0)
			if _opt  =='-k' or  _opt == '--keyhome':
		   		self._GPGKEYHOME=_arg
		   		self.debug("Set gpgkeyhome to '%s'"%self._GPGKEYHOME)
			if _opt  =='-l' or  _opt == '--log':
				self._LOGGING=self.l_stderr
				if isinstance(_arg,str):
					if _arg=="syslog":
						self._LOGGING=self.l_syslog
					elif _arg=='file':
						self._LOGGING=self.l_file
					else:
						self._LOGGING=self.l_stderr
	
			if _opt  =='-o' or  _opt == '--output':
				if isinstance(_arg,str):
					if _arg=="mail":
						self._OUTPUT=self.o_mail
					elif _arg=="stdout":
						self._OUTPUT=self.o_stdout
					elif _arg=="file":
						self._OUTPUT=self.o_file
					else:
						self._OUTPUT=self.o_stdout
			if _opt  =='-m':
		   		self._OUTFILE=expanduser(_arg)
		   		self._OUTPUT=self.o_file
		   		self.debug("Set _OUTFILE to '%s'"%self._OUTFILE)
			if (_opt  =='-s' or  _opt == '--stdout') and len(self._OUTFILE)==0:
			   	self._OUTPUT=self.o_stdout
			if (_opt  =='-d' or  _opt == '--daemon'):
			   	self._RUNMODE=self.m_daemon
			if _opt  =='-x' or  _opt == '--example':
		   		print_exampleconfig()
		   		exit(0)
			if (_opt  =='-z' or  _opt == '--zip'):
			   	self._ZIPATTACHMENTS=True
		if not self._RUNMODE==self.m_daemon:
			if len(_remainder)>0 :
				receiver=_remainder[0:]
				self.debug("set addresses from commandline to '%s'"%receiver)
			else:
				self._LOGGING=self.l_stderr
				self.log("gpgmailencrypt needs at least one recipient at the commandline, %i given"%len(_remainder),"e")
				exit(1)
		return receiver
	######################
	#_read_smtpcredentials
	######################	
	@_dbg
	def _read_smtpcredentials(self,pwfile):
		if not self._AUTHENTICATE:
			return
		try:
			f=open(pwfile)
		except:
			self.log("hksmtpserver: Config file could not be read","e")
			self.log_traceback()
			exit(5)
		txt=f.read()
		f.close()
		c=0
		for l in txt.splitlines():
			try:
				name,passwd=l.split("=",1)
				self._SMTP_USER=name.strip()
				self._SMTP_PASSWORD=passwd.strip()
				c+=1
			except:
				pass
		self.debug("_read_smtpcredentials END read lines: %i"%c)
	####
	#log
	####
	def log(self,msg,infotype="m",ln=-1):
		"prints logging information"
		if self._LOGGING!=self.l_none:
			if infotype=='d':
				space=" "*self._level
			else:
				space=" "
			if ln==-1:
				ln=inspect.currentframe().f_back.f_lineno
			_lftmsg=20
			prefix="Info"
			if infotype=='w':
				self._systemwarnings+=1
				prefix="Warning"
			elif infotype=='e':
				self._systemerrors=+1
				prefix="Error"
			elif infotype=='d':
				prefix="Debug"
			t=time.localtime(time.time())
			_lntxt="Line %i:%s"%(ln,space)
			tm=("%02d.%02d.%04d %02d:%02d:%02d:" % (t[2],t[1],t[0],t[3],t[4],t[5])).ljust(_lftmsg)
			txt=_splitstring(msg,320)
			c=0
			for t in txt:
				if (ln>0):
					t=_lntxt+t
				l=len(txt)
				if l>1 and c<l-1:
					t=t+"\\"
				c+=1
				if self._LOGGING==self.l_syslog:
					#write to syslog
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
				elif  self._LOGGING==self.l_file and self._logfile!=None:
					#write to _logfile
					self._logfile.write("%s %s: %s\n"%(tm,prefix,t ))
					self._logfile.flush()
				else:
					# print to stdout if nothing else works
					sys.stdout.write("%s %s: %s\n"%(tm,prefix,t ))
	##############
	#log_traceback
	##############
	def log_traceback(self):
		"logs the exception information"
		exc_type, exc_value, exc_tb = sys.exc_info()
		error=traceback.format_exception(exc_type, exc_value, exc_tb)
		for e in error:
			self.log(" ***%s"%e.replace("\n",""),"e")
	######
	#debug
	######
	def debug(self,msg,lineno=0):
		"prints debugging information"
		if self._DEBUG:
			if lineno==0:
				ln=inspect.currentframe().f_back.f_lineno
			else:
				ln=lineno
			self.log(msg,"d",ln)
	################
	#_debug_keepmail
	################
	@_dbg
	def _debug_keepmail(self,mailtext):
		searchtext=mailtext.lower()
		#return True
		for txt in self._DEBUGSEARCHTEXT:
			if txt.lower() in searchtext:
				for exclude in self._DEBUGEXCLUDETEXT:
					if exclude.lower() in searchtext:
						return False
				return True
		return False
	#################
	#_create_password
	#################
	@_dbg
	def _create_password(self,pwlength=10):
		#prior to pdf 1.7 only ASCII characters are allowed and maximum 32 characters
		if pwlength<5:
			pwlength=5
		elif pwlength>32:
			pwlength=32
		nonletters="0123456789+-*/@"
		pwkeys="ABCDEFGHJKLMNOPQRSTUVWXYZabcdefghijkmnopqrstvwxyz"+nonletters
		return ''.join(random.SystemRandom().choice(pwkeys) for _ in range(pwlength))
	####################
	#_load_rawmailmaster
	####################
	@_dbg
	def _load_rawmailmaster(self,identifier,defaulttext):
		f=None
		self.debug("_load_mailmaster '%s'"% identifier)
		try:
			f=open("%s/%s/%s.html"%(self._MAILTEMPLATEDIR,self._LOCALE,identifier))
			self.debug("template found in %s"%("%s/%s/%s.html"%(self._MAILTEMPLATEDIR,self._LOCALE,identifier)))
		except:
			pass
		if f==None:
			try:
				f=open("%s/EN/%s.html"%(self._MAILTEMPLATEDIR,identifier))
				self.debug("template found in %s"%("%s/EN/%s.html"%(self._MAILTEMPLATEDIR,identifier)))
			except:
				pass
		if f==None:
			self.debug("template not found, returning defaulttext")
			return defaulttext
		
		txt=f.read()
		f.close()
		txt=re.sub(r'(?:\r\n|\n|\r(?!\n))', "\r\n", txt)
		return txt
	#################
	#_load_mailmaster
	#################
	def _load_mailmaster(self,identifier,defaulttext):
		mail=self._load_rawmailmaster("00-template","<html><body>%EMAILTEXT%</body></html>")
		txt=self._load_rawmailmaster(identifier,defaulttext)
		return replace_variables(mail,{"EMAILTEXT":txt})
	################
	#set_pdfpassword
	################
	@_dbg
	def set_pdfpassword(self,user,password,autodelete=True):
		if autodelete==True:
			starttime=time.time()
		else:
			starttime=0
		
		self._pdfpasswords[user]=(password,starttime)
	################
	#get_pdfpassword
	################
	@_dbg
	def get_pdfpassword(self,user):
		pw=None
		try:
			pw=self._pdfpasswords[user]
			return pw[0]
		except:	
			pass

		pw= self._create_password(self._PDFPASSWORDLENGTH)
		self.set_pdfpassword(user,pw)
		return pw
	########################
	#_read_pdfpasswordfile
	########################
	@_dbg
	def _read_pdfpasswordfile( self,pwfile):
		try:
			f=open(os.path.expanduser(pwfile))
		except:
			self.log("read_pdfpasswordfile: passwords could not be read","e")
			self.log_traceback()
			return
		txt=f.read()
		f.close()
		self._pdfpasswords=dict()
		for l in txt.splitlines():
			try:
				name,passwd=l.split("=",1)
				self._pdfpasswords[name.strip()]=(passwd.strip(),0)
			except:
				pass
	#############
	#_set_logmode
	#############
	@_dbg
	def _set_logmode(self):
		""
		try:
			if self._LOGGING==self.l_file and len(self._LOGFILE)>0:
				self._logfile = open(self._LOGFILE, 'a')
		except:
			self._logfile=None
			self._LOGGING=self.l_stderr
			self.log_traceback()
	#####################
	#_store_temporaryfile
	#####################
	@_dbg
	def _store_temporaryfile(self,message,add_deferred=False,spooldir=False,fromaddr="",toaddr=""):
		self.debug("_store_temporaryfile add_deferred=%s"%add_deferred)
		try:
			tmpdir=None
			if add_deferred or spooldir:
				tmpdir=self._deferdir
			f=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-',dir=tmpdir)
			f.write(message.encode("UTF-8",_unicodeerror))
			f.close()
			if add_deferred:
				self._deferred_emails.append([f.name,fromaddr,toaddr,time.time()])
				self._count_deferredmails+=1
				self.log("store_temporaryfile.append deferred email '%s'"%f.name)
			else:
				self.debug("Message in temporary file '%s'"%f.name)
			return f.name
		except:
			self.log("Couldn't save email in temporary file, write error")
			self.log_traceback()
		return None
	################
	#_prepare_syslog
	################
	@_dbg
	def _prepare_syslog(self):
			self._LOGGING=self.l_syslog
			syslog.openlog("gpgmailencrypt",syslog.LOG_PID,syslog.LOG_MAIL)
	######################
	#_read_smtpcredentials
	######################	
	@_dbg
	def _read_smtpcredentials(self,pwfile):
		if not self._AUTHENTICATE:
			return
		try:
			f=open(pwfile)
		except:
			self.log("hksmtpserver: Config file could not be read","e")
			self.log_traceback()
			exit(5)
		txt=f.read()
		f.close()
		c=0
		for l in txt.splitlines():
			try:
				name,passwd=l.split("=",1)
				self._SMTP_USER=name.strip()
				self._SMTP_PASSWORD=passwd.strip()
				c+=1
			except:
				pass
		self.debug("_read_smtpcredentials END read lines: %i"%c)
	########################
	#_remove_mail_from_queue
	########################
	@_dbg
	def _remove_mail_from_queue(self,m_id):
		try:
			if m_id>-1:
				mail=self._email_queue[m_id]
				try:
					self.debug("_remove_mail_from_queue file '%s'"%mail[0])
					os.remove(mail[0])
				except:
					pass
				del self._email_queue[m_id]
		except:
			self.log("mail %i could not be removed from queue"%m_id)
			self.log_traceback()
	################
	#zip_attachments
	################
	@_dbg
	def zip_attachments(self,mailtext):
		message = email.message_from_string( mailtext )		
		tempdir = tempfile.mkdtemp()
		Zip=_ZIP(self)
		for m in message.walk():
			contenttype=m.get_content_type()
			if (m.get_param( 'attachment', None, 'Content-Disposition' ) is not None) and self.is_compressable(contenttype,m.get_filename()):
				is_text=m.get_content_maintype()=="text"
				charset=m.get_param("charset",header="Content-Type")
				if charset==None or charset.upper()=="ASCII" or len(charset)==0:
					charset="UTF-8"
				cte=m["Content-Transfer-Encoding"]
				if not cte:
					cte="8bit"
				filename = m.get_filename()
				self.debug("zipping file '%s'"%filename)
				zipFilename = "%s.zip"%filename
				zipFilenamecD,zipFilenamecT=_encodefilename(zipFilename)
				self.debug("Content-Type=%s"%contenttype)
				if  isinstance( m.get_payload() , list ):
					for part in m.get_payload():
						if isinstance(part,email.message.Message):
							raw_payload=part.as_bytes()
							break
						else:
							continue
				else:
					raw_payload = m.get_payload(decode=not is_text)
				if is_text:
					raw_payload=_decodetxt(raw_payload,cte,charset)	
					m.del_param("charset")	
					m.set_param("charset",charset)
					raw_payload=raw_payload.encode(charset,_unicodeerror)
				fp=open("%s/%s"%(tempdir,filename),"wb")

				try:
					fp.write(raw_payload)
				except:
					self.log("File '%s' could not be written"%filename)
					self.log_traceback()
				fp.close()
				result,zipfile=Zip.create_zipfile(tempdir,password=None,containerfile=None)
				try:
					os.remove(fp.name)
				except:
					pass
				if result==True:
					if m["Content-Transfer-Encoding"]:
						del m["Content-Transfer-Encoding"]
					m["Content-Transfer-Encoding"]="base64"
					m.set_type( 'application/zip')
					if m["Content-Disposition"]:
						del m["Content-Disposition"]
					m.add_header('Content-Disposition', 'attachment; filename*="%s"' % zipFilenamecD)
					m.set_param( 'name', zipFilenamecT )
					m.set_payload(str(base64.encodebytes(zipfile),"ascii"))
		try:
			shutil.rmtree(tempdir)
		except:
			pass
		return message.as_string()
	################
	#is_compressable
	################
	@_dbg
	def is_compressable(self,filetype,filename):
		maintype,subtype=filetype.lower().split("/")
		filename, extension = os.path.splitext(filename)
		if maintype=="video":
			return False
		if maintype=="image":
			if subtype in ["bmp","x-windows-bmp","svg+xml","tiff",
					"photoshop","x-photoshop","psd"]:
				return True
			#raw image format
			elif extension in ["3fr","ari","arw","bay","crw","cr2","cap","dcs","dcr","dng","drf","eip","erf",
					"fff","iiq","k25","kdc","mdc","mef","mos","mrw","nef","nrw","obm","orf","pef",
					"ptx","pxn","r3d","raf","raw","rwl","rw2","rwz","sr2","srf","srw","tif","x3f"]:
				return True 
			else:
				return False
		if maintype=="audio":
			if subtype in ["x-aiff","x-wav"]:
				return True
			else:
				return False
		if maintype=="application":
			#compressed archives
			if subtype in   ["zip","x-compressed","x-compress","x-gzip","x-gtar","x-lzip",
					"x-lzma","x-lzh","x-lzip","x-lzop","x-zoo","x-rar-compressed","x-7z-compressed",
					"x-bzip","x-bzip2","vnd.android.package-archive","x-snappy-framed","x-xz",
					"x-ace-compressed","x-astrotite-afa","x-alz-compressed","x-b1","x-dar","x-dgc-compressed",
					"x-apple-diskimage","x-apple-diskimage","x-lzx",
					"x-arj","vnd.ms-cab-compressed","x-cfs-compressed","x-stuffit","x-stuffitx"]:
				return False
			#compressed Microsoft Office formats
			elif subtype in ["application/vnd.openxmlformats-officedocument.wordprocessingml.document",
					"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", 
					"application/vnd.openxmlformats-officedocument.presentationml.presentation"]:
				return False
			#Openoffice/LibreOffice
			elif subtype in ["vnd.oasis.opendocument.text","vnd.oasis.opendocument.spreadsheet",
					"vnd.oasis.opendocument.presentation","vnd.oasis.opendocument.graphics",
					"vnd.oasis.opendocument.chart","vnd.oasis.opendocument.formula",
					"vnd.oasis.opendocument.image","vnd.oasis.opendocument.text-master",
					"vnd.oasis.opendocument.text-template","vnd.oasis.opendocument.spreadsheet-template",
					"vnd.oasis.opendocument.presentation-template","vnd.oasis.opendocument.graphics-template"]:
				return False
			#misc.
			elif subtype in ["epub+zip","vnd.gov.sk.e-form+zip"]:
				return False
			extension=extension.lower()[1:]
			#same as above, just over the file extension
			if subtype=="octet-stream":
				if extension in ["jpg","jpeg","png","gif","jif","jfif","jp2","j2k","jpx","j2c","psd",
					#Videos
					"mpeg","mpg","mpe","mpgv","mp4","mpg4","mov","avi","mkv","swf","flv","f4v","f4p","f4a",
					"f4b","wmv","ogv","m2t","mjpeg","3gp","asx","m4v","rv","swz","rm","m2v","mv4","xwmv"
					"3ga","mp3","ogg",
					#Archives
					"zip","arj","deb","tgz","bz2","bz","gz","7z","s7z","rar","ar","xar",
					"cpio","lz","lzh","lha","lzo","lzma","xz","z","apk","cab","rpm","jar","zoo",
					#Office
					"docx","xlsx","pptx","ods","odt","odp","ott","odm","oth","ots","odg","otg","odf","odb","oxt",
					"odg","odc","odi",
					#Misc
					"epub"
					]:
					return False
		return True
	#############
	#_send_rawmsg
	#############
	@_dbg
	def _send_rawmsg(self,m_id,mailtext,msg,from_addr, to_addr):
		try:
			message = email.message_from_string( mailtext )
			if self._ADDHEADER and not self._encryptheader in message and msg:
				message.add_header(self._encryptheader,msg)
			self._send_msg(m_id,message,from_addr,to_addr)
		except:
			self.log("_send_rawmsg: exception _send_textmsg")
			self.log_traceback()
			self._send_textmsg(m_id,mailtext,from_addr,to_addr)
	##########
	#_send_msg
	##########
	@_dbg
	def _send_msg( self,m_id,message,from_addr,to_addr ):
		self.debug("_send_msg output %i"%self._OUTPUT)
		if isinstance(message,str):
			self._send_textmsg(m_id,message,from_addr,to_addr)
		else:
			if self._ADDHEADER and not self._encryptheader in message:
				message.add_header(self._encryptheader,self._encryptgpgcomment)
			self._send_textmsg(m_id,message.as_string(),from_addr,to_addr)
	##############
	#_send_textmsg
	##############
	@_dbg
	def _send_textmsg(self,m_id,message, from_addr,to_addr,store_deferred=True):
		self.debug("_send_textmsg output %i"%self._OUTPUT)
		if self._OUTPUT==self.o_mail:
			if len(to_addr) == 0:
				self.log("Couldn't send email, recipient list is empty!","e")
				return False
			self.debug("Sending email to: <%s>" % to_addr)
			try:
				smtp = smtplib.SMTP(self._HOST, self._PORT)
				smtp.ehlo_or_helo_if_needed()
				try:
					if smtp.has_extn("starttls"):
						self.debug("_send_textmsg starttls")
						smtp.starttls()
						smtp.ehlo_or_helo_if_needed()
				except:
					self.debug("smtp.starttls on server failed")
				if self._AUTHENTICATE and smtp.has_extn("auth"):
					self.debug("_send_textmsg: authenticate at smtp server with user %s"%self._SMTP_USER)
					try:
						smtp.login(self._SMTP_USER,self._SMTP_PASSWORD)
					except smtplib.SMTPAuthenticationError:
						self.log("Could not send email, could not authenticate","e")
						self.debug("_send_textmsg: store_deferred %s" % store_deferred)
						if store_deferred:
							self._store_temporaryfile(message,add_deferred=True,fromaddr=from_addr,toaddr=to_addr)
						return False
				self.debug("smtp.sendmail")
				message=re.sub(r'(?:\r\n|\n|\r(?!\n))', "\r\n", message)
				smtp.sendmail( from_addr, to_addr, message.encode("UTF-8") )
				self._remove_mail_from_queue(m_id)
				return True
			except:
				self.log("Couldn't send mail!","e")
				self.log_traceback()
				self.debug("store_deferred %s"%store_deferred)
				if store_deferred:
					self._store_temporaryfile(message,add_deferred=True,fromaddr=from_addr,toaddr=to_addr)
					self._remove_mail_from_queue(m_id)
				return False
		elif self._OUTPUT==self.o_file and self._OUTFILE and len(self._OUTFILE)>0:
			try:
				fname=self._OUTFILE
				if self._mailcount>0:
					fname=self._OUTFILE+"."+str(self._mailcount)
				f=open(fname,mode='w',encoding="UTF-8")
				f.write(message)
				f.close()
				self._mailcount+=1
				self._remove_mail_from_queue(m_id)
				return True
			except:
				self.log("Could not open Outputfile '%s'"%self._OUTFILE,"e")
				self.log_traceback()
				return False
		else:
			print (message)
			self._remove_mail_from_queue(m_id)
			return True
	###################
	#load_deferred_list
	###################
	@_dbg
	def load_deferred_list(self):
		"loads the list with deferred emails, that have to be sent later"
		self._deferred_emails=[]
		try:
			f=open(self._deferlist)
			for l in f:
				mail=l.split("|")
				mail[3]=float(mail[3])
				self._deferred_emails.append(mail)
			f.close()
			self._count_deferredmails=len(self._deferred_emails)
		except:
			self.log("Couldn't load defer list '%s'"%self._deferlist)
	####################
	#store_deferred_list
	####################
	@_dbg
	def store_deferred_list(self):
		"stores the list with deferred emails, that have to be sent later"
		try:
			self.debug("store_deferred_list '%s'"%self._deferlist)
			f=open(self._deferlist,"w")
			for mail in self._deferred_emails:
				mail[3]=str(mail[3])
				f.write("|".join(mail))
				f.write("\n")
			for qid in self._email_queue:
				mail=self._email_queue[qid]
				mail[3]=str(mail[3])
				f.write("|".join(mail))
				f.write("\n")
			f.close()
		except:
			self.log("Couldn't store defer list '%s'"%self._deferlist)
			self.log_traceback()
	######################
	#_is_old_deferred_mail
	######################
	@_dbg
	def _is_old_deferred_mail(self,mail):
		_maxage=3600*48 #48 hrs
		now=time.time()
		if (now - mail[3]) > _maxage:
			self.log("Deferred mail '%s' will be removed because of age"%mail[0])
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
	def check_deferred_list(self):
		"tries to re-send deferred emails"
		new_list=[]
		for mail in self._deferred_emails:
			try:
				f=open(mail[0])
				msg=f.read()
				f.close()
				if not self._send_textmsg(-1,msg,mail[1],mail[2],store_deferred=False):
					if not self._is_old_deferred_mail(mail):
						new_list.append(mail)
				else:
					self.log("Deferred mail successfully sent from %s to %s"%(mail[1],mail[2]))
					try:
						os.remove(mail[0])
					except:
						pass	
			except:
				self.log("Could not read file '%s'"%mail[0])
				if not self._is_old_deferred_mail(mail):
					new_list.append(mail)	
		self._deferred_emails=new_list
		self.debug("End check_deferred_list")		
	################
	#check_mailqueue
	################
	@_dbg
	def check_mailqueue(self):
		for qid in self._email_queue:
			mail=self._email_queue[qid]
			try:
				f=open(mail[0],"rb")
				m=f.read()
				f.close()
				mailtext=m.decode("UTF-8",_unicodeerror)
				self.encrypt_single_mail(-1,mailtext,mail[1],mail[2])	
				del self._email_queue[qid]
			except:
				self.log("mail couldn't be removed from email queue")
				self.log_traceback()
	#########
	#is_admin
	#########
	@_dbg
	def is_admin(self,user):
		return user in self._ADMINS
	################
	#_log_statistics
	################
	@_dbg
	def _log_statistics(self):
		self.log("Mail statistics: total: %i, encrypt: %i, were encrypted: %i, total deferred: %i, still deferred: %i" %\
		(self._count_totalmails,self._count_encryptedmails,self._count_alreadyencryptedmails,self._count_deferredmails,len(self._deferred_emails)))
		self.log("PGPMIME: %i, PGPINLINE: %i, SMIME: %i, PDF: %i"%(self._count_pgpmimemails,
				self._count_pgpinlinemails, self._count_smimemails ,self._count_pdfmails))
		self.log("systemerrors: %i, systemwarnings: %i" %(self._systemerrors,self._systemwarnings))
	##############
	#_new_tempfile
	##############
	@_dbg
	def _new_tempfile(self,delete=False):
		"creates a new tempfile"
		f=tempfile.NamedTemporaryFile(mode='wb',delete=delete,prefix='mail-')
		self._tempfiles.append(f.name)
		self.debug("_new_tempfile %s"%f.name)
		return f
	##############
	#_del_tempfile
	##############
	@_dbg
	def _del_tempfile(self,f):
		"deletes the tempfile, f is the name of the file"
		n=""
		if not isinstance(f,str):
			return
		self.debug("_del_tempfile:%s"%f)
		try:
			self._tempfiles.remove(f)
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
	def _find_charset(self,msg):
		if not isinstance(msg, str):
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
	def _make_boundary(self,text=None):
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
	def set_output2mail(self):
		"outgoing email will be sent to email server"
		self._OUTPUT=self.o_mail
	################
	#set_output2file
	################
	@_dbg
	def set_output2file(self,mailfile):
		"outgoing email will be written to file 'mailfile'"
		if not isinstance(mailfile,str):
			return
		self._OUTFILE=expanduser(mailfile)
		self._OUTPUT=self.o_file
	##################
	#set_output2stdout
	##################
	@_dbg
	def set_output2stdout(self):
		"outgoing email will be written to stdout"
		self._OUTPUT=self.o_stdout
	###########
	#get_output
	###########
	@_dbg
	def get_output(self):
		"returns the output way"
		return self._OUTPUT
	##########
	#set_debug
	##########
	@_dbg
	def set_debug(self,dbg):
		"set debug mode"
		if dbg:
			self._DEBUG=True
		else:
			self._DEBUG=False
	###########
	#set_locale
	###########
	@_dbg
	def set_locale(self,l):
		"sets the locale"
		if isinstance(l,str):
			l=l.strip()
			if len(l)>0:
				self._LOCALE=l
	###############
	#set_configfile
	###############
	@_dbg
	def set_configfile(self,f):
		"loads the configfile f without any init"
		if not f:
			return
		cf=f.strip()
		if len(cf)>0:
			self._CONFIGFILE=cf
			self.debug("read new config file '%s'"%self._CONFIGFILE)
			self._read_configfile()
	###########
	#get_locale
	###########
	@_dbg
	def get_locale(self):
		"returns the Locale"
		return self._LOCALE
	###############
	#get_statistics
	###############
	@_dbg
	def get_statistics(self):
		"returns how many mails were handeled"
		return {"total":self._count_totalmails,
			"total encrypt":self._count_encryptedmails,
			"deferred":self._count_deferredmails,
			"still deferred":len(self._deferred_emails),
			"total already encrypted":self._count_alreadyencryptedmails,
			"total smime":self._count_smimemails,
			"total_pdf":self._count_pdfmails,
			"total pgpmime":self._count_pgpmimemails,
			"total pgpinline":self._count_pgpinlinemails,
			"systemerrors":self._systemerrors,
			"systemwarnings":self._systemwarnings,
			}
	###########
	#get_uptime
	###########
	@_dbg
	def get_uptime(self):
		"returns the time since the server has started"
		_now=datetime.datetime.now()
		return _now-self._daemonstarttime
	#############
	#is_debugging
	#############
	@_dbg
	def is_debugging(self):
		"returns True if gpgmailencrypt is in debuggin mode"
		return self._DEBUG
	################################
	#set_default_preferredencryption
	################################
	@_dbg
	def set_default_preferredencryption(self,mode):
		"set the default preferred encryption. Valid values are SMIME,PGPMIME,PGPINLINE"
		if isinstance(mode,str):
			m=mode.upper()
			if m in ["SMIME","PGPMIME","PGPINLINE"]:
				self._PREFERRED_ENCRYPTION=mode.upper()
	#########
	#set_smtp
	#########
	@_dbg
	def set_smtp(self,host,port,auth=False,user="",password=""):
		"sets the smtp setting for sending emails (don't mix it up with the daemon settings where the server listens)"
		self._HOST=host
		self._PORT=port
		self._AUTHENTICATE=auth
		self._SMTP_USER=user
		self._SMTP_PASSWORD=password
	###########
	#set_daemon
	###########
	@_dbg
	def set_daemon(self,host,port,smtps=False,auth=False,sslkeyfile=None,sslcertfile=None,passwordfile=None):
		"sets the smtpd daemon settings"
		self._SERVERHOST=host
		self._SERVERPORT=port
		self._SMTPD_USE_SMTPS=smtps
		self._SMTPD_USE_AUTH=auth
		if sslkeyfile:
			self._SMTPD_SSL_KEYFILE=sslkeyfile
		if sslcertfile:
			self._SMTPD_SSL_CERTFILE=sslcertfile
		if passwordfile:
			self._SMTPD_PASSWORDFILE=passwordfile
	################################
	#get_default_preferredencryption
	################################
	def get_default_preferredencryption(self):
		"returns the default preferred encryption method"
		return self._PREFERRED_ENCRYPTION
	###################
	#check_gpgrecipient
	###################
	@_dbg
	def check_gpgrecipient(self,gaddr):
		"returns True and the effective key-emailaddress if emails to address 'gaddr' can be GPG encrcrypted"
		self.debug("check_gpgrecipient: start '%s'"%gaddr)
		gaddr=emailutils.parseaddr(gaddr)[1]
		addr=gaddr.split('@')
		domain=''
		if len(addr)==2:
			domain = addr[1]
		found =False
		gpg = _GPG( self,self._GPGKEYHOME)
		try:
			gpg_to_addr=self._addressmap[gaddr]
		except:
			self.debug("_addressmap to_addr not found")
			gpg_to_addr=gaddr
		if gpg.has_public_key(gpg_to_addr):
			if (len(self._DOMAINS)>0 and domain in self._DOMAINS.split(',')) or len(self._DOMAINS)==0:
				found=True
				self.debug("check_gpgrecipient: after in_key")
			else:
				self.debug("gpg key exists, but '%s' is not in _DOMAINS [%s]"%(domain,self._DOMAINS))
		return found,gpg_to_addr
	#####################
	#check_smimerecipient
	#####################
	@_dbg
	def check_smimerecipient(self,saddr):
		"returns True and the effective key-emailaddress if emails to address 'saddr' can be SMIME encrcrypted"
		self.debug("check_smimerecipient: start '%s'"%saddr)
		saddr=emailutils.parseaddr(saddr)[1]
		addr=saddr.split('@')
		domain=''
		if len(addr)==2:
			domain = addr[1]
		found =False
		smime = _SMIME(self,self._SMIMEKEYHOME)
		try:
			smime_to_addr=self._addressmap[saddr]
		except:
			self.debug("smime _addressmap to_addr not found")
			smime_to_addr=saddr
		self.debug("check_smimerecipient '%s'"%smime_to_addr)
		if smime.has_public_key(smime_to_addr):
			found=True
			self.debug("check_smimerecipient FOUND") 
			if (len(self._DOMAINS)>0 and domain in self._DOMAINS.split(',')) or len(self._DOMAINS)==0:
				self.debug("check_smimerecipient: after in_key")
			else:
				self.debug("smime key exists, but '%s' is not in _DOMAINS [%s]"%(domain,self._DOMAINS))
				found=False
		return found, smime_to_addr
	#####################
	#check_encryptsubject
	#####################
	@_dbg
	def check_encryptsubject(self,mailtext):
		mail=email.message_from_string(mailtext)
		subject=self._decode_header(mail["Subject"])
		self.debug("subject: %s"%mail["Subject"])
		find=re.search("^#encrypt ",subject,re.I)
		if find:
			return True
		else:
			return False
	#############################
	#is_encrypted function family
	#############################
	@_dbg
	def _pgpinlineencrypted(self,msg):
		if msg ==None:
			return False
		if type(msg)==bytes:
			return False
		if isinstance(msg,email.message.Message):
			msg=msg.as_string()
		if self.is_pgpmimeencrypted(msg):
			return False
		if "\n-----BEGIN PGP MESSAGE-----" in msg and "\n-----END PGP MESSAGE-----" in msg:
			return True
		else:
			return False
	@_dbg
	def is_pgpinlineencrypted(self,msg):
		"returns whether or not the email is already PGPINLINE encrypted"
		if self._pgpinlineencrypted(msg):
			return True
		if type(msg)==bytes:
			return False
		if isinstance(msg,str):
			msg=email.message_from_string(msg)
		for m in msg.walk():
			charset=m.get_param("charset",header="Content-Type")
			cte=m["Content-Transfer-Encoding"]
			if isinstance( m.get_payload(), str):
				if self._pgpinlineencrypted(_decodetxt(m.get_payload(),cte,charset)):
					return True
		return False
	@_dbg
	def is_pgpmimeencrypted(self,msg):
		"returns whether or not the email is already PGPMIME encrypted"
		if type(msg)==bytes:
			return False
		m=msg
		if isinstance(msg,email.message.Message):
			m=msg.as_string()
		find=re.search("^Content-Type: application/pgp-encrypted",m,re.I|re.MULTILINE)
		if find:
			return True
		else:
			return False
	@_dbg
	def is_smimeencrypted(self,msg):
		"returns whether or not the email is already SMIME encrypted"
		if type(msg)==bytes:
			return False
		m=msg
		if isinstance(msg,email.message.Message):
			m=msg.as_string()
		find=re.search("^Content-Type: application/pkcs7-mime",m,re.I|re.MULTILINE)
		if find:
			return True
		else:
			return False
	@_dbg
	def is_pdfencrypted(self,msg):
		"returns whether or not the email is already PDF encrypted"
		if type(msg)==bytes:
			return False
		m=msg
		if isinstance(msg,email.message.Message):
			m=msg.as_string()
		find=re.search("^%s:"%self._pdfencryptheader,m,re.I|re.MULTILINE)
		if find:
			return True
		else:
			return False
	@_dbg
	def is_encrypted(self,msg):
		"returns whether or not the email is already encrypted"
		if self.is_pgpmimeencrypted(msg) or self.is_pgpinlineencrypted(msg) or self.is_smimeencrypted(msg) or self.is_pdfencrypted(msg):
			return True
		else:
			return False
	############
	#_split_html
	############
	@_dbg
	def _split_html(self,html):
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
				body=_decode_html(self,body[0:res.start()])
		else:		
			body=_decode_html(self,_r)
		return result,header,body,footer
	#################
	#_encrypt_payload
	#################
	@_dbg
	def _encrypt_payload( self,payload,gpguser,counter=0 ):
		htmlheader=""
		htmlbody=""
		htmlfooter=""
		charset=payload.get_param("charset",header="Content-Type")
		is_text=payload.get_content_maintype()=="text"
		cte=payload["Content-Transfer-Encoding"]
		if not cte:
			cte="8bit"
		self.debug("_encrypt_payload: charset %s"%charset)
		if charset==None or charset.upper()=="ASCII" or len(charset)==0:
			charset="UTF-8"
		gpg = _GPG(self, self._GPGKEYHOME, gpguser,counter)
		raw_payload = payload.get_payload(decode=not is_text)
		if is_text:
			raw_payload=_decodetxt(raw_payload,cte,charset)	
			payload.del_param("charset")	
			payload.set_param("charset",charset)
		contenttype=payload.get_content_type()	
		self.debug("nach payload.get_content_typ")	
		self.debug("Content-Type:'%s'"%contenttype)
		fp=self._new_tempfile()
		self.debug("_encrypt_payload _new_tempfile %s"%fp.name)
		filename = payload.get_filename()
		tencoding="7bit"
		if contenttype=="text/html":
			res,htmlheader,htmlbody,htmlfooter=self._split_html(raw_payload)
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
		if self.is_encrypted(raw_payload):
			if self._ADDHEADER:
				if not self._encryptheader in payload:
					payload[self._encryptheader] = 'Mail was already encrypted'
				self.debug("Mail was already encrypted")
			self._del_tempfile(fp.name)
			if len(self._OUTFILE) >0:
				return None	
			return payload
		contentmaintype=payload.get_content_maintype() 
		if isAttachment or (isInline and contentmaintype not in ("text") ):
			self.debug("ENCRYPT PAYLOAD ATTACHMENT")
			addPGPextension=True
			if filename==None:
				count=""
				if counter>0:
					count="%i"%counter
				try:
					f=self._LOCALEDB[self._LOCALE][1]
				except:
					self.log("wrong locale '%s'"%self._LOCALE,"w")
					f=self._LOCALEDB["EN"][1]
				filename=('%s%s.'%(f,count))+guess_fileextension(contenttype)
			f,e=os.path.splitext(filename)
			addPGPextension=(e.lower()!=".pgp")
			if filename and addPGPextension:
				pgpFilename = filename + ".pgp"
			else:
				pgpFilename=filename
				
			self.debug("Filename:'%s'"%filename)
			pgpFilenamecD,pgpFilenamecT=_encodefilename(pgpFilename)
			
			isBinaryattachment=(contentmaintype!="text")
			if addPGPextension:
				self.debug("addPGPextension gpg.encrypt_file")
				result,pl=gpg.encrypt_file(binary=isBinaryattachment)
			else:
				result=False
			if result==True:
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
			if result==True:
				if contenttype=="text/html":
					pl=htmlheader+"\n<br>\n"+re.sub('\n',"<br>\n",pl)+"<br>\n"+htmlfooter
				if "Content-Transfer-Encoding" in payload:
					del payload["Content-Transfer-Encoding"]
				payload["Content-Transfer-Encoding"]=tencoding
				payload.set_payload(pl)
			else:
				self.log("Error during encryption: payload will be unencrypted!","m")	
		self._del_tempfile(fp.name)
		return payload
	###################
	#encrypt_pgpinline
	###################
	@_dbg
	def encrypt_pgpinline(self,mail,gpguser,from_addr,to_addr):
		"""
		returns the string 'message' as an PGP/INLINE encrypted mail as an email.Message object
		returns None if encryption was not possible
		"""
		message=email.message_from_string(mail)
		counter=0
		attach_list=list()
		appointment="appointment"
		try:
			appointment=self._LOCALEDB[self._LOCALE][0]
		except:
			pass
		cal_fname="%s.ics.pgp"%appointment
		if isinstance(message,list):
			msg=message
		else:
			msg=message.walk()
			self.debug("encrypt_pgpinline vor get_content_type")
			contenttype=message.get_content_type()	
			self.debug("encrypt_pgpinline nach get_content_type")
			self.debug("CONTENTTYPE %s"%contenttype)
			if isinstance( message.get_payload(),str ):
				self.debug("encrypt_pgpinlie: type( message.get_payload() ) == str")
				charset=message.get_param("charset",header="Content-Type")
				if charset==None or charset.upper()=="ASCII":
					message.set_param("charset",charset)		
				pl=self._encrypt_payload( message ,gpguser)
				if contenttype=="text/calendar":
					CAL=MIMEText(pl.get_payload(decode=True),_subtype="calendar",_charset="UTF-8")
					CAL.add_header('Content-Disposition', 'attachment', filename=cal_fname)
					CAL.set_param( 'name', cal_fname)
					pl.set_payload(None)
					pl.set_type("multipart/mixed")
					pl.attach(CAL)
				self.debug("encrypt_pgpinline: type( message.get_payload() ) == str END")
				return pl
		for payload in msg:
			content=payload.get_content_maintype()
			if (content in ("application","image","audio","video" )) \
			and payload.get_param( 'inline', None, 'Content-Disposition' ) is None:
				payload.add_header('Content-Disposition', 'attachment;"')
			if payload.get_content_maintype() == 'multipart':
				continue
			if  isinstance( payload.get_payload() , list ):
				continue
			else:
				self.debug("for in schleife for _encrypt payload %s" %type(payload))
				res=self._encrypt_payload( payload,gpguser,counter )
				if res and payload.get_content_type()=="text/calendar" and payload.get_param( 'attachment', None, 'Content-Disposition' ) is  None:
					CAL=MIMEText(res.get_payload(decode=True),_subtype="calendar",_charset="UTF-8")
					CAL.add_header('Content-Disposition', 'attachment', filename=cal_fname)
					CAL.set_param( 'name', cal_fname)
					payload.set_payload("")
					payload.set_type("text/plain")
					attach_list.append(CAL)
				if (content in ("application","image","audio","video" )):
					counter+=1
				self.debug("for schleife next")
			self.debug("for schleife Ende")			
		for a in attach_list:
			message.attach(a)
		return message
	#################
	#encrypt_pgpmime
	#################
	@_dbg
	def encrypt_pgpmime(self,message,gpguser,from_addr,to_addr):
		"""
		returns the string 'message' as an PGP/MIME encrypted mail as an email.Message object
		returns None if encryption was not possible
		"""
		raw_message=email.message_from_string(message)
		splitmsg=re.split("\n\n",message,1)
		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",message,1)
		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part (mailsize=%i)"%len(message))
			return None
		header,body=splitmsg 
		header+="\n\n"
		try:
			newmsg=email.message_from_string( header)
		except:
			self.log("creating new message failed","w")
			self.log_traceback()
			return None
		contenttype="text/plain"
		contenttransferencoding=None
		contentboundary=None
		c=newmsg.get("Content-Type")
		if c==None:
			self.debug("Content-Type not set, set default 'text/plain'.")
			newmsg.set_type("text/plain")
		boundary=self._make_boundary(message)
		try:
			newmsg.set_boundary(boundary)
		except:
			self.log("Error setting boundary")
			self.log_traceback()
		res= re.search("boundary=.*\n",message,re.IGNORECASE)
		if res:
			_b=message[res.start():res.end()]
			res2=re.search("\".*\"", _b)
			if res2:
				contentboundary=_b[(res2.start()+1):(res2.end()-1)]
		try:
			contenttype=newmsg.get_content_type()
			self.debug("Content-Type:'%s'"%str(contenttype))
			contenttransferencoding=newmsg['Content-Transfer-Encoding']
		except:
			self.log("contenttype and/or transerfencoding could not be found")
			self.og_traceback()
		newmsg.set_type("multipart/encrypted")
		newmsg.set_param("protocol","application/pgp-encrypted")
		newmsg.preamble='This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)'
		if 'Content-Transfer-Encoding' in newmsg:
			del newmsg['Content-Transfer-Encoding']
		gpg = _GPG( self,self._GPGKEYHOME, gpguser)
		fp=self._new_tempfile()
		self.debug("encrypt_mime new tempfile %s"%fp.name)
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
		if isinstance (rawpayload, str):
			self.debug("Payload==String len=%i"%len(rawpayload))
			if contenttype ==None:
				contenttype="multipart/mixed"
			protocol=""
			charset=""
			if contenttype=="multipart/signed":
				protocol=" protocol=\"application/pgp-signature\";\n"
			_ch=self._find_charset(header)
			self.debug("Charset:%s"%str(_ch))
			bdy=""
			if contentboundary!=None:
				bdy='boundary="%s"\n'%contentboundary
			if ("text/" in contenttype) and _ch!= None and len(_ch)>0 :
				charset="charset=\"%s\""%_ch
				self.debug("content-type: '%s' charset: '%s'"%(contenttype,charset))
			msgheader='Content-Type: %(ctyp)s; %(charset)s\n%(protocol)s%(bdy)s'\
			%{"bdy":bdy,"ctyp":contenttype,"protocol":protocol,"charset":charset}
			self.debug("msgheader:    '%s'"%str(msgheader))
			self.debug("new boundary: '%s'"%str(boundary))
			if contenttransferencoding !=None:
				msgheader+=("Content-Transfer-Encoding: %s\n" %contenttransferencoding)
			body=msgheader+"\n"+body	
		else:
			self.debug("Payload==Msg")
			for p in rawpayload:
				bodymsg.attach(p)
			body=bodymsg.as_string()	
		fp.write(body.encode("UTF-8",_unicodeerror))
		fp.close()
		gpg.set_filename( fp.name )
		attachment=_GPGEncryptedAttachment()
		if self.is_encrypted(message):
			self.del_tempfile(fp.name)
			return None
		result,pl=gpg.encrypt_file(binary=False) 
		if result==True:
			attachment.set_payload(pl)
		else:
			self.log("Error during encryption pgpmime: payload will be unencrypted!","m")	
		newmsg.set_payload(attachment)
		newmsg.set_boundary(boundary)
		attachment.set_boundary(contentboundary)
		attachment.set_masterboundary(boundary)
		self._del_tempfile(fp.name)
		return newmsg
	##############################
	#get_preferredencryptionmethod
	##############################	
	@_dbg
	def get_preferredencryptionmethod(self,user):
		"returns the preferenced encryption method for user 'user'"
		self.debug("get_preferredencryptionmethod :'%s'"%user)
		method=self._PREFERRED_ENCRYPTION
		_m=""
		user=emailutils.parseaddr(user)[1]
		_u=user
		try:
			_u=self._addressmap[user]
		except:
			pass
		try:
			self.debug("get_preferred encryptionmap %s"%_u)
			_m=self._encryptionmap[_u][0].upper()
		except:
			pass
		if len(_m)==0:
			addr=user.split('@')
			if len(addr)==2:
				try:
					_m=self._encryptionmap["*@%s"%addr[1]][0].upper()
					self.debug("preferencedencryptionmethod for *@%s=%s"%(addr[1],_m))
				except:
					self.debug("get_preferredencryptionmethod User '%s/%s' not found"%(user,_u))
					return method
		if _m in ("PGPMIME","PGPINLINE","SMIME","PDF","NONE"):
			self.debug("get_preferredencryptionmethod User %s (=> %s) :'%s'"%(user,_u,_m))
			return _m
		else:
			self.debug("get_preferredencryptionmethod: Method '%s' for user '%s' unknown" % (_m,_u))
			return method
	##################
	#encrypt_gpg_mail 
	##################
	@_dbg
	def encrypt_gpg_mail(self,mailtext,use_pgpmime, gpguser,from_addr,to_addr):
		"""
		returns the string 'message' as an PGP encrypted mail (either PGP/INLINE or PGP/MIME depending on the configuration) as an email.Message object
		returns None if encryption was not possible
		"""
		raw_message=email.message_from_string(mailtext)
		msg_id=""
		if "Message-Id" in raw_message:
			msg_id="Id:%s "%raw_message["Message-Id"]
		if "Subject"  in raw_message and len(self._SPAMSUBJECT.strip())>0 and self._SPAMSUBJECT in raw_message["Subject"]:
			self.debug("message is SPAM, don't encrypt")
			return None
		if self.is_encrypted( raw_message ):
			self.debug("encrypt_gpg_mail, is already encrypted")
			return None
		self.log("Encrypting email to: %s" % to_addr )
		if use_pgpmime:
			mail = self.encrypt_pgpmime( mailtext,gpguser,from_addr,to_addr )
		else:
			#PGP Inline
			mail = self.encrypt_pgpinline( mailtext,gpguser,from_addr,to_addr )
		if mail==None:
			return None
		self._count_encryptedmails+=1
		if use_pgpmime:
			self._count_pgpmimemails+=1
		else:
			self._count_pgpinlinemails+=1

		return mail
	#####################
	# encrypt_smime_mail 
	#####################
	@_dbg
	def encrypt_smime_mail(self,mailtext,smimeuser,from_addr,to_addr):
		"""
		returns the string 'message' as an S/MIME encrypted mail as an email.Message object
		returns None if encryption was not possible
		"""
		raw_message=email.message_from_string(mailtext)
		contenttype="text/plain"
		contenttransferencoding=None
		contentboundary=None
		if self.is_encrypted(raw_message):
			self.debug("encrypt_smime_mail:mail is already encrypted")
			self.debug("Mail was already encrypted")
			return None
		splitmsg=re.split("\n\n",mailtext,1)
		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",mailtext,1)
		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part (mailsize=%i)"%len(mailtext))
			return None
		header,body=splitmsg 
		header+="\n\n"
		try:
			newmsg=email.message_from_string( header)
		except:
			self.log("creating new message failed","w")
			self.log_traceback()
			return None
		m_id=""
		if "Message-Id" in raw_message:
			m_id="Id:%s "%raw_message["Message-Id"]
		self.log("Encrypting email %s to: %s" % (m_id, to_addr) )
	
		res= re.search("boundary=.*\n",mailtext,re.IGNORECASE)
		if res:
			_b=mailtext[res.start():res.end()]
			res2=re.search("\".*\"", _b)
			if res2:
				contentboundary=_b[(res2.start()+1):(res2.end()-1)]
		try:
			contenttype=newmsg.get_content_type()
			self.debug("Content-Type:'%s'"%str(contenttype))
			contenttransferencoding=newmsg['Content-Transfer-Encoding']
		except:
			self.log("contenttype and/or transerfencoding could not be found")
			self.log_traceback()
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
		smime = _SMIME( self,self._SMIMEKEYHOME)
		smime.set_recipient(smimeuser)
		fp=self._new_tempfile()
		self.debug("encrypt_smime_mail _new_tempfile %s"%fp.name)
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
		if isinstance(rawpayload,str):
			self.debug("Payload==String len=%i"%len(rawpayload))
			if contenttype ==None:
				contenttype="multipart/mixed"
			protocol=""
			charset=""
			if contenttype=="multipart/signed":
				protocol=" protocol=\"application/pgp-signature\";\n"
			_ch=self._find_charset(header)
			self.debug("Charset:%s"%str(_ch))
			bdy=""
			if contentboundary!=None:
				bdy='boundary="%s"\n'%contentboundary
			if ("text/" in contenttype) and _ch!= None and len(_ch)>0 :
				charset="charset=\"%s\""%_ch
				self.debug("content-type: '%s' charset: '%s'"%(contenttype,charset))
			msgheader='Content-Type: %(ctyp)s; %(charset)s\n%(protocol)s%(bdy)s'\
			%{"bdy":bdy,"ctyp":contenttype,"protocol":protocol,"charset":charset}
			self.debug("msgheader:    '%s'"%str(msgheader))
			if contenttransferencoding !=None:
				msgheader+=("Content-Transfer-Encoding: %s\n" %contenttransferencoding)
			body=msgheader+"\n"+body	
		else:
			self.debug("Payload==Msg")
			for p in rawpayload:
				bodymsg.attach(p)
			body=bodymsg.as_string()	
		fp.write(body.encode("UTF-8",_unicodeerror))
		fp.close()
		smime.set_filename(fp.name)
		result,pl=smime.encrypt_file()
		if result==True:
			self.debug("encrypt_smime_mail: send encrypted mail")
			self._count_encryptedmails+=1
			self._count_smimemails+=1
			if self._ADDHEADER:
				if self._encryptheader in newmsg:
					del newmsg[self._encryptheader]
				newmsg[self._encryptheader] = self._encryptgpgcomment
			newmsg.set_payload( pl )
		else:
			self.debug("encrypt_smime_mail: error encrypting mail, send unencrypted")
			m=None
			newmsg=None
		self._del_tempfile(fp.name)
		return newmsg
	###############
	#_decode_header
	###############
	@_dbg
	def _decode_header(self,header):
		if not header:
			return None
		h=email.header.decode_header(header)
		result=""
		for m in h:
			try:
				if m[1]==None:
					if isinstance(m[0],str):
						result+=m[0]+" "
					else:
						result+=m[0].decode("UTF-8")+" "
				else:
					result+=m[0].decode(m[1])+" "
			except:
				pass
		return result
	##################
	# encrypt_pdf_mail 
	##################
	@_dbg
	def encrypt_pdf_mail(self,message,pdfuser,from_addr,to_addr):
		splitmsg=re.split("\n\n",message,1)
		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",message,1)
		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part (mailsize=%i)"%len(message))
			return None
		header,body=splitmsg 
		header+="\n\n"
		try:
			newmsg=MIMEMultipart()
			m=email.message_from_string(header)
			for k in m.keys():
				newmsg[k]=m[k]
		except:
			self.log("creating new message failed","w")
			self.log_traceback()
			return None
		pdf=_PDF(self)
		fp=self._new_tempfile()
		fp.write(message.encode("UTF-8",_unicodeerror))
		fp.close()
		pdf.set_filename(fp.name)
		pw=self.get_pdfpassword(pdfuser)
		self.debug("Password '%s'"%pw)
		result,pdffile=pdf.create_pdffile(pw)
		if result==True:
			domain=''
			addr= emailutils.parseaddr(from_addr)[1].split('@')
			if len(addr)==2:
				domain = addr[1]
			if domain in self._PDFDOMAINS:
				msgtxt=self._load_mailmaster("01-pdfpassword","<table><tr><td>Subject:</td><td>%SUBJECT%</td></tr>"
					"<tr><td>From:</td><td>%FROM%</td></tr><tr><td>To:</td><td>%TO%</td></tr><tr><td>Date:</td><td>%DATE%</td></tr>"
					"<tr><td>Password:</td><td>%PASSWORD%</td></tr></table>")
				msgtxt=replace_variables(msgtxt,{"FROM":html.escape(from_addr),
								"TO":html.escape(self._decode_header(newmsg["To"])),
								"DATE":newmsg["Date"],
								"PASSWORD":html.escape(pw),
								"SUBJECT":html.escape(self._decode_header(newmsg["Subject"]))})
				msg=MIMEMultipart()
				msg.set_type("multipart/alternative")
				res,htmlheader,htmlbody,htmlfooter=self._split_html(msgtxt)
				htmlmsg=MIMEText(msgtxt,"html")
				plainmsg=MIMEText(htmlbody)
				msg.attach(plainmsg)
				msg.attach(htmlmsg)
				msg['Subject'] = 'Password for: %s' %self._decode_header(newmsg["To"])
				msg['To'] = from_addr
				msg['From'] = self._SYSTEMMAILFROM
				self.encrypt_mails(msg.as_string(),from_addr)
			msgtxt=self._load_mailmaster("02-pdfmail","Content of this e-mail is stored in an pdf attachment.")
			msg=MIMEMultipart()
			msg.set_type("multipart/alternative")
			res,htmlheader,htmlbody,htmlfooter=self._split_html(msgtxt)
			htmlmsg=MIMEText(msgtxt,"html")
			plainmsg=MIMEText(htmlbody)
			msg.attach(plainmsg)
			msg.attach(htmlmsg)
			newmsg.attach(msg)
			msg = MIMEBase("application","pdf")
			msg.set_payload(pdffile)
			try:
				f=self._LOCALEDB[self._LOCALE][2]
			except:
				self.log("wrong locale '%s'"%self._LOCALE,"w")
				f=self._LOCALEDB["EN"][2]
			msg.add_header('Content-Disposition', 'attachment', filename="%s.pdf"%f)
			encoders.encode_base64(msg)
			newmsg.attach(msg)
			self._count_pdfmails+=1
			self._count_encryptedmails+=1
		else:
			return None
		oldmsg=email.message_from_string(message)
		attachments=0
		tempdir = tempfile.mkdtemp()
		Zip=_ZIP(self)
		try:
			Zip.set_zipcipher(self._encryptionmap[pdfuser][1])
		except:
			try:
				_addr=emailutils.parseaddr(pdfuser)[1].split('@')
				if len(_addr)==2:
					domain = _addr[1]
					Zip.set_zipcipher(self._encryptionmap["*@%s"%domain][1])
			except:
				pass
		for m in oldmsg.walk():
			if m.get_param( 'attachment', None, 'Content-Disposition' ) is not None:
				contenttype=m.get_content_type()
				filename = m.get_filename()
				self.debug("Content-Type=%s"%contenttype)
				if  isinstance( m.get_payload() , list ):
					for part in m.get_payload():
						if isinstance(part,email.message.Message):
							payload=part.as_bytes()
							break
						else:
							continue
				else:
					payload=m.get_payload(decode=True)
				self.debug("Open write: %s/%s"%(tempdir,filename))
				fp=open("%s/%s"%(tempdir,filename),"wb")
				try:
					fp.write(payload)
				except:
					self.log("File '%s' could not be written"%filename)
					self.log_traceback()
				fp.close()
				attachments+=1
		if attachments>0:
			if self._PDFSECUREZIPCONTAINER==True:
				try:
					content=self._LOCALEDB[self._LOCALE][2]
				except:
					self.log("wrong locale '%s'"%self._LOCALE,"w")
					content=self._LOCALEDB["EN"][2]
				content="%s.zip"%content
			else:
				content=None
			result,zipfile=Zip.create_zipfile(tempdir,pw,containerfile=content)
			if result==True:
				msg= MIMEBase("application", "zip")
				msg.set_payload(zipfile)
				try:
					f=self._LOCALEDB[self._LOCALE][3]
				except:
					self.log("wrong locale '%s'"%self._LOCALE,"w")
					f=self._LOCALEDB["EN"][3]
				filenamecD,filenamecT=_encodefilename("%s.zip"%f)
				msg.add_header('Content-Disposition', 'attachment; filename*="%s"' % filenamecD)
				msg.set_param( 'name', filenamecT )
				encoders.encode_base64(msg)
				newmsg.attach(msg)
		self._del_tempfile(fp.name)
		try:
			shutil.rmtree(tempdir)
			pass
		except:
			self.log("Couldn't delete tempdir '%s'"%tempdir)
			self.log_traceback()
		if not self._pdfencryptheader in newmsg:
			newmsg.add_header(self._pdfencryptheader,self._encryptgpgcomment)
		return newmsg
	####################
	#encrypt_single_mail
	####################	
	@_dbg
	def encrypt_single_mail(self,queue_id,mailtext,from_addr,to_addr):
		_pgpmime=False
		_prefer_gpg=True
		_prefer_pdf=False
		_prefer_smime=False
		mresult=None
		_encrypt_subject=self.check_encryptsubject(mailtext)
		try:
			to_pdf=self._addressmap[to_addr]
		except:
			self.debug("preferpdf _addressmap to_addr not found")
			to_pdf=to_addr
		if _encrypt_subject:
			m=email.message_from_string(mailtext)
			self.debug("remove #encrypt from subject")
			subject=self._decode_header(m["Subject"])[9:]
			del m["Subject"]
			m["Subject"]=subject
			mailtext=m.as_string()
			
		g_r,to_gpg=self.check_gpgrecipient(to_addr)
		s_r,to_smime=self.check_smimerecipient(to_addr)
		method=self.get_preferredencryptionmethod(to_addr)
		self.debug("GPG encrypt possible %i / %s"%(g_r,to_gpg))
		self.debug("SMIME encrypt possible %i / %s"%(s_r,to_smime))
		self.debug("Prefer PDF %i / %s"%(_prefer_pdf,to_pdf))
		self._count_totalmails+=1
		domain=''
		_addr=emailutils.parseaddr(from_addr)[1].split('@')
		if len(_addr)==2:
			domain = _addr[1]

		if method=="PGPMIME":
			_prefer_gpg=True
			_prefer_smime=False
			_pgpmime=True
		elif method=="PGPINLINE":
			_prefer_gpg=True
			_prefer_smime=False
			_pgpmime=False
		if method=="SMIME":
			_prefer_gpg=False
			_prefer_smime=True
		if method=="PDF" or self._ALWAYSENCRYPT or _prefer_pdf:
			if domain in self._PDFDOMAINS:
				_prefer_pdf=True
		if method=="NONE":
			g_r=False
			s_r=False
		if not s_r and not g_r and not _prefer_pdf and not _encrypt_subject:
			m="Email not encrypted, public key for '%s' not found"%to_addr
			self.log(m)
			if self._ZIPATTACHMENTS:
				mailtext=self.zip_attachments(mailtext)
			self._send_rawmsg(queue_id,mailtext,m,from_addr,to_addr)
			return
		if self.is_encrypted(mailtext):
			m="Email already encrypted"
			self.debug(m)
			self._count_alreadyencryptedmails+=1
			self._send_rawmsg(queue_id,mailtext,m,from_addr,to_addr)
			return

		if (not _prefer_pdf and not _encrypt_subject) or (_encrypt_subject and (g_r or s_r)): 
			if self._ZIPATTACHMENTS:
				mailtext=self.zip_attachments(mailtext)
		if _prefer_gpg:
			self.debug("PREFER GPG")
			if g_r:
				mresult=self.encrypt_gpg_mail(mailtext,_pgpmime,to_gpg,from_addr,to_addr)
			elif s_r:
				mresult=self.encrypt_smime_mail(mailtext,to_smime,from_addr,to_addr)
		elif _prefer_smime :
			self.debug("PREFER S/MIME")
			if s_r:
				mresult=self.encrypt_smime_mail(mailtext,to_smime,from_addr,to_addr)
			elif g_r:
				mresult=self.encrypt_gpg_mail(mailtext,_pgpmime,to_gpg,from_addr,to_addr)
		if not mresult and (_encrypt_subject or _prefer_pdf):
			if domain in self._PDFDOMAINS:
				mresult=self.encrypt_pdf_mail(mailtext,to_pdf,from_addr,to_addr)			
		if mresult:
			self.debug("send encrypted mail")
			self._send_msg(queue_id,mresult,from_addr,to_addr )
		else:
			m="Email could not be encrypted"
			self.debug(m)
			self._send_rawmsg(queue_id,mailtext,m,from_addr,to_addr)
	###############
	# encrypt_mails 
	###############
	@_dbg
	def encrypt_mails(self,mailtext,receiver):
		"""
		Main function of this library: 
			mailtext is the mail as a string
			receiver is a list of receivers
		The emails will be encrypted if possible and sent as defined  in /etc/gpgmailencrypt.conf
		example:
		encrypt_mails(myemailtext,['agentj@mib','agentk@mib'])
		"""
		if isinstance(receiver,str):
			receiver=[receiver]
		try:
			if self._debug_keepmail(mailtext): #DEBUG
				self._store_temporaryfile(mailtext)
			if self._PREFERRED_ENCRYPTION=="PGPMIME":
				_pgpmime=True
			else:
				_pgpmime=False
			if self._SMIMEAUTOMATICEXTRACTKEYS:
				self.debug("_SMIMEAUTOMATICEXTRACTKEYS")
				f=self._new_tempfile()
				f.write(mailtext.encode("UTF-8",_unicodeerror))
				f.close()
				s=_SMIME(self,self._SMIMEKEYHOME)
				s.extract_publickey_from_mail(f.name,self._SMIMEKEYEXTRACTDIR)
				self._del_tempfile(f.name)
			for to_addr in receiver:
				self.debug("encrypt_mail for user '%s'"%to_addr)
				if self._RUNMODE==self.m_daemon:
					fname=self._store_temporaryfile(mailtext,spooldir=True)
				try:
					raw_message = email.message_from_string( mailtext )
				except:
					self._store_temporaryfile(mailtext,add_deferred=True,fromaddr="UNKNOWN",toaddr=to_addr)
					self.log_traceback()
					return
				from_addr = raw_message['From']
				if self._RUNMODE==self.m_daemon:
					self._email_queue[self._queue_id]=[fname,from_addr,to_addr,time.time()]
				else:
					self._queue_id=-1
				mailid=self._queue_id
				if self._RUNMODE==self.m_daemon:
					self._queue_id+=1
				self.encrypt_single_mail(mailid,mailtext,from_addr,to_addr)
		except:
			self.log_traceback()
	#######################################
	#END definition of encryption functions
	#######################################
	###########
	#scriptmode
	###########
	@_dbg
	def scriptmode(self,receiver):
		"run gpgmailencrypt a script"
		try:
			#read message
			if len(self._INFILE)>0:
				try:
					f=open(self._INFILE,"rb")
					m=email.message_from_binary_file(f)
					raw=m.as_string()
					f.close()
				except:
					self.log("Could not open Inputfile '%s'"%self._INFILE,"e")
					self.log_traceback()
					exit(2)
			else:
				import io
				sys.stdin = io.TextIOWrapper(sys.stdin.buffer,encoding='UTF-8',errors=_unicodeerror)
				raw = sys.stdin.read()
			#do the magic
			self.encrypt_mails(raw,receiver)
		except SystemExit as m:
			self.debug("Exitcode:'%s'"%m)
			exit(int(m.code))
		except:
			self.log("Bug:Exception occured!","e")
			self.log_traceback()
			exit(4)	
		else:
			self.debug("Program exits without errors")
	###########
	#daemonmode
	###########
	@_dbg
	def daemonmode(self):
		"starts the smtpd daemon"
		#####################
		#_deferredlisthandler
		#####################
		def _deferredlisthandler():
			self.check_deferred_list()
			self.store_deferred_list()
			if self._count_alarms>1:
				self._count_alarms-=1
			else:
				try:
					self._count_alarms=24/self._STATISTICS_PER_DAY
				except:
					self._count_alarms=0
				if self._count_alarms>0:
					self._log_statistics() #log statistics every 24 hours
			self.del_old_pdfpasswords(self._PDFPASSWORDLIFETIME)
		##################
		self._RUNMODE=self.m_daemon
		self._daemonstarttime=datetime.datetime.now()
		alarm=_mytimer()
		alarm.start(0,3600,alarmfunction=_deferredlisthandler)
		try:
			self._count_alarms=24//self._STATISTICS_PER_DAY
		except:
			self._count_alarms=0
		signal.signal(signal.SIGTERM, _sigtermhandler)
		self.load_deferred_list()
		smtpd.__version__="gpgmailencrypt smtp server %s"%VERSION
		_deferredlisthandler()
		self.log("gpgmailencrypt %s starts as daemon on %s:%s"%(VERSION,self._SERVERHOST,self._SERVERPORT) )
		if self._SMTPD_USE_AUTH:
			self._read_smtpdpasswordfile(self._SMTPD_PASSWORDFILE)
		try:
			server = _gpgmailencryptserver(	self,
							(self._SERVERHOST, self._SERVERPORT),
							use_auth=self._SMTPD_USE_AUTH,
							authenticate_function=file_auth,
							write_smtpdpasswordfile=self.write_smtpdpasswordfile,
							read_smtpdpasswordfile=self._read_smtpdpasswordfile,
							use_smtps=self._SMTPD_USE_SMTPS,
							sslkeyfile=self._SMTPD_SSL_KEYFILE,
							sslcertfile=self._SMTPD_SSL_CERTFILE)
		except:
			self.log("Couldn't start mail server")
			self.log_traceback()
			exit(1)
		try:
			asyncore.loop()
		except SystemExit as m:
			exit(0)
		except (KeyboardInterrupt,EOFError):
			self.log("Keyboard Exit")
		except:
			self.log("Bug:Exception occured!","e")
			self.log_traceback()
		alarm.stop()
	##############
	#adm_get_users
	##############
	@_dbg
	def adm_get_users(self):
		"returns a list of all users and whether or not the user is a admin"
		users=[]
		for user in self._smtpd_passwords:
			users.append({"user":user,"admin":self.is_admin(user)})
		return users
	#############
	#adm_set_user
	#############
	@_dbg
	def adm_set_user(self,user,password):
		"adds a user, if the user already exists it changes the password"
		try:
			self._smtpd_passwords[user]=_get_hash(password)
			return True
		except:
			self.log("User could not be added","e")
			self.log_traceback()
			return False
		return True
	#############
	#adm_del_user
	#############
	@_dbg
	def adm_del_user(self,user):
		"deletes a user"
		try:
			del self._smtpd_passwords[user]
			return True
		except:
			self.log("User could not be deleted","w")
			return False
		return True
	########################
	#_read_smtpdpasswordfile
	########################
	@_dbg
	def _read_smtpdpasswordfile( self,pwfile):
		try:
			f=open(os.path.expanduser(pwfile))
		except:
			self.log("hksmtpserver: Config file could not be read","e")
			self.log_traceback()
			exit(5)
		txt=f.read()
		f.close()
		self._smtpd_passwords=dict()
		for l in txt.splitlines():
			try:
				name,passwd=l.split("=",1)
				self._smtpd_passwords[name.strip()]=passwd.strip()
			except:
				pass
	########################
	#write_smtpdpasswordfile
	########################
	@_dbg
	def write_smtpdpasswordfile(self, pwfile):
		"writes the users to the password file"
		try:
			pwfile=os.path.expanduser(pwfile)
			fileexists=os.path.exists(pwfile)
			f=open(pwfile,"w")
			if not fileexists:
				os.chmod(pwfile,0o600)
				self.debug("new pwfile chmod")
				f=open(pwfile,"w")
		except:
			self.log("hksmtpserver: Config file could not be written","e")
			self.log_traceback()
			return False
		for user in self._smtpd_passwords:
			try:
				password=self._smtpd_passwords[user]
				f.write(("%s=%s\n"%(user,password)))
			except:
				self.log_traceback()
		f.close()
###################
#start_adminconsole
###################
@_dbg
def start_adminconsole(host,port):
	"starts the admin console"
	import getpass
	class gmeadmin():
		def __init__(self):
			self.smtp= smtplib.SMTP()
			self.host="localhost"
			self.port=0
			self.timer=_mytimer()
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
			print("gpgmailencrypt admin console")
			print("============================")
			user=input("User: ")
			password=getpass.getpass("Password: ")
			auth=binascii.b2a_base64(("\x00%s\x00%s"%(user,password)).encode("UTF-8"))[:-1]
			code,msg=self._sendcmd("ADMIN",auth.decode("UTF-8"))
			code,msg=self._sendcmd("AUTH PLAIN",auth.decode("UTF-8"))
			if code!=235:
				print("Authentication failed")
				exit(1)
			print("Welcome. Enter 'HELP' for a list of commands")
			self.timer.start(10,60)
			while True:
				i=""
				try:
					try:
						i=input("> ").upper()
					except (KeyboardInterrupt,EOFError):
						i="QUIT"
					self.timer.set_alive()
					if not self.timer.is_running():
						print("Automatic logout due to inactivity")
						i="QUIT"
					res=i.split(" ")
					i=res[0].upper()
					args=""
					try:
						args=" ".join(res[1:])
					except:
						pass
					cmd=""
					if i in _gpgmailencryptserver.ADMINALLCOMMANDS:
						if i=="HELP":
							self.print_help()
						else:
							self._sendcmd(i,args)
					else:
						print("Error: command '%s' unknown"%i)
				except:
					print("Error sending admin command, perhaps server is down")
					#print( sys.exc_info())
					i="QUIT"
				if i=="QUIT":
					break
			self.timer.stop()
		def print_help(self):
			print("\nAllowed commands:")
			print("=================")
			print("flush			tries to re-send deferred emails")
			print("debug true/false	sets the debug mode")
			print("deluser			deletes a user")
			print("			example: 'deluser john'")
			print("help			this help")
			print("quit			leave the console")
			print("reload			reloads the configuration file")
			print("resetstatistics		sets all statistic values to 0")
			print("setuser			adds a new user or changes the password for an existing user")
			print("			example: 'setuser john johnspassword'")
			print("statistics		print statistic information")
			print("users			print users")
	class MyCompleter(object):  # Custom completer
		#class taken from http://stackoverflow.com/questions/20625642/autocomplete-with-readline-in-python3
		def __init__(self, options):
			self.options = sorted(options)
		def complete(self, text, state):
			if state == 0:  # on first trigger, build possible matches
				if not text:
					self.matches = self.options[:]
				else:
					self.matches = [s for s in self.options if s and s.upper().startswith(text.upper())]
			try:
				return self.matches[state]
			except IndexError:
				return None
		def display_matches(self, substitution, matches, longest_match_length):
			print()
			print(matches)
			print("> %s"%substitution,end="")
			sys.stdout.flush()
			columns = environ.get("COLUMNS", 80)
			line_buffer = readline.get_line_buffer()
			tpl = "{:<" + str(int(max(map(len, matches)) * 1.2)) + "}"
			buffer = ""
			for match in matches:
				match = tpl.format(match[len(substitution):])
				if len(buffer + match) > columns:
					print(buffer)
					buffer = ""
				buffer += match
			if buffer:
				print(buffer)
			print("> ", end="")
			print(line_buffer, end="")
			sys.stdout.flush()
	completer = MyCompleter(_gpgmailencryptserver.ADMINALLCOMMANDS)
	readline.set_completer_delims(' \t\n;')
	readline.set_completer(completer.complete)
	readline.parse_and_bind('tab: complete')
	readline.set_completion_display_matches_hook(completer.display_matches)
	g=gmeadmin()
	g.start(host,port)
######################
#_gpgmailencryptserver
######################
class _gpgmailencryptserver(smtpd.SMTPServer):
	"encryption smtp server based on smtpd"
	ADMINCOMMANDS=["STATISTICS","RELOAD","FLUSH","SETUSER","DELUSER","DEBUG","USERS","RESETSTATISTICS"]
	ADMINALLCOMMANDS=ADMINCOMMANDS+["HELP","QUIT"]
	def __init__(self, 
			parent,
			localaddr,
			sslcertfile=None,
			sslkeyfile=None,
			sslversion=ssl.PROTOCOL_SSLv23,
			use_smtps=False,
			use_auth=False,
			authenticate_function=None,
			write_smtpdpasswordfile=None,
			read_smtpdpasswordfile=None,
			data_size_limit=smtpd.DATA_SIZE_DEFAULT):
		self.parent=parent
		try:
			smtpd.SMTPServer.__init__(self, localaddr, None,data_size_limit=data_size_limit)
		except socket.error as e:
			self.parent.log("hksmtpserver: error",e)
			exit(5)
		self.sslcertfile=sslcertfile
		self.sslkeyfile=sslkeyfile
		self.sslversion=sslversion
		self.use_smtps=use_smtps
		self.use_authentication=use_auth
		self.write_smtpdpasswordfile=write_smtpdpasswordfile
		self.read_smtpdpasswordfile=read_smtpdpasswordfile
		self.authenticate_function=authenticate_function
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
					self.parent.log("hksmtpserver: Exception: Could not start SSL connection")
					self.parent.log_traceback()
					return
			self.parent.debug('hksmtpserver: Incoming connection from %s' % repr(addr))
			channel = _hksmtpchannel(self, 
						conn, 
						addr,
						parent=self.parent,
						use_auth=self.use_authentication, 
						authenticate_function=self.authenticate_function,
						write_smtpdpasswordfile=self.write_smtpdpasswordfile,	
						read_smtpdpasswordfile=self.read_smtpdpasswordfile,
						sslcertfile=self.sslcertfile,
						sslkeyfile=self.sslkeyfile,
						sslversion=self.sslversion)
	@_dbg
	def process_message(self, peer, mailfrom, receiver, data):
		self.parent.debug("hksmtpserver: _gpgmailencryptserver from '%s' to '%s'"%(mailfrom,receiver))
		try:
			self.parent.encrypt_mails(data,receiver)
		except:
			self.parent.log("hksmtpserver: Bug:Exception!")
			self.parent.log_traceback()
		return
###############
#_hksmtpchannel
###############
class _hksmtpchannel(smtpd.SMTPChannel):
	"helper class for _gpgmailencryptserver"
	def __init__(self, 
				smtp_server, 
				newsocket, 	
				fromaddr,					
				use_auth,
				parent,
				authenticate_function=None,
				write_smtpdpasswordfile=None,
				read_smtpdpasswordfile=None,
				use_tls=False,
				force_tls=False,
				sslcertfile=None,
				sslkeyfile=None,
				sslversion=None):
		smtpd.SMTPChannel.__init__(self, smtp_server, newsocket, fromaddr)
		asynchat.async_chat.__init__(self, newsocket)
		self.parent=parent
		self.sslcertfile=sslcertfile
		self.sslkeyfile=sslkeyfile
		self.sslversion=sslversion
		self.use_tls=use_tls
		self.starttls_available=False
		self.force_tls=force_tls
		self.tls_active=False
		self.authenticate_function=authenticate_function
		self.write_smtpdpasswordfile=write_smtpdpasswordfile  
		self.read_smtpdpasswordfile=read_smtpdpasswordfile
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
	#the following method is taken from SMTPChannel and is corrected to not throw an encoding error if something else than unciode comes through the line
	# Implementation of base class abstract method
	def collect_incoming_data(self, data):
		limit = None
		if self.smtp_state == self.COMMAND:
			limit = self.max_command_size_limit
		elif self.smtp_state == self.DATA:
			limit = self.data_size_limit
		if limit and self.num_bytes > limit:
			return
		elif limit:
			self.num_bytes += len(data)
		encodeddata=None
		for e in ["UTF-8","ISO8859-15","ISO8859-2","ISO8859-9","ISO8859-3","ISO8859-4","ISO8859-5","ISO8859-6","ISO8859-7",
				"ISO8859-8","ISO8859-10","ISO8859-13","ISO8859-14","ISO8859-16","KOI8","KOI8-R","KOI8-U","Windows-1251",
				"BIG5","GB18030","Windows-1252","Windows-1256","Windows-1250","Windows-1251","Windows-1250","UTF-16"]:
			try:
				encodeddata=data.decode(e)
				break
			except:
				pass
		if encodeddata==None:
			encodeddata=data.decode("UTF-8",_unicodeerror)
		self.received_lines.append(encodeddata)

	def smtp_HELO(self,arg):
		self.parent.debug("hksmtpserver: HELO")
		if not arg:
	       		self.push('501 Syntax: HELO hostname')
	       		return
		if self.seen_greeting:
			self.push('503 Duplicate HELO/EHLO')
		else:
			self.seen_greeting = True
			self.push('250 %s' % self.fqdn)
	def smtp_EHLO(self, arg):
		self.parent.debug("hksmtpserver: EHLO")
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
	def smtp_RSET(self, arg):
		self.parent.debug("hksmtpserver: RSET")
		self.reset_values()
		smtpd.SMTPChannel.smtp_RSET(self,arg)
	def reset_values(self):	
		self.is_authenticated=False
		self.is_admin=False
		self.user=""
		self.password=""
		self.seen_greeting=False
	def smtp_DEBUG(self,arg):
		syntaxerror="501 Syntax error: DEBUG TRUE|FALSE or ON|OFF or YES|NO"
		if not arg:
			self.push(syntaxerror)
			return
		command=arg.upper()
		if command in ["TRUE","ON","YES"] :
			res=True
		elif command in ["FALSE","OFF","NO"]:
			res=False
		else:
			self.push(syntaxerror)
			return
		self.parent.set_debug(res)
		self.push("250 OK")
	def smtp_AUTH(self,arg):
		self.parent.debug("hksmtpserver: AUTH")
		if not arg:
			self.push("501 Syntax error: AUTH PLAIN")
			return
		#self.parent.debug("hksmtpserver: Original ARG: %s"%arg)
		res=arg.split(" ")
		if len(res)<2:
			self.push("454 Temporary authentication failure.")
			return
		command,encoded=res	
		if "PLAIN" in command.upper():
			self.parent.debug("hksmtpserver: PLAIN decoding")
			try:
				d=binascii.a2b_base64(encoded).decode("UTF-8",_unicodeerror).split('\x00')
			except:
				self.parent.debug("hksmtpserver: error decode base64 '%s'"%sys.exc_info()[1])
				d=[]
			if len(d)<2:
				self.push("454 Temporary authentication failure.")
				return
			while len(d)>2:
				del d[0]
			user=d[0]
			password=d[1]
			if not self.authenticate_function:
				self.parent.debug("hksmtpserver: self.authenticate_function=None")
			if self.authenticate_function and self.authenticate_function(self.parent,user,password):
				self.push("235 Authentication successful.")
				self.is_authenticated=True
				self.is_admin=self.parent.is_admin(user)
				self.user=user
				if self.is_admin:
					self.parent.log("admin user '%s' logged in"%user)
				else:
					self.parent.log("User '%s' successfully logged in"%user)
			else:
				self.push("454 Temporary authentication failure.")
				self.parent.log("User '%s' failed to login"%user,"w")
		else:
			self.push("454 Temporary authentication failure.")
	def smtp_RESETSTATISTICS(self,arg):
		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return
		self.parent.reset_statistics()
		self.push("250 OK")
	def smtp_STATISTICS(self,arg):
		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return
		statistics=self.parent.get_statistics()
		c=0
		self.push("250-gpgmailencrypt version %s (%s)"%(VERSION,DATE))
		_now=datetime.datetime.now()
		self.push("250-Server runs %s"%(_now-self.parent._daemonstarttime))
		for s in sorted(statistics):
			dash="-"
			if c==len(statistics)-1:
				dash=" "
			self.push("250%s%s %s"%(dash,s.ljust(25),str(statistics[s]).rjust(4)) )
			c+=1
	def smtp_FLUSH(self,arg):
		self.parent.log("FLUSH")
		self.parent.check_deferred_list()
		self.parent.check_mailqueue()
		self.push("250 OK")
	def smtp_RELOAD(self,arg):
		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return
		self.parent.log("smtp_RELOAD configuration")
		self.parent.init()
		self.parent._parse_commandline()
		self.push("250 OK")
	def smtp_USERS(self,arg):
		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return
		c=0
		users=self.parent.adm_get_users()
		for user in users:
			dash="-"
			if c==len(users)-1:
				dash=" "
			adm=""
			if user["admin"]:
				adm="is admin"
			self.push("250%s%s %s"%(dash,user["user"],adm))
			c+=1

	def smtp_SETUSER(self,arg):
		if not arg:
			self.push("501 Syntax error: SETUSER user password")
			return
		res=arg.split(" ")
		if len(res)!=2:
			self.push("501 Syntax error: SETUSER user password")
			return
		r=self.parent.adm_set_user(res[0],res[1])
		if r:
			if self.write_smtpdpasswordfile:
				self.write_smtpdpasswordfile(self.parent._SMTPD_PASSWORDFILE)
			self.push("250 OK")
		else:
			self.push("454 User could not be set")
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
		r=self.parent.adm_del_user(res[0])
		if r:
			if self.write_smtpdpasswordfile:
				self.write_smtpdpasswordfile(self.parent._SMTPD_PASSWORDFILE)
			self.push("250 OK")
		else:
			self.push("454 User could not be deleted")
	def smtp_ADMIN(self,arg):
		self.adminmode=True
		if self.read_smtpdpasswordfile:
			self.read_smtpdpasswordfile(self.parent._SMTPD_PASSWORDFILE)
		self.push("250 OK")
		return
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
		if (self.use_authentication or self.adminmode) and not self.is_authenticated:
			if not command in SIMPLECOMMANDS+["AUTH"]:
				self.push("530 Authentication required.")
				self._SMTPChannel__line=[]
				return
		if not self.is_admin:
			if command in _gpgmailencryptserver.ADMINCOMMANDS:
				self.push("530 Admin authentication required.")
				self._SMTPChannel__line=[]
				return
		if self.use_tls and self.force_tls and not self.tls_active:
			if not command in SIMPLECOMMANDS+_gpgmailencryptserver.ADMINCOMMANDS:
				self.push("530 STARTTLS before authentication required.")
				self._SMTPChannel__line=[]
				return
		smtpd.SMTPChannel.found_terminator(self)
	def smtp_STARTTLS(self,arg):
			self.push('502 Error: command "STARTTLS" not implemented' )
			self._SMTPChannel__line=[]
			return
##########
#file_auth
##########
def file_auth(parent,user,password):
	"checks user authentication against a password file"
	parent.debug("hksmtpserver: file_auth")
	try:
		pw=parent._smtpd_passwords[user]
		if pw==_get_hash(password):
			parent.debug("hksmtpserver: User '%s' authenticated"%user)
			return True
		else:
			parent.debug("hksmtpserver: User '%s' incorrect password"%user)
	except:
		parent.debug("hksmtpserver: No such user '%s'"%user)
	return False
##########
#_get_hash
##########
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
#####
#main
#####
def main():
	"main routine which will be called when gpgmailencrypt is started as a script, not as a module"
	with gme() as g:
		receiver=g._parse_commandline()
		g._set_logmode()
		if g._RUNMODE==g.m_daemon:
			g.daemonmode()
		else:
			g.scriptmode(receiver)
#############################
# gpgmailencrypt main program
#############################
if __name__ == "__main__":
	main()


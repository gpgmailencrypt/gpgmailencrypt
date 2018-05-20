#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
"""
gpgmailencrypt is an e-mail gateway, that can encrypt e-mails, scan for viruses
and spam.

It supports
* PGP/Inline
* PGP/Mime
* S/Mime
* encrypted PDF

It can be used normally as a script doing everything on command line, in daemon
mode, where gpgmailencrypt acts as an encrypting smtp server or as a module
for programmers.
It takes e-mails and  returns the e-mail encrypted to another e-mail server
if a encryption key exists for the recipient. Otherwise it returns the e-mail
unencrypted.The encryption method can be selected per user.

Usage:
Create a configuration file with "gpgmailencrypt.py -x > ~/gpgmailencrypt.conf"
and copy this file into the directory /etc
"""
import base64
import configparser
import datetime
import email
import email.encoders
import email.message
import email.mime
import email.utils
from   email.mime.base	  		import MIMEBase
from   email.mime.multipart 	import MIMEMultipart
from   email.mime.text	  		import MIMEText
import getopt
import gmeutils.spamscanners 	as spamscanners
import gmeutils.archivemanagers as archivemanagers
import gmeutils.storagebackend 	as backend
import gmeutils.mylogger 		as mylogger
from   gmeutils._dbg 		  	import _dbg
from   gmeutils.gpgclass 		import _GPG,_GPGEncryptedAttachment
from   gmeutils.gpgmailserver 	import _gpgmailencryptserver
from   gmeutils.helpers			import *
from   gmeutils.mytimer       	import _mytimer
from   gmeutils.smimeclass 		import _SMIME
from   gmeutils.pdfclass 		import _PDF
from   gmeutils.usage       	import show_usage,print_exampleconfig
from   gmeutils.viruscheck    	import _virus_check
from   gmeutils.version			import *
from   gmeutils.dkim			import mydkim
import html
from   io					  	import TextIOWrapper
import locale
import os
import re
import shutil
import signal
import smtplib
import ssl
import sys
import tempfile
import time
import traceback

__all__ =["gme"]

####
#gme
####

class gme:
	"""
	Main class to encrypt emails
	create an instance of gme via 'with gme() as g'
	example:
	with gme() as g:
	  g.send_mails(mailtext,["recipient@mail.com","receiver2@mail.com"])

	this will be all to encrypt and send the mails
	"""
	o_mail=1
	o_stdout=2
	o_file=3
	m_daemon=1
	m_script=2
	s_may=1
	s_redirect=2
	s_bounce=3
	s_script=4
	pdf_none=1
	pdf_script=2
	pdf_sender=3
	_encryptheader="X-GPGMailencrypt"
	_pdfencryptheader="X-PDFEncrypted"

	#########
	#__init__
	#########

	def __init__(self):
		"class creator"
		self._deferred_emails=[]
		self._email_queue={}
		self._virus_queue=[]
		self._queue_id=0
		self._daemonstarttime=datetime.datetime.now()
		self._RUNMODE=None
		self.reset_statistics()
		self._logger=mylogger.mylogger(parent=self)
		self.reset_messages()
		self._GPGkeys=list()
		self._GPGprivatekeys=list()
		self._backend=backend.get_backend("TEXT",parent=self)
		self.init()

	#################
	#reset_statistics
	#################

	def reset_statistics(self):
		#self.reset_messages()
		self._count_totalmails=0
		self._count_encryptedmails=0
		self._count_deferredmails=0
		self._count_alreadyencryptedmails=0
		self._count_alarms=0
		self._count_smimemails=0
		self._count_pgpmimemails=0
		self._count_decryptedemails=0
		self._count_pgpinlinemails=0
		self._count_pdfmails=0
		self._count_viruses=0
		self._count_spam=0
		self._count_maybespam=0

	###############
	#reset_messages
	###############

	def reset_messages(self):
		self._systemerrors=0
		self._systemwarnings=0
		self._logger._systemmessages=[]

	###################
	#reset_pdfpasswords
	###################

	@_dbg
	def reset_pdfpasswords(self):
		self._backend.reset_pdfpasswords()

	#####################
	#del_old_pdfpasswords
	#####################

	@_dbg
	def del_old_pdfpasswords(self,age):
		self._backend.del_old_pdfpasswords(age)

	#########
	#__exit__
	#########

	def __exit__(self, exc_type, exc_value, traceback):
		"automatic clean up tempfiles when created with the 'with' statement"
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
			self.log("gpgmailencrypt server did run %s"%(
											_now-self._daemonstarttime))
			self._log_statistics()

		for f in self._tempfiles:

			try:
				os.remove(f)
				self.debug("do_finally delete tempfile '%s'"%f)
			except:
				pass

		if self._RUNMODE==self.m_daemon:
			self.store_deferred_list()

		self._logger.close()
		self._backend.close()

	#####
	#init
	#####

	@_dbg
	def init(self):
		"initiales the module and reads the config file"

		#Internal variables
		self._tempfiles = list()
		self._mailcount=0
		self._encryptgpgcomment="Encrypted by gpgmailencrypt version %s"%VERSION
		self._smtpd_passwords=dict()
		self._encoding = locale.getdefaultlocale()[1]
		self._virus_checker=None
		self._spam_checker=None

		if self._encoding==None:
			self._encoding="UTF-8"

		self._spam_cmd=shutil.which("spamc")
		self._spam_leveldict={}
		self._usepdf=False
		self._dkim=None

		#GLOBAL CONFIG VARIABLES
		self._DEFERLIST=os.path.expanduser("~/deferlist.txt")
		self._DEFERDIR=os.path.expanduser("~/gpgmaildirtmp")
		self._VIRUSLIST=os.path.expanduser("~/viruslist.txt")
		self._QUARANTINEDIR=os.path.expanduser("~/gmequarantine")

		if not os.path.exists(self._DEFERDIR):
			os.makedirs(self._DEFERDIR)

		if not os.path.exists(self._QUARANTINEDIR):
			os.makedirs(self._QUARANTINEDIR)

		self._STATISTICS_PER_DAY=1
		self._SYSTEMMAILFROM="gpgmailencrypt@localhost"
		self._ALWAYSENCRYPT=False
		self._ADDHEADER=False
		self._SMTP_HOST='localhost'
		self._SMTP_PORT=25
		self._SMTP_CREDENTIAL=""
		self._SMTP_AUTHENTICATE=False
		self._SMTP_USER=""
		self._SMTP_PASSWORD=""
		self._SMTP_USESMTPS=False
		self._SMTP_CERTFINGERPRINTS=[]
		self._SMTP_CACERTS=None
		self._SMTP_VERIFYCERT=False
		self._SMTP_HOST2='localhost'
		self._SMTP_PORT2=25
		self._SMTP_AUTHENTICATE2=False
		self._SMTP_USER2=""
		self._SMTP_PASSWORD2=""
		self._SMTP_CREDENTIAL2=""
		self._SMTP_CACERTS2=None
		self._SMTP_USESMTPS2=False
		self._SMTP_VERIFYCERT2=False
		self._DOMAINS=""
		self._HOMEDOMAINS=["localhost"]
		self._INFILE=""
		self._OUTFILE=""
		self._SECURITYLEVEL=self.s_may
		self._BOUNCESCRIPT=None
		self._DECRYPT=False
		self._BOUNCEHOMEDOMAIN=True
		self._PREFERRED_ENCRYPTION="PGPINLINE"
		self._ALLOWGPGCOMMENT=False
		v=default_values()
		self._GPGCMD=v["GPGCMD"]
		self._SMIMECMD=v["SMIMECMD"]
		self._GPGKEYHOME=v["GPGKEYHOME"]
		self._SMIMEKEYHOME=v["SMIMEKEYHOME"]
		self._CONFIGFILE=v["CONFIGFILE"]
		self._MAILTEMPLATEDIR=v["MAILTEMPLATEDIR"]
		self._SMTPD_SSL_KEYFILE=v["SMTPD_SSL_KEYFILE"]
		self._SMTPD_SSL_CERTFILE=v["SMTPD_SSL_CERTFILE"]
		self._GPGKEYEXTRACTDIR=os.path.join(self._GPGKEYHOME,"extract")
		self._GPGAUTOMATICEXTRACTKEYS=False
		self._GPGMIME_ENCRYPTSUBJECT=False
		self._GPGINLINE_ZIPCONTAINER=False
		self._GPGINLINE_CONTENTPDF=False
		self._SMIMEKEYEXTRACTDIR=os.path.join(self._SMIMEKEYHOME,"extract")
		self._SMIMECIPHER="DES3"
		self._SMIMEAUTOMATICEXTRACTKEYS=False
		self._OUTPUT=self.o_mail
		self._LOCALE="EN"
		self._RUNMODE=self.m_script
		self._SMTPD_HOST="127.0.0.1"
		self._SMTPD_PORT=10025
		self._SMTPD_USE_SMTPS=False
		self._SMTPD_USE_STARTTLS=False
		self._SMTPD_USE_AUTH=False
		self._SMTPD_FORCETLS=False
		self._USEPDF=False
		self._PDFPASSWORDMODE=self.pdf_sender
		self._PDFPASSWORDSCRIPT="~/mailscript.sh"
		self._PDFSECUREZIPCONTAINER=False
		self._PDFPASSWORDLENGTH=10
		self._PDFPASSWORDLIFETIME=48*60*60
		self._PDFINCLUDEIMAGES=True
		self._7ZIPCMD=""
		self._USE7ZARCHIVE=False
		self._ZIPCIPHER="ZipCrypto"
		self._ZIPCOMPRESSION=5
		self._ZIPATTACHMENTS=False
		self._ADMINS=[]
		self._VIRUSCHECK=False
		self._VIRUSLIFETIME=2419200 #4 weeks
		self._SPAMCHECK=False
		self._SPAMSCANNER="SPAMASSASSIN"
		self._SA_SPAMHOST="localhost"
		self._SA_SPAMPORT=783
		self._SA_SPAMLEVEL=6.2
		self._SA_SPAMSUSPECTLEVEL=3.0
		self._SPAMMAXSIZE=500000
		self._SPAMCHANGESUBJECT=False
		self._SPAMSUBJECT="***SPAM***"
		self._SPAMSUSPECTSUBJECT="***SPAMSUSPICION***"
		self._SPAMADDHEADER=True
		self._USEDKIM=False
		self._DKIMSELECTOR="gpgdkim"
		self._DKIMDOMAIN="localhost"
		self._DKIMKEY=""
		self._SENTADDRESS="SENT"
		self._USE_SENTADDRESS=False
		self._used_smtpdport=-1 # used to return the real port number 
								#(e.g. when _SMTPD_PORT=0)
		self._logger.init()
		self._backend.init()
		self._read_configfile()

	#################
	#_read_configfile
	#################

	@_dbg
	def _read_configfile(self):
		_cfg = configparser.ConfigParser(	inline_comment_prefixes=("#",),
								comment_prefixes=("#",))
		self._GPGkeys=list()

		try:
			_cfg.read(self._CONFIGFILE)
		except:
			self.log("Could not read config file '%s'"%self._CONFIGFILE,"e",
			force=True)
			self.log_traceback()
			return

		#logging
		self._logger.read_configfile(_cfg)
		
		#default
		if _cfg.has_section('default'):

			try:
				domains=_cfg.get('default','homedomains').split(",")
				self._HOMEDOMAINS=[]

				for d in domains:
					self._HOMEDOMAINS.append(d.lower().strip())

			except:
				pass

			try:
				self._ADDHEADER=_cfg.getboolean('default','add_header')
			except:
				pass

			try:
				o=_cfg.get('default','output').lower().strip()

				if o=="mail":
					self._OUTPUT=self.o_mail
				elif o=="stdout":
					self._OUTPUT=self.o_stdout
				elif o=="file":
					self._OUTPUT=self.o_file
				else:
					self._OUTPUT=self.o_stdout

			except:
				pass
			try:
				self._DEFERLIST=os.path.expanduser(_cfg.get('default','deferlist'))
			except:
				pass

			try:
				self._DEFERDIR=os.path.expanduser(_cfg.get('default','deferdir'))

				if not os.path.exists(self._DEFERDIR):
					os.makedirs(self._DEFERDIR)

			except:
				pass

			try:
				self._VIRUSLIST=os.path.expanduser(_cfg.get('default','viruslist'))
			except:
				pass

			try:
				self._QUARANTINEDIR=os.path.expanduser(_cfg.get('default','quarantinedir'))

				if not os.path.exists(self._QUARANTINEDIR):
					os.makedirs(self._QUARANTINEDIR)

			except:
				pass


			try:
				self._OUTFILE=os.path.expanduser(_cfg.get('default','outfile'))
			except:
				pass

			try:
				o=_cfg.get('default','securitylevel').lower().strip()

				if o=="bounce":
					self._SECURITYLEVEL=self.s_bounce
				elif o=="redirect":
					self._SECURITYLEVEL=self.s_redirect
				elif o=="script":
					self._SECURITYLEVEL=self.s_script
				else:
					self._SECURITYLEVEL=self.s_may
					if not o=="may":
						self.log("Config file security option '%s' unknown."
							" Setting securitylevel to 'may'","e")
			except:

				try:
					s2=_cfg.getboolean('mailserver',"useserver2")
					self.log("config entry [mailserver].useserver2 is depre"
					"cated. Use '[default].securitylevel redirect' instead")
					if s2:
						self._SECURITYLEVEL=self.s_redirect
				except:
					pass

			try:
				self._BOUNCEHOMEDOMAIN=_cfg.getboolean('default',
												'bouncehomedomain')
			except:
				pass

			try:
				self._BOUNCESCRIPT=_cfg.get('default',
												'bouncescript')
			except:
				pass

			try:
				self._DECRYPT=_cfg.getboolean('default',
												'decrypt')
			except:
				pass

			try:
				self._LOCALE=_cfg.get('default','locale').upper().strip()
			except:
				pass

			try:
				self._SYSTEMMAILFROM=_cfg.get('default',
												'systemmailfrom').strip()
			except:
				pass

			try:
				self._MAILTEMPLATEDIR=_cfg.get('default',
												'mailtemplatedir').strip()
			except:
				pass

			try:
				self._DOMAINS=_cfg.get('default','domains')
			except:
				pass

			try:
				p=_cfg.get('default','preferred_encryption').lower()

				if p=="smime":
					self._PREFERRED_ENCRYPTION="SMIME"
				elif p=="pgpmime":
					self._PREFERRED_ENCRYPTION="PGPMIME"
				elif p=="pdf":
					self._PREFERRED_ENCRYPTION="PDF"
				else:
					self._PREFERRED_ENCRYPTION="PGPINLINE"

			except:
				pass

			try:
				self._ALWAYSENCRYPT=_cfg.getboolean('default','alwaysencrypt')
			except:
				pass

			try:
				self._SENTADDRESS=_cfg.get('default',
							'sent_address').replace("<","_").replace(">","_")
			except:
				pass

			try:
				self._USE_SENTADDRESS=_cfg.getboolean('default',
													'use_sentaddress')
			except:
				pass

			try:
				b=_cfg.get('default',
								'storagebackend')
				self._backend=backend.get_backend(b,parent=self)
			except:
				pass

		#gpg
		if _cfg.has_section('gpg'):

			try:
				k=_cfg.get('gpg','keyhome')

				if k!=None:
					self._GPGKEYHOME=k.strip()

			except:
				pass

			try:
				self._GPGCMD=_cfg.get('gpg','gpgcommand')
			except:
				pass

			try:
				self._ALLOWGPGCOMMENT=_cfg.getboolean('gpg','allowgpgcomment')
			except:
				pass

			try:
				self._GPGINLINE_ZIPCONTAINER=_cfg.getboolean('gpg','inlinezipcontainer')
			except:
				pass

			try:
				self._GPGINLINE_CONTENTPDF=_cfg.getboolean('gpg','inlinecontentpdf')
			except:
				pass

			try:
				self._GPGAUTOMATICEXTRACTKEYS=_cfg.getboolean('gpg',
															'extractkey')
			except:
				pass

			try:
				self._GPGMIME_ENCRYPTSUBJECT=_cfg.getboolean('gpg',
															'encryptsubject')
			except:
				pass

			try:
				k=_cfg.get('gpg','keyextractdir')

				if k!=None:
					self._GPGKEYEXTRACTDIR=k.strip()

			except:
				pass

		#mailserver
		if _cfg.has_section('mailserver'):

			try:
				self._SMTP_HOST=_cfg.get('mailserver','host')
			except:
				pass

			try:
				self._SMTP_PORT=_cfg.getint('mailserver','port')
			except:
				pass

			try:
				self._SMTP_USESMTPS=_cfg.getint('mailserver','usesmtps')
			except:
				pass

			try:
				self._SMTP_VERIFYCERT=_cfg.getboolean('mailserver',
														'verifycertificate')
			except:
				pass

			try:
				self._SMTP_AUTHENTICATE=_cfg.getboolean('mailserver',
														'authenticate')
			except:
				pass

			try:
				self._SMTP_CREDENTIAL=_cfg.get('mailserver','smtpcredential')
			except:
				pass

			try:
				self._SMTP_CACERTS=_cfg.get('mailserver','cacerts')
				if self._SMTP_CACERTS.upper()=="NONE":
					self._SMTP_CACERTS=None
			except:
				pass

			try:
				self._SMTP_HOST2=_cfg.get('mailserver','host2')
			except:
				pass

			try:
				self._SMTP_PORT2=_cfg.getint('mailserver','port2')
			except:
				pass

			try:
				self._SMTP_AUTHENTICATE2=_cfg.getboolean('mailserver',
														'authenticate2')
			except:
				pass

			try:
				self._SMTP_CREDENTIAL2=_cfg.get('mailserver','smtpcredential2')
			except:
				pass

			try:
				self._SMTP_USESMTPS2=_cfg.getint('mailserver','usesmtps2')
			except:
				pass

			try:
				self._SMTP_VERIFYCERT2=_cfg.getboolean('mailserver',
														'verifycertificate2')
			except:
				pass

			try:
				self._SMTP_CACERTS2=_cfg.get('mailserver','cacerts2')
				if self._SMTP_CACERTS2.upper()=="NONE":
					self._SMTP_CACERTS2=None
			except:
				pass

			try:
				fingerprints=_cfg.get('mailserver','fingerprints').split(",")

				for f in fingerprints:
					self._SMTP_CERTFINGERPRINTS.append(f.strip())
			except:
				pass

		#daemon
		if _cfg.has_section('daemon'):

			try:
				self._SMTPD_HOST=_cfg.get('daemon','host')
			except:
				pass

			try:
				self._SMTPD_PORT=_cfg.getint('daemon','port')
			except:
				self.log_traceback()
				pass

			try:
				self._SMTPD_USE_SMTPS=_cfg.getboolean('daemon','smtps')
			except:
				pass

			try:
				self._SMTPD_USE_STARTTLS=_cfg.getboolean('daemon','starttls')
			except:
				pass

			try:
				self._SMTPD_FORCETLS=_cfg.getboolean('daemon','forcetls')
			except:
				pass

			try:
				self._SMTPD_SSL_KEYFILE=_cfg.get('daemon','sslkeyfile')
			except:
				pass

			try:
				self._SMTPD_SSL_CERTFILE=_cfg.get('daemon','sslcertfile')
			except:
				pass

			try:
				self._SMTPD_USE_AUTH=_cfg.getboolean('daemon','authenticate')
			except:
				pass

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

		#pdf
		if _cfg.has_section('pdf'):

			try:
				self._USEPDF=_cfg.getboolean('pdf','useenryptpdf')
			except:
				pass

			if not self._USEPDF and self._PREFERRED_ENCRYPTION=="PDF":
				self._PREFERRED_ENCRYPTION="PGPINLINE"

			try:
				self._PDFPASSWORDLENGTH=_cfg.getint('pdf','passwordlength')
			except:
				pass

			try:
				self._PDFPASSWORDLIFETIME=_cfg.getint('pdf','passwordlifetime')
			except:
				pass

			try:
				self._PDFINCLUDEIMAGES=_cfg.getboolean('pdf','includeimages')
			except:
				pass

			try:
				o=_cfg.get('pdf','passwordmode').lower().strip()

				if o=="none":
					self._PDFPASSWORDMODE=self.pdf_none
				elif o=="script":
					self._PDFPASSWORDMODE=self.pdf_script
				else:
					self._PDFPASSWORDMODE=self.pdf_sender

			except:
				pass

			try:
				script=_cfg.get('pdf','passwordscript')

				if len(script.strip())>0:
					self._PDFPASSWORDSCRIPT=script

			except:
				pass

		#zip
		if _cfg.has_section('zip'):

			try:
				self._PDFSECUREZIPCONTAINER=_cfg.getboolean('zip',
														'securezipcontainer')
			except:
				pass

			try:
				self._USE7ZARCHIVE=_cfg.getboolean('zip','use7zarchive')
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

		#smime
		if _cfg.has_section('smime'):

			try:
				self._SMIMECMD=_cfg.get('smime','opensslcommand')
			except:
				pass

			try:
				self._SMIMECIPHER=_cfg.get('smime',
										'defaultcipher').upper().strip()
			except:
				pass

			try:
				k=_cfg.get('smime','keyhome')

				if k!=None:
					self._SMIMEKEYHOME=k.strip()

			except:
				pass

			try:
				self._SMIMEAUTOMATICEXTRACTKEYS=_cfg.getboolean('smime',
															'extractkey')
			except:
				pass

			try:
				k=_cfg.get('smime','keyextractdir')

				if k!=None:
					self._SMIMEKEYEXTRACTDIR=k.strip()

			except:
				pass

		#spam
		if _cfg.has_section('spam'):

			try:
				self._SPAMCHECK=_cfg.getboolean('spam','checkspam')
			except:
				pass

			try:
				s=_cfg.get('spam','spamscanner').upper().strip()
				if s in spamscanners.get_spamscannerlist():
					self._SPAMSCANNER=s
			except:
				pass

			try:
				self._SPAMADDHEADER==_cfg.getboolean('spam','add_spamheader')
			except:
				pass

			try:
				self._SA_SPAMHOST=_cfg.get('spam','sa_host')
			except:
				pass

			try:
				self._SA_SPAMPORT=_cfg.getint('spam','sa_port')
			except:
				pass

			try:
				self._SPAMMAXSIZE=_cfg.getint('spam','maxsize')
			except:
				pass

			try:
				self._SA_SPAMLEVEL=_cfg.getfloat('spam','sa_spamlevel')
			except:
				pass

			try:
				self._SA_SPAMSUSPECTLEVEL=_cfg.getfloat('spam',
														'sa_spamsuspectlevel')
			except:
				pass

			try:
				self._SPAMCHANGESUBJECT=_cfg.getboolean('spam','change_subject')
			except:
				pass

			try:
				self._SPAMSUBJECT=_cfg.get('spam','spam_subject')
			except:
				pass

			try:
				self._SPAMSUSPECTSUBJECT=_cfg.get('spam','spamsuspect_subject')
			except:
				pass

		if (self._SA_SPAMLEVEL - self._SA_SPAMSUSPECTLEVEL) <1.0:
			self._SA_SPAMSUSPECTLEVEL=self._SA_SPAMLEVEL-1.0
			self.log("Spamlevel-Spamsuspectlevel<1, automatically corrected",
			"w")

		self._spam_leveldict["SPAMASSASSIN"]=[	self._SA_SPAMLEVEL,
												self._SA_SPAMSUSPECTLEVEL,
												self._SA_SPAMHOST,
												self._SA_SPAMPORT,
												self._SPAMMAXSIZE]

		#virus
		if _cfg.has_section('virus'):

			try:
				self._VIRUSCHECK=_cfg.getboolean('virus','checkviruses')
				self.set_check_viruses(self._VIRUSCHECK)
			except:
				pass

			try:
				self._VIRUSLIFETIME=_cfg.getint('virus','quarantinelifetime')
			except:
				pass

		#dkim
		if _cfg.has_section('dkim'):

			try:
				self._USEDKIM=_cfg.getboolean('dkim','use_dkim')
			except:
				pass

			try:
				self._DKIMSELECTOR=_cfg.get('dkim','dkimselector')
			except:
				pass

			try:
				self._DKIMDOMAIN=_cfg.get('dkim','dkimdomain')
			except:
				pass

			try:
				self._DKIMKEY=_cfg.get('dkim','dkimkey')
			except:
				pass

		if self._USEDKIM:
			self._dkim=mydkim(	parent=self,
							selector=self._DKIMSELECTOR,
							domain=self._DKIMDOMAIN,
							privkey=self._DKIMKEY)
		else:
			self._dkim=None

		self._set_logmode()

		if self._SMTP_AUTHENTICATE:
			self._SMTP_USER,self._SMTP_PASSWORD=self._read_smtpcredentials(
													self._SMTP_CREDENTIAL)

		if self._SMTP_AUTHENTICATE2:
			self._SMTP_USER2,self._SMTP_PASSWORD2=self._read_smtpcredentials(
													self._SMTP_CREDENTIAL2)

		pdf=self.pdf_factory()
		self._use_pdf=pdf.is_available()

		if not self._use_pdf:
			self.log("PDF support is not available","e")

		try:
			self._backend.read_configfile(_cfg )
		except:
			self.error("Backend read_configfile error")
			self.log_traceback()

	###################
	#_parse_commandline
	###################

	@_dbg
	def _parse_commandline(self):
		recipient=[]

		try:
			cl=sys.argv[1:]
			_opts,_remainder=getopt.gnu_getopt(cl,'ac:de:f:hk:l:m:n:o:vxyz',
			  ['addheader',
				'config=',
				'daemon',
				'decrypt',
				'example',
				'help',
				'keyhome=',
				'log=',
				'output=',
				'spamcheck=',
				'verbose',
				'version',
				'viruscheck=',
				'zip'])
		except getopt.GetoptError as e:
			self.log("unknown commandline parameter '%s'"%e,"e",force=True)
			exit(2)

		self._logger._parse_commandline(_opts)
		
		for _opt, _arg in _opts:

			if (_opt  =='-c' or  _opt == '--config') and _arg!=None:
				   _arg=_arg.strip()

				   if len(_arg)>0:
					   self._CONFIGFILE=_arg
					   self.log("read new config file '%s'"%self._CONFIGFILE)
					   self._read_configfile()
					   break

		self._logger._parse_commandline(_opts)

		for _opt, _arg in _opts:

			if _opt  =='-a' or  _opt == '--addheader':
				   self._ADDHEADER=True

			if _opt  =='-v' or  _opt == '--verbose':
				   self._logger._DEBUG=True

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

				self.debug("Set _PREFERRED_ENCRYPTION to "
						"'%s'"%self._PREFERRED_ENCRYPTION)

			if _opt  =='-f':
				   self._INFILE=os.path.expanduser(_arg)
				   self.debug("Set _INFILE to '%s'"%self._INFILE)

			if _opt  =='-h' or  _opt == '--help':
				   show_usage()
				   exit(0)

			if _opt  =='-k' or  _opt == '--keyhome':
				   self._GPGKEYHOME=_arg
				   self.debug("Set gpgkeyhome to '%s'"%self._GPGKEYHOME)

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
				   self._OUTFILE=os.path.expanduser(_arg)
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

			if _opt == '--viruscheck':

					if _arg.lower() in ["true","yes",None]:
				   		self.set_check_viruses(True)
					elif _arg.lower() in ["false","no"]:
						self.set_check_viruses(False)

			if _opt == '--decrypt':
					self._DECRYPT=True
			if _opt == '--spamcheck':

					if _arg.lower() in ["true","yes",None]:
				   		self._SPAMCHECK=True
					elif _arg.lower() in ["false","no"]:
				   		self._SPAMCHECK=False

		if not self._RUNMODE==self.m_daemon:

			if len(_remainder)>0 :
				recipient=_remainder[0:]
				self.debug("set addresses from commandline to '%s'"%recipient)
			else:
				self.log("gpgmailencrypt needs at least one recipient "
				"at the commandline, %i given"%len(_remainder),"e",force=True)
				exit(1)

		return recipient

	#################
	#try_repair_email
	#################

	@_dbg
	def try_repair_email(self,message):

		if isinstance(message,str):
			message = email.message_from_bytes( message.encode("utf8") )

		keys=[]

		for k in message.keys():

			if k in keys:
				continue
			else:
				keys.append(k)

			for p in message.get_all(k):

				if isinstance(p,email.header.Header):
					message.replace_header(k,p.__str__())
					self.debug("repair header %s"%k)


		if message["Content-Type"]==None:
			message["Content-Type"]="text/plain; charset=\"UTF-8\""

		if not message.is_multipart():
			field="Content-Transfer-Encoding"

			if not message[field]:
				message[field]="8bit"

		field="From"

		if not message[field]:
			message[field]=""

		field="To"

		if not message[field]:
			message[field]=""
		
		for p in message.walk():

			if p.is_multipart():
				continue

			if p.get_param("charset",header="Content-Type")==None:
				p.set_param("charset","UTF8")

		try:
			message.as_string()
		except:
			self.log("charset problem within payloads, try to repair","w")
			message=self.try_repack_payload(message)
			try:
				message.as_string()
			except:
				self.log("Could not use input file, give up","e")
				self.log_traceback()
				message=None


		return message

	###################
	#try_repack_payload
	###################

	@_dbg
	def try_repack_payload(self,message):
		for payload in message.walk():

			if payload.is_multipart():
				continue

			is_text=payload.get_content_maintype()=="text"

			if not is_text:
				continue

			cte=payload["Content-Transfer-Encoding"]
			charset=payload.get_param("charset",header="Content-Type")

			if not cte:
				cte="8bit"

			if charset!=None:
				try:
					"test".encode(charset)
				except:
					charset="UTF-8"

			if charset==None or charset.upper()=="ASCII" or len(charset)==0:
				charset="UTF-8"

			raw_payload=decodetxt(payload.get_payload(),cte,charset)
			payload.del_param("charset")
			payload.set_param("charset",charset)
			_encoder=None

			if cte=="8bit" or cte=="7bit":
				_encoder=email.encoders.encode_7or8bit
			elif cte=="base64":
				_encoder=email.encoders.encode_base64
			elif cte=="quoted-printable":
				_encoder=email.encoders.encode_quopri
			else:
				raise Exception("Could not find decoder for %s"% cte,"")

			raw_payload=raw_payload.replace("\r\n","\n").replace("\n","\r\n")
			payload.set_payload(raw_payload)
			_encoder(payload)

		return message

	######################
	#_read_smtpcredentials
	######################

	@_dbg
	def _read_smtpcredentials(self,pwfile):

		if not self._SMTP_AUTHENTICATE:
			return "",""

		try:
			f=open(pwfile,encoding="UTF-8",errors=unicodeerror)
		except:
			self.log("_gpgmailencryptserver: Config file could not be read","e")
			self.log_traceback()
			exit(5)

		txt=f.read()
		f.close()
		c=0
		_USER=""
		_PASSWORD=""

		for l in txt.splitlines():

			try:
				name,passwd=l.split("=",1)
				_USER=name.strip()
				_PASSWORD=passwd.strip()
				c+=1
			except:
				pass

		self.debug("_read_smtpcredentials END read lines: %i"%c)
		return _USER,_PASSWORD

	####
	#log
	####

	def log(self,
			msg,
			infotype="m",
			lineno=-1,
			filename="",
			force=False):
		self._logger.log(msg,infotype,lineno,filename,force=force)
		
	##############
	#log_traceback
	##############

	def log_traceback(self):
		"logs the exception information"
		exc_type, exc_value, exc_tb = sys.exc_info()
		error=traceback.format_exception(exc_type, exc_value, exc_tb)

		for e in error:
			self.log(" ***%s"%e.replace("\n",""),"e",force=True)

	######
	#debug
	######

	def debug(  self,
				msg,
				lineno=0,
				filename=""):
		"prints debugging information"

		self._logger.debug(msg,lineno,filename)

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

	########
	#warning
	########

	def warning(self,
				msg,
				lineno=0,
				filename=""):
		"""logs as warning message."""
		self.log(msg,infotype="w",lineno=lineno,filename=filename,force=False)

	############
	#set_logging
	############

	def set_logging( self, logmode):
		self._logger.set_logging(logmode)

	############
	#get_logging
	############

	def get_logging( self):
		return self._logger.get_logging()

	################
	#_debug_keepmail
	################

	@_dbg
	def _debug_keepmail(self,mailtext):

		if not isinstance(mailtext,str):
			mailtext=mailtext.as_string()

		searchtext=mailtext.lower()
		#return True

		for txt in self._logger._DEBUGSEARCHTEXT:

			if txt.lower() in searchtext:

				for exclude in self._logger._DEBUGEXCLUDETEXT:

					if exclude.lower() in searchtext:
						return False

				return True

		return False

	####################
	#_load_rawmailmaster
	####################

	@_dbg
	def _load_rawmailmaster(self,identifier,defaulttext):
		f=None
		self.debug("_load_mailmaster '%s'"% identifier)

		try:
			templatefile=os.path.join(  self._MAILTEMPLATEDIR,
										self._LOCALE,
										"%s.html"%identifier)
			f=open(templatefile,encoding="UTF-8",errors=unicodeerror)
			self.debug("template found in %s"%templatefile)
		except:
			self.debug("(%s)template %s not found in %s"%(
						self._LOCALE,identifier,templatefile))


		if f==None:

			try:
				templatefile=os.path.join(self._MAILTEMPLATEDIR,
											"EN",
											"%s.html"%identifier)
				f=open(templatefile,encoding="UTF-8",errors=unicodeerror)
				self.debug("template found in %s"%templatefile)
			except:
				self.debug("(%s)template %s not found in %s"%(
				"EN",identifier,templatefile))

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

	@_dbg
	def _load_mailmaster(self,identifier,defaulttext):
		mail=self._load_rawmailmaster("00-template",
									"<html><body>%EMAILTEXT%</body></html>")
		txt=self._load_rawmailmaster(   identifier,
										defaulttext)
		return replace_variables(mail,{"EMAILTEXT":txt})

	################
	#set_pdfpassword
	################

	@_dbg
	def set_pdfpassword(self,user,password,autodelete=True):

		self._backend.set_pdfpassword(user,password,autodelete)

	################
	#get_pdfpassword
	################

	@_dbg
	def get_pdfpassword(self,user):
		return self._backend.get_pdfpassword(user)

	##############
	#set_zipcipher
	##############

	@_dbg
	def set_zipcipher(self,cipher):
		cipher=cipher.strip().upper()
		defaultciphers=["ZIPCRYPTO","AES128","AES192","AES256"]
		if not cipher in defaultciphers:
			return

		if len(cipher)>0:
			self._ZIPCIPHER=cipher.upper()

	##############
	#get_zipcipher
	##############

	@_dbg
	def get_zipcipher(self):
		return	 self._ZIPCIPHER

	#############
	#_set_logmode
	#############

	@_dbg
	def _set_logmode(self):

		self._logger._set_logmode()

	#####################
	#_store_temporaryfile
	#####################

	@_dbg
	def _store_temporaryfile(   self,
								message,
								add_deferred=False,
								spooldir=False,
								quarantinedir=False,
								fromaddr="",
								toaddr=""):
		self.debug("_store_temporaryfile add_deferred=%s"%add_deferred)

		try:
			tmpdir=None

			if add_deferred or spooldir:
				tmpdir=self._DEFERDIR
			elif quarantinedir:
				tmpdir=self._QUARANTINEDIR

			f=tempfile.NamedTemporaryFile(  mode='wb',
											delete=False,
											prefix='mail-',
											dir=tmpdir)
			f.write(message.encode("UTF-8",unicodeerror))
			f.close()

			if add_deferred:
				self._deferred_emails.append([  f.name,
												fromaddr,
												toaddr,
												time.time()])
				self._count_deferredmails+=1
				self.log("store_temporaryfile.append deferred "
							"email '%s'"%f.name)
			else:
				self.debug("Message in temporary file '%s'"%f.name)
			return f.name

		except:
			self.log("Couldn't save email in temporary file, write error")
			self.log_traceback()

		return None

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

	############
	#zip_factory
	############

	@_dbg
	def zip_factory(self):
		"returns a ZIP class"
		z= archivemanagers._ZIP(self)

		if len(self._7ZIPCMD)>0:
			z.cmd=self._7ZIPCMD

		return z

	############
	#a7z_factory
	############

	@_dbg
	def a7z_factory(self):
		"returns a ZIP class"
		z= archivemanagers._7Z(self)

		if len(self._7ZIPCMD)>0:
			z.cmd=self._7ZIPCMD

		return z

	############
	#pdf_factory
	############

	@_dbg
	def pdf_factory(self):
		"returns a PDF class"
		return _PDF(self)

	##############
	#smime_factory
	##############

	@_dbg
	def smime_factory(self):
		"returns a _SMIME class"
		return _SMIME(self,self._SMIMEKEYHOME)

	############
	#gpg_factory
	############

	@_dbg
	def gpg_factory(self):
		"returns a _GPG class"
		return _GPG(self,self._GPGKEYHOME)

	################
	#zip_attachments
	################

	@_dbg
	def zip_attachments(self,mailtext):

		if isinstance(mailtext,str):
			message = email.message_from_string( mailtext )
		else:
			message=mailtext

		tempdir = tempfile.mkdtemp()

		if self._USE7ZARCHIVE:
			Zip=self.a7z_factory()
		else:
			Zip=self.zip_factory()

		for m in message.walk():
			contenttype=m.get_content_type()

			if (is_attachment(m) ) and self.is_compressable(contenttype,
															m.get_filename()):
				is_text=m.get_content_maintype()=="text"
				charset=m.get_param("charset",header="Content-Type")

				if charset!=None:
					try:
						"test".encode(charset)
					except:
						charset="UTF-8"

				if (charset==None
				or charset.upper()=="ASCII"
				or len(charset)==0):
					charset="UTF-8"

				cte=m["Content-Transfer-Encoding"]

				if not cte:
					cte="8bit"

				filename = m.get_filename()
				filename=decode_filename(filename)
				self.debug("zipping file '%s'"%filename)

				zipFilename = "%s.zip"%filename
				zipFilenamecD,zipFilenamecT=encode_filename(zipFilename)
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
					raw_payload=decodetxt( raw_payload,
											cte,
											charset)
					m.del_param("charset")
					m.set_param("charset",charset)
					raw_payload=raw_payload.encode(charset,unicodeerror)

				fp=open(os.path.join(tempdir,filename),mode="wb")

				try:
					fp.write(raw_payload)
				except:
					self.log("File '%s' could not be written"%filename)
					self.log_traceback()

				fp.close()
				result,zipfile=Zip.create_zipfile(  tempdir,
													password=None,
													containerfile=None)

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

					m.add_header(   'Content-Disposition',
									'attachment; filename*="%s"'%zipFilenamecD)
					m.set_param( 'name', zipFilenamecT )
					m.set_payload(str(base64.encodebytes(zipfile),"ascii"))

		try:
			shutil.rmtree(tempdir)
		except:
			pass

		return message

	###################
	#_create_contentpdf
	###################

	@_dbg
	def _create_contentpdf(self,message,tempdir=None,filename=None):
		pdf=self.pdf_factory()

		if not pdf.is_available():
			self.debug("pdf not available")
			return None

		if isinstance(message,email.message.Message):
			message=message.as_string()

		fp=self._new_tempfile()
		fp.write(message.encode("UTF-8",unicodeerror))
		fp.close()
		pdf.set_filename(fp.name)
		result,pdffile=pdf.create_pdffile(None,None)
		self._del_tempfile(fp.name)

		if result==True:

			if tempdir:
				newfilename=os.path.join(tempdir,localedb(self,"content")+".pdf")
				f1,ext=os.path.splitext(newfilename)
				fncount=0

				while os.path.exists(newfilename):
					fncount+=1
					newfilename=os.path.join(tempdir,f1+str(fncount)+ext)
			else:
				f2=self._new_tempfile()
				if filename:
					newfilename=filename
				else:
					newfilename=f2.name

			fp=open(newfilename,"wb")
			fp.write(pdffile)
			fp.close()
			self.debug("set filename to '%s'"%newfilename)
			pgpFilenamecD,pgpFilenamecT=encode_filename("%s.pdf"%os.path.basename(newfilename))
			msg = MIMEBase("application","pdf")
			msg.set_payload(pdffile)

			try:
				del msg["Content-Disposition"]
			except:
				self.debug("content disposition deleted")
				self.logtraceback()

			try:
				msg.del_param("name")
			except:
				self.debug("param name deleted")
				self.logtraceback()

			msg.add_header( 'Content-Disposition',
							'attachment; filename*="%s"'%pgpFilenamecD)
			msg.set_param( 'name', pgpFilenamecT )
			email.encoders.encode_base64(msg)
			self.debug("sucessfully return payload")

			if not tempdir:
				self._del_tempfile(f2.name)

			return msg
		else:
			self.debug("result==False")
			return None

	#############
	#_handle_mail
	#############

	@_dbg
	def _handle_mail(self,message,newmsg,tempdir):
		attachments=0

		for m in message.get_payload():

				if not isinstance(m,str):
					attachments+=self._handle_part(m,newmsg,tempdir)

		return attachments

	#############
	#_handle_part
	#############

	@_dbg
	def _handle_part(self,part,newmsg,tempdir):
		contenttype=part.get_content_type()
		self.debug("_handle_partContenttype=%s"%contenttype)
		attachments=0

		if is_attachment(part) :

			if part.get_content_type()=="text/calendar":
				filename="%s.ics"%localedb(self,"appointment")
			else:
				filename = part.get_filename()

			filecounter=0

			if filename==None:
				count=""

				if filecounter>0:
					count="%i"%filecounter

				f=localedb(self,"file")
				filename=('%s%s.'%(f,count))+guess_fileextension(contenttype)
				filecounter+=1
			else:
				filename=decode_filename(filename)

			self.debug("Content-Type=%s"%contenttype)
			payload=part.get_payload(decode=True)

			if part.get_content_type()=="text/calendar":
				payload=payload.replace(b"\r\n",b"\n").replace(b"\n",b"\r\n")

			self.debug("Open write: %s/%s"%(tempdir,filename))
			newfilename=os.path.join(tempdir,filename)
			f1,ext=os.path.splitext(newfilename)
			fncount=0

			while os.path.exists(newfilename):
				fncount+=1
				newfilename=os.path.join(tempdir,f1+str(fncount)+ext)

			fp=open(newfilename,mode="wb")

			try:
				fp.write(payload)
			except:
				self.log("File '%s' could not be written"%filename)
				self.log_traceback()

			fp.close()
			attachments+=1
		elif (part.get_content_maintype()!="multipart"):
			#add all none-attachment payloads
			self.debug("contenttype not multipart (%s)"%type(part.get_payload()))
			newmsg.attach(part)
		elif part.get_content_type()=="multipart/alternative":
			self.debug("contenttype multipart alternative ")
			alternative=MIMEMultipart(_subtype="alternative")

			for pl in part.get_payload():

				ct=pl.get_content_type()
				self.debug("ct %s"%ct)

				if pl.get_param( 'inline',
									None,
									'Content-Disposition' ) is not None:
					self.debug("handle inline payload 1")

					if pl.get_content_maintype()!="text":
						attachments+=self._handle_mail(pl,newmsg,tempdir)
					else:
						alternative.attach(pl)

				elif ct=="text/calendar":
					attachments+=self._handle_part(pl,newmsg,tempdir)
				elif ct=="multipart/related":
					self.debug("handle multipartrelated payload")

					for pl2 in pl.walk():
						self.debug("multipart/related payload")
						self.debug("is string %s"% isinstance(pl2,str))

						if not isinstance(pl2,str):

							if pl2.get_content_type()=="multipart/related":
								self.debug("multipart/related continue")
								continue

						if (not isinstance(pl2,str)) and pl2.get_param( 'inline',
											None,
											'Content-Disposition' ) is not None:
							self.debug("handle inline")
							attachments+=self._handle_part(pl2,newmsg,tempdir)
						else:
							self.debug("add non inline attachment ")
							alternative.attach(pl2)

				else:
					self.debug("attach alternative payload")
					alternative.attach(pl)

			newmsg.attach(alternative)

		elif part.get_content_maintype()=="multipart":
			self.debug("other multipart parts (%s)"%part.get_content_type())
			attachments+=self._handle_mail(part,newmsg,tempdir)

		else:
			self.debug("ignore payload")

		return attachments


	###############################
	# zip_attachments_one_container
	###############################

	@_dbg
	def zip_attachments_one_container(   self,
							message,
							gpguser,
							from_addr,
							to_addr,
							include_contentpdf=False):

		if isinstance(message,str):
			message=email.message_from_string(message)

		newmsg=MIMEMultipart()
		self._copy_headers(message,newmsg)
		attachments=0
		tempdir = tempfile.mkdtemp()
		contenttype=message.get_content_type()
		self.debug("Message CONTENTTYPE %s"%contenttype)
		filecounter=0

		if self._USE7ZARCHIVE:
			Zip=self.a7z_factory()
		else:
			Zip=self.zip_factory()

		if include_contentpdf:
			msg=self._create_contentpdf(message,tempdir)

			if msg!=None:
				attachments+=1
				message=self._make_multipart_mixed_message(message)
				
		if not message.is_multipart():
			self.debug("message is not multipart return")
			return message
		
		attachments+=self._handle_mail(message,newmsg,tempdir)

		if attachments<1:
			self.debug("no attachment")
			return message

		result,zipfile=Zip.create_zipfile(tempdir)
		self.debug("create_zipfile result=%s"%str(result))

		if result==True:

			if self._USE7ZARCHIVE:
				extension="7z"
			else:
				extension="zip"

			msg= MIMEBase("application", extension)
			msg.set_payload(zipfile)
			f=localedb(self,"attachment")
			filenamecD,filenamecT=encode_filename("%s.%s"%(f,extension))
			msg.add_header( 'Content-Disposition',
							'attachment; filename*="%s"' % filenamecD)
			msg.set_param( 'name', filenamecT )
			email.encoders.encode_base64(msg)
			newmsg.attach(msg)

		try:
			shutil.rmtree(tempdir)
		except:
			self.log("Couldn't delete tempdir '%s'"%tempdir)
			self.log_traceback()

		if not self._pdfencryptheader in newmsg:
			newmsg.add_header(self._pdfencryptheader,self._encryptgpgcomment)

		#save_txtfile("~/01.eml",newmsg.as_string())
		return newmsg

	################
	#is_compressable
	################

	@_dbg
	def is_compressable(self,
						filetype,
						filename):
		try:
			maintype,subtype=filetype.lower().split("/")
		except:
			return False

		f, extension = os.path.splitext(filename.lower())
		extension=extension[1:]

		if filename in ["winmail.dat","win.dat","signature.asc"]:
			return False

		if maintype=="video":
			return False

		if maintype=="text" and subtype=="calendar":
			return False

		if maintype=="image":

			if subtype in ["bmp","x-windows-bmp","svg+xml","tiff",
					"photoshop","x-photoshop","psd"]:
				return True
			#raw image format
			elif extension in [
					"3fr","ari","arw","bay","crw","cr2","cap","dcs","dcr","dng",
					"drf","eip","erf","fff","iiq","k25","kdc","mdc","mef","mos",
					"mrw","nef","nrw","obm","orf","pef","ptx","pxn","r3d","raf",
					"raw","rwl","rw2","rwz","sr2","srf","srw","tif","x3f"]:
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
			if subtype in ["zip","x-compressed","x-compress","x-gzip",
						  "x-gtar","x-lzip","x-lzma","x-lzh","x-lzip",
						  "x-lzop","x-zoo","x-rar-compressed","java-archive",
						  "x-7z-compressed","x-bzip","x-bzip2",
						  "vnd.android.package-archive","x-snappy-framed",
						  "x-xz","x-ace-compressed","x-astrotite-afa",
						  "x-alz-compressed","x-b1","x-dar","x-dgc-compressed",
						  "x-apple-diskimage","x-apple-diskimage","x-lzx",
						  "x-arj","vnd.ms-cab-compressed","x-cfs-compressed",
						  "x-stuffit","x-stuffitx"]:
				return False
			#compressed Microsoft Office formats
			elif subtype in [
			"application/vnd.openxmlformats-officedocument."
								"wordprocessingml.document",
			"application/vnd.openxmlformats-officedocument."
								"spreadsheetml.sheet",
			"application/vnd.openxmlformats-officedocument."
								"presentationml.presentation"]:
				return False
			#Openoffice/LibreOffice
			elif subtype in ["vnd.oasis.opendocument.text",
							 "vnd.oasis.opendocument.spreadsheet",
							 "vnd.oasis.opendocument.presentation",
							 "vnd.oasis.opendocument.graphics",
							 "vnd.oasis.opendocument.chart",
							 "vnd.oasis.opendocument.formula",
							 "vnd.oasis.opendocument.image",
							 "vnd.oasis.opendocument.text-master",
							 "vnd.oasis.opendocument.text-template",
							 "vnd.oasis.opendocument.spreadsheet-template",
							 "vnd.oasis.opendocument.presentation-template",
							 "vnd.oasis.opendocument.graphics-template"]:
				return False
			#Miscellaneous
			elif subtype in ["epub+zip","vnd.gov.sk.e-form+zip"]:
				return False
			extension=extension[1:]

			#same as above, just over the file extension
			if subtype=="octet-stream":
				if extension in [
					#Images
					"jpg","jpeg","png","gif","jif","jfif","jp2","j2k","jpx",
					"j2c","psd",
					#Videos
					"mpeg","mpg","mpe","mpgv","mp4","mpg4","mov","avi","mkv",
					"swf","flv","f4v","f4p","f4a","f4b","wmv","ogv","m2t",
					"mjpeg","3gp","asx","m4v","rv","swz","rm","m2v","mv4",
					"xwmv","3ga","mp3","ogg",
					#Archives
					"zip","zipx","arj","cpio","dar","deb","tgz","bz2","bz","gz",
					"7z","s7z","7zip","ar","xar","cpio","kgb","lrz","lz","lzh",
					"lha","lzo","lzma","rar","xz","apk","tgz","tbz","tbz2",
					"tlz","txz","cab","rpm","sz","snappy","jar","z",
					"zoo","zpaq",
					#Office
					"docx","xlsx","pptx","ods","odt","odp","ott","odm","oth",
					"ots","odg","otg","odf","odb","oxt","odg","odc","odi",
					#Miscellaneous
					"epub","ics"
					]:
					return False
		return True

	#############
	#_send_rawmsg
	#############

	@_dbg
	def _send_rawmsg(   self,
						m_id,
						message,
						msg,
						from_addr,
						to_addr):

		if isinstance(message,str):
			message = email.message_from_string( message )

		if self._ADDHEADER and not self._encryptheader in message and msg:
			message.add_header(self._encryptheader,msg)

		return self._send_msg(	m_id,
						message,
						from_addr,
						to_addr)

	##########
	#_send_msg
	##########

	@_dbg
	def _send_msg(  self,
					m_id,
					message,
					from_addr,
					to_addr):
		self.debug("_send_msg output %i"%self._OUTPUT)

		if isinstance(message,str):
			return self._send_textmsg(	m_id,
								message,
								from_addr,
								to_addr)
		else:

			if self._ADDHEADER and not self._encryptheader in message:
				message.add_header(self._encryptheader,self._encryptgpgcomment)

			return self._send_textmsg(	m_id,
								message.as_string(),
								from_addr,
								to_addr)

	##############
	#_send_textmsg
	##############

	@_dbg
	def _send_textmsg(  self,
						m_id,
						message,
						from_addr,
						to_addr,
						store_deferred=True):
		self.debug("_send_textmsg output %i"%self._OUTPUT)
		domain=maildomain(from_addr)
		usessl=False

		if not isinstance(message,str):
			message=message.as_string()

		if self._USEDKIM and (domain in self._HOMEDOMAINS):
				message=self._dkim.sign_mail(message)

		if self._OUTPUT==self.o_mail:

			if len(to_addr) == 0:
				self.log("Couldn't send email, recipient list is empty!","e")
				return False

			self.debug("Sending email to: <%s>" % to_addr)

			if self._SECURITYLEVEL==self.s_redirect:
				_HOST=self._SMTP_HOST2
				_PORT=self._SMTP_PORT2
				_USESMTPS=self._SMTP_USESMTPS2
				_AUTHENTICATE=self._SMTP_AUTHENTICATE2
				_USER=self._SMTP_USER2
				_PASSWORD=self._SMTP_PASSWORD2
				_CACERTS=self._SMTP_CACERTS2
				_VERIFYCERT=self._SMTP_VERIFYCERT2
			else:
				_HOST=self._SMTP_HOST
				_PORT=self._SMTP_PORT
				_USESMTPS=self._SMTP_USESMTPS
				_AUTHENTICATE=self._SMTP_AUTHENTICATE
				_USER=self._SMTP_USER
				_PASSWORD=self._SMTP_PASSWORD
				_CACERTS=self._SMTP_CACERTS
				_VERIFYCERT=self._SMTP_VERIFYCERT

			if not _VERIFYCERT:
				sslcontext=ssl.create_default_context(cafile=_CACERTS)
				sslcontext.check_hostname = False
				sslcontext.verify_mode=ssl.CERT_NONE

			elif _CACERTS==None:
					sslcontext=None
			else:
				sslcontext=ssl.create_default_context(cafile=_CACERTS)

			try:

				if _USESMTPS:
					smtp = smtplib.SMTP_SSL(_HOST,
											_PORT,
											context=sslcontext)
					usessl=True
				else:
					smtp = smtplib.SMTP(_HOST, _PORT)

				smtp.ehlo_or_helo_if_needed()

				try:

					if smtp.has_extn("starttls"):
						self.debug("_send_textmsg starttls")
						smtp.starttls(context=sslcontext)
						smtp.ehlo_or_helo_if_needed()
						usessl=True

				except:
					self.debug("smtp.starttls on server failed")
					self.log_traceback()

					if store_deferred:
						self._store_temporaryfile(  message,
													add_deferred=True,
													fromaddr=from_addr,
													toaddr=to_addr)
						self._remove_mail_from_queue(m_id)

					return False

				if usessl:
					cert=ssl.DER_cert_to_PEM_cert(smtp.sock.getpeercert(True))
					fingerprint=get_certfingerprint(cert,self)
					self.debug("CERT fingerprint='%s'"%fingerprint)

					if len(self._SMTP_CERTFINGERPRINTS)>0:

						if not fingerprint in self._SMTP_CERTFINGERPRINTS:
							self.log("Wrong Certificate fingerprint!","e")
							return False
						else:
							self.debug("CERT fingerprint ok.")

				if _AUTHENTICATE and smtp.has_extn("auth"):
					self.debug("_send_textmsg: authenticate at smtp server"
					" with user %s"%_USER)

					try:
						smtp.login(_USER,_PASSWORD)
					except smtplib.SMTPAuthenticationError:
						self.log("Could not send email, could not "
								 "authenticate","e")
						self.debug( "_send_textmsg: store_deferred"
									" %s" % store_deferred)

						if store_deferred:
							self._store_temporaryfile(  message,
														add_deferred=True,
														fromaddr=from_addr,
														toaddr=to_addr)
						return False

				self.debug("smtp.sendmail")
				message=re.sub(r'(?:\r\n|\n|\r(?!\n))', "\r\n", message)
				smtp.sendmail( from_addr, to_addr, message.encode("UTF-8",
																unicodeerror) )
				self._remove_mail_from_queue(m_id)
				return True

			except:
				self.log("Couldn't send mail!","e")
				self.log_traceback()
				self.debug("store_deferred %s"%store_deferred)

				if store_deferred:
					self._store_temporaryfile(  message,
												add_deferred=True,
												fromaddr=from_addr,
												toaddr=to_addr)
					self._remove_mail_from_queue(m_id)

				return False
		elif (self._OUTPUT==self.o_file
			and self._OUTFILE
			and len(self._OUTFILE)>0):

			try:
				fname=self._OUTFILE
				f1,ext=os.path.splitext(self._OUTFILE)
				if self._mailcount>0:
					fname=f1+str(self._mailcount)+ext

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

	################
	#load_virus_list
	################

	@_dbg
	def load_virus_list(self):
		"loads the list with virus infected emails"
		self._virus_queue=[]

		try:
			f=open(self._VIRUSLIST,encoding="UTF-8",errors=unicodeerror)

			for l in f:
				mail=l.split("|")

				try:
					mail[3]=float(mail[3])
				except:
					mail[3]=-1
					self.log("load_viruslist, id could not be converted"
							" to float","e")

				self._virus_queue.append(mail)

			f.close()
			self._count_viruses=len(self._virus_queue)
		except:
			self.log("Couldn't load viruslist list '%s'"%self._VIRUSLIST)

	###################
	#load_deferred_list
	###################

	@_dbg
	def load_deferred_list(self):
		"loads the list with deferred emails, that have to be sent later"
		self._deferred_emails=[]

		try:
			f=open(self._DEFERLIST,encoding="UTF-8",errors=unicodeerror)

			for l in f:
				mail=l.split("|")

				try:
					mail[3]=float(mail[3])
				except:
					mail[3]=-1
					self.log("load_defer list, id could not be converted"
							" to float","e")

				self._deferred_emails.append(mail)

			f.close()
			self._count_deferredmails=len(self._deferred_emails)
		except:
			self.log("Couldn't load defer list '%s'"%self._DEFERLIST)

	####################
	#store_deferred_list
	####################

	@_dbg
	def store_deferred_list(self):
		"stores the list with deferred emails, that have to be sent later"

		try:
			self.debug("store_deferred_list '%s'"%self._DEFERLIST)
			f=open(	self._DEFERLIST,mode="w",
					encoding="UTF-8",errors=unicodeerror)

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
			self.log("Couldn't store defer list '%s'"%self._DEFERLIST)
			self.log_traceback()
		self.store_virus_list()

	####################
	#store_virus_list
	####################

	@_dbg
	def store_virus_list(self):
		"stores the list with emails, that contain viruses"

		try:
			self.debug("store_virus_list '%s'"%self._VIRUSLIST)
			f=open(self._VIRUSLIST,mode="w",
					encoding="UTF-8",errors=unicodeerror)

			for mail in self._virus_queue:
				mail[3]=str(mail[3])
				f.write("|".join(mail))
				f.write("\n")

			f.close()
		except:
			self.log("Couldn't store virus list '%s'"%self._VIRUSLIST)
			self.log_traceback()

	######################
	#_is_old_deferred_mail
	######################

	@_dbg
	def _is_old_deferred_mail(self,mail):
		_maxage=3600*48 #48 hrs
		now=time.time()

		if (now - mail[3]) > _maxage:
			self.log("Deferred mail '%s' will be removed because "
						"of age"%mail[0])

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
				f=open(mail[0],encoding="UTF-8",errors=unicodeerror)
				msg=f.read()
				f.close()

				if not self._send_textmsg(  -1,
											msg,
											mail[1],
											mail[2],
											store_deferred=False):

					if not self._is_old_deferred_mail(mail):
						new_list.append(mail)

				else:
					self.log("Deferred mail successfully sent from %s to %s"%(
												mail[1],
												mail[2]))

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
				f=open(mail[0],mode="rb")
				m=f.read()
				f.close()
				mailtext=m.decode("UTF-8",unicodeerror)
				self._encrypt_single_mail(-1,mailtext,mail[1],mail[2])
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
		self.log("Version: %s Uptime:  %s"%(VERSION,self.get_uptime()))
		self.log("Mail statistics: total: %i, encrypt: %i, were encrypted:"
		" %i" %(
				self._count_totalmails,
				self._count_encryptedmails,
				self._count_alreadyencryptedmails))
		self.log("PGPMIME: %i, PGPINLINE: %i, SMIME: %i, PDF: %i"%(
				self._count_pgpmimemails,
				self._count_pgpinlinemails,
				self._count_smimemails ,
				self._count_pdfmails))
		self.log("Decrypted mails: %i"%(self._count_decryptedemails))
		self.log("total deferred: %i, still deferred: %i" %(
				self._count_deferredmails,
				len(self._deferred_emails)))
		self.log("Systemerrors: %i, systemwarnings: %i" %(
				self._systemerrors,
				self._systemwarnings))
		self.log("Virus infected mails: %i" %self._count_viruses)
		self.log("Spam mails: %i, maybe spam: %i" %(
				self._count_spam,
				self._count_maybespam))

	##############
	#_new_tempfile
	##############

	@_dbg
	def _new_tempfile(self,delete=False):
		"creates a new tempfile"
		f=tempfile.NamedTemporaryFile(  mode='wb',
										delete=delete,
										prefix='mail-')
		self._tempfiles.append(f.name)
		self.debug("_new_tempfile %s"%f.name)
		return f

	##############
	#_del_tempfile
	##############

	@_dbg
	def _del_tempfile(self,f):
		"deletes the tempfile, f is the name of the file"

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
			msg=msg.as_string()

		find=re.search(
			"^Content-Type:.*(\r)*\n(^\s+.*(\r)*\n)*",
			msg,
			re.I|re.MULTILINE)

		if find==None:
			return None

		contenttype=msg[find.start():find.end()]
		find=re.search(
					"charset=[-_\.\'\"0-9A-Za-z]+",
					contenttype,
					re.I|re.MULTILINE|re.S)

		if not find:
			return None

		charset=contenttype[find.start():find.end()]
		res=charset.split("=")

		if len(res)<2:
			return None

		charset=str(res[1]).replace('"','').replace("'","").strip()
		self.debug("_find_charset:`%s` from `%s`"%(charset,res))
		return charset

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

		self._OUTFILE=os.path.expanduser(mailfile)
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

		self._logger.set_debug(dbg)

	##########
	#get_debug
	##########

	@_dbg
	def get_debug(self):
		return self._logger.get_debug()

	###########
	#set_locale
	###########

	@_dbg
	def set_locale(self,l):
		"sets the locale"

		if isinstance(l,str):
			l=l.strip()

			if len(l)>0:
				self._LOCALE=l.upper()

	##################
	#set_check_viruses
	##################

	@_dbg
	def set_check_viruses(self,c):
		self._VIRUSCHECK=c
		self._virus_checker=None

	##################
	#get_check_viruses
	##################

	@_dbg
	def get_check_viruses(self):
		return self._VIRUSCHECK

	###################
	#get_quarantinelist
	###################

	@_dbg
	def get_quarantinelist(self):
		return self._virus_queue

	##################
	#quarantine_remove
	##################

	@_dbg
	def quarantine_remove(self,v_id):
		res=None

		for i in self._virus_queue:

			try:

				if float(i[3])==v_id:
					res=i

					try:
						os.remove(i[0])
					except:
						self.log_traceback()
					break

			except:
				self.log("quarantine_remove, could not convert float","w")

		if res:

			try:
				self._virus_queue.remove(res)
				self.log("quarantine remove %f"%v_id)
			except:
				self.log_traceback()

		self._count_viruses=len(self._virus_queue)

		if res:
			return True
		else:
			return False

	###################
	#quarantine_release
	###################

	@_dbg
	def quarantine_release(self,v_id):
		res=None

		for i in self._virus_queue:

			try:

				if float(i[3])==v_id:
					res=i
					break

			except:
				self.log("quarantine_release, could not convert float","w")

		if res:

			with open(res[0],encoding="UTF-8",errors=unicodeerror) as f:
				mail=f.read()

			self._send_textmsg(	m_id=-1,
								message=mail,
								from_addr=res[1],
								to_addr=res[2])
			self._count_viruses=len(self._virus_queue)

		return self.quarantine_remove(v_id)

	###################
	#quarantine_forward
	###################

	@_dbg
	def quarantine_forward(self,v_id,to_addr):
		res=None

		for i in self._virus_queue:

			try:

				if float(i[3])==v_id:
					res=i
					break

			except:
				self.log("quarantine_forward, could not convert float","w")

		if res:

			with open(res[0],encoding="UTF-8",errors=unicodeerror) as f:
				mail=f.read()

			m=email.message_from_string(mail)
			del m["To"]
			m["To"]=to_addr

			self._send_textmsg(	m_id=-1,
								message=m.as_string(),
								from_addr=res[1],
								to_addr=to_addr)
			self._count_viruses=len(self._virus_queue)

		return self.quarantine_remove(v_id)

	#####################
	#del_old_virusmails
	#####################

	@_dbg
	def del_old_virusmails(self):
		delmail=[]

		if self._VIRUSLIFETIME<=0:
			return

		for mail in self._virus_queue:

			try:
				date=float(mail[3])

				if date>0 and (date + self._VIRUSLIFETIME < time.time()):
					delmail.append(mail)

			except:
				self.log_traceback()

		for mail in delmail:

			try:

				if self.quarantine_remove(float(mail[3])):
					self.debug("Old virus mail '%s' deleted"%mail)

			except:
				self.log_traceback()

	#############################
	#set_virusquarantine_lifetime
	#############################

	@_dbg
	def set_virusquarantine_lifetime(self,lifetime):
		"""sets the lifetime of infected mails in the quarantine in second
		0 deactivates automatic deletion
		"""
		self._VIRUSLIFETIME=lifetime

	#############################
	#get_virusquarantine_lifetime
	#############################

	@_dbg
	def get_virusquarantine_lifetime(self):
		"returns the quarantine lifetime of infected mails"
		return self._VIRUSLIFETIME

	###############
	#set_check_spam
	###############

	@_dbg
	def set_check_spam(self,c):
		self._SPAMCHECK=c

	###############
	#get_check_spam
	###############

	@_dbg
	def get_check_spam(self):
		return self._SPAMCHECK

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
			"deferred total":self._count_deferredmails,
			"deferred still":len(self._deferred_emails),
			"total already encrypted":self._count_alreadyencryptedmails,
			"total smime":self._count_smimemails,
			"total pdf":self._count_pdfmails,
			"total pgpmime":self._count_pgpmimemails,
			"total pgpinline":self._count_pgpinlinemails,
			"total decrypted":self._count_decryptedemails,
			"systemerrors":self._systemerrors,
			"systemwarnings":self._systemwarnings,
			"virus infected mails":self._count_viruses,
			"spam mails":self._count_spam,
			"spam mails maybe":self._count_maybespam,
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
		return self._logger.is_debugging()

	################################
	#set_default_preferredencryption
	################################

	@_dbg
	def set_default_preferredencryption(self,mode):
		"set the default preferred encryption. "
		"Valid values are SMIME,PGPMIME,PGPINLINE"

		if isinstance(mode,str):
			m=mode.upper()

			if m in ["SMIME","PGPMIME","PGPINLINE"]:
				self._PREFERRED_ENCRYPTION=mode.upper()

	#########
	#set_smtp
	#########

	@_dbg
	def set_smtp(   self,
					host,
					port,
					auth=False,
					user="",
					password=""):
		"""sets the smtp setting for sending emails (don't mix it up with
		the daemon settings where the server listens)"""
		self._SMTP_HOST=host
		self._SMTP_PORT=port
		self._SMTP_AUTHENTICATE=auth
		self._SMTP_USER=user
		self._SMTP_PASSWORD=password

	###########
	#set_daemon
	###########

	@_dbg
	def set_daemon( self,
					host,
					port,
					smtps=False,
					auth=False,
					sslkeyfile=None,
					sslcertfile=None):
		"sets the smtpd daemon settings"
		self._SMTPD_HOST=host
		self._SMTPD_PORT=port
		self._SMTPD_USE_SMTPS=smtps
		self._SMTPD_USE_AUTH=auth

		if sslkeyfile:
			self._SMTPD_SSL_KEYFILE=sslkeyfile

		if sslcertfile:
			self._SMTPD_SSL_CERTFILE=sslcertfile

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
	def check_gpgrecipient(self,gaddr, from_addr=None):
		"""returns True and the effective key-emailaddress if emails
		to address 'gaddr' can be GPG encrypted"""
		self.debug("check_gpgrecipient: start '%s'"%gaddr)
		domain=maildomain(gaddr)
		found =False
		gpg = self.gpg_factory()

		try:
			gpg_to_addr=self._backend.usermap(gaddr)
		except:
			self.debug("_addressmap to_addr not found")
			gpg_to_addr=gaddr

		if maildomain(from_addr) in self._HOMEDOMAINS:
			gpg.set_fromuser(from_addr)

		if gpg.has_public_key(gpg_to_addr):

			if (
				(len(self._DOMAINS)>0
				and domain in self._DOMAINS.split(',')
				)
			or len(self._DOMAINS)==0):
				found=True
				self.debug("check_gpgrecipient: after in_key")
			else:
				self.debug("gpg key exists, but '%s' is not in "
							"_DOMAINS [%s]"%(domain,self._DOMAINS))

		return found,gpg_to_addr

	#####################
	#check_smimerecipient
	#####################

	@_dbg
	def check_smimerecipient(self,saddr, from_addr=None):
		"""returns True and the effective key-emailaddress if emails
		to address 'saddr' can be SMIME encrypted"""
		self.debug("check_smimerecipient: start '%s'"%saddr)
		domain=maildomain(saddr)
		found =False
		smime = self.smime_factory()

		try:
			smime_to_addr=self._backend.usermap(saddr)
		except:
			self.debug("smime _addressmap to_addr not found")
			smime_to_addr=saddr

		self.debug("check_smimerecipient '%s'"%smime_to_addr)

		if smime.has_public_key(smime_to_addr):
			found=True
			self.debug("check_smimerecipient FOUND")

			if ((len(self._DOMAINS)>0
				and domain in self._DOMAINS.split(','))
				or len(self._DOMAINS)==0):
				self.debug("check_smimerecipient: after in_key")
			else:
				self.debug("smime key exists, but '%s' is not in "
							"_DOMAINS [%s]"%(domain,self._DOMAINS))
				found=False

		return found, smime_to_addr

	#####################
	#check_encryptsubject
	#####################

	@_dbg
	def check_encryptsubject(self,mailtext):

		if isinstance(mailtext,str):
			mail=email.message_from_string(mailtext)
		else:
			mail=mailtext

		subject=self._decode_header(mail["Subject"])
		self.debug("subject: %s"%mail["Subject"])

		if subject==None:
			return False

		find=re.search("^#encrypt ",subject,re.I)

		if find:
			return True
		else:
			return False

	####################
	#_pgpinlineencrypted
	####################

	@_dbg
	def _pgpinlineencrypted(self,msg):

		if msg ==None:
			return False

		if type(msg)==bytes:
			return False

		if isinstance(msg,email.message.Message):
			msg=msg.as_string()

		cre = re.compile('^-----BEGIN PGP MESSAGE-----.*?'
		'^-----END PGP MESSAGE-----', re.MULTILINE|re.DOTALL)

		if cre.search(msg):
			return True
		else:
			return False

	######################
	#is_pgpinlineencrypted
	######################

	@_dbg
	def is_pgpinlineencrypted(self,msg):
		"returns whether or not the email is already PGPINLINE encrypted"

		if self.is_pgpmimeencrypted(msg):
			return False

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

				if self._pgpinlineencrypted(decodetxt(m.get_payload(),
											cte,
											charset)):
					return True

		return False

	####################
	#is_pgpmimenecrypted
	####################

	@_dbg
	def is_pgpmimeencrypted(self,msg):
		"returns whether or not the email is already PGPMIME encrypted"

		if type(msg)==bytes:
			return False

		m=msg

		if isinstance(msg,email.message.Message):
			m=msg.as_string()

		find=re.search("^Content-Type: multipart/encrypted",
						m,
						re.I|re.MULTILINE)
		find2=None

		if find:
			find2=re.search("application/pgp-encrypted",
						m[find.end():],
						re.I|re.MULTILINE)

		if find2:
			return True
		else:
			return False

	##################
	#is_smimeencrypted
	##################

	@_dbg
	def is_smimeencrypted(self,msg):
		"returns whether or not the email is already SMIME encrypted"

		if type(msg)==bytes:
			return False

		m=msg

		if isinstance(msg,email.message.Message):
			m=msg.as_string()

		find=re.search("^Content-Type: application/pkcs7-mime",
						m,
						re.I|re.MULTILINE)

		if find:
			return True
		else:
			return False

	################
	#is_pdfencrypted
	################

	@_dbg
	def is_pdfencrypted(self,msg):
		"returns whether or not the email is already PDF encrypted"

		if type(msg)==bytes:
			return False

		pdf=self.pdf_factory()
		m=msg

		if not isinstance(msg,email.message.Message):
			m=email.message_from_string(msg)

		if isinstance(m,list):
			p=m
		else:
			p=m.walk()

		for payload in p:

			if payload.get_content_type()=="application/pdf":
				raw_payload = payload.get_payload(decode=True)
				fp=self._new_tempfile()
				fp.write(raw_payload)
				fp.close()

				try:
					r=pdf.is_encrypted(fp.name)
				except:
					self.log("is_pdfencrypted failed","w")
					self._del_tempfile(fp.name)
					return False

				self._del_tempfile(fp.name)

				if r==True:
					return True

		return False

	#############
	#is_encrypted
	#############

	@_dbg
	def is_encrypted(self,msg):
		"returns whether or not the email is already encrypted"

		if (self.is_pgpmimeencrypted(msg)
		or self.is_pgpinlineencrypted(msg)
		or self.is_smimeencrypted(msg)
		or self.is_pdfencrypted(msg)):
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
				body=decode_html(self,body[0:res.start()])
		else:
			body=decode_html(self,_r)

		return result,header,body,footer

	#################
	#_encrypt_payload
	#################

	@_dbg
	def _encrypt_payload(   self,
							payload,
							gpguser,
							from_addr,
							counter=0 ):
		htmlheader=""
		htmlbody=""
		htmlfooter=""
		charset=payload.get_param("charset",header="Content-Type")
		is_text=payload.get_content_maintype()=="text"
		cte=payload["Content-Transfer-Encoding"]

		if not cte:
			cte="8bit"

		self.debug("_encrypt_payload: charset %s"%charset)

		if charset!=None:

			try:
				"test".encode(charset)
			except:
				charset="UTF-8"

		if charset==None or charset.upper()=="ASCII" or len(charset)==0:
			charset="UTF-8"

		gpg =self.gpg_factory()
		gpg._set_counter(counter)
		gpg.set_recipient(gpguser)
		gpg.set_fromuser(from_addr)
		raw_payload = payload.get_payload(decode=not is_text)
		contenttype=payload.get_content_type()
		self.debug("nach payload.get_content_typ")
		self.debug("Content-Type:'%s'"%contenttype)

		if is_text:

			if contenttype=="text/html":

				if "ascii" in charset.lower():
					charset="UTF8"

			raw_payload=decodetxt(raw_payload,cte,charset)
			payload.del_param("charset")
			payload.set_param("charset",charset)

		fp=self._new_tempfile()
		self.debug("_encrypt_payload _new_tempfile %s"%fp.name)
		filename = payload.get_filename()

		if filename:
			filename=decode_filename(filename)

		tencoding="7bit"

		if contenttype=="text/html":
			res,htmlheader,htmlbody,htmlfooter=self._split_html(raw_payload)
			fp.write(htmlbody.encode(charset,unicodeerror))
		else:

			if is_text:

				try:
					raw_payload.encode("ascii")
				except:
					tencoding="8bit"

				raw_payload=raw_payload.encode(charset,unicodeerror)

			fp.write(raw_payload)

		fp.close()
		isAttachment = payload.get_param(   'attachment',
											None,
											'Content-Disposition' ) is not None
		isInline=payload.get_param( 'inline',
									None,
									'Content-Disposition' ) is not None
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

		if ( isAttachment
		or (isInline and contentmaintype not in ("text") )):
			self.debug("ENCRYPT PAYLOAD ATTACHMENT")
			addPGPextension=True

			if filename==None:
				count=""

				if counter>0:
					count="%i"%counter

				f=localedb(self,"file")
				filename=('%s%s.'%(f,count))+guess_fileextension(contenttype)

			f,e=os.path.splitext(filename)
			addPGPextension=(e.lower()!=".pgp")

			if filename and addPGPextension:
				pgpFilename = filename + ".pgp"
			else:
				pgpFilename=filename

			self.debug("Filename:'%s'"%filename)
			pgpFilenamecD,pgpFilenamecT=encode_filename(pgpFilename)
			isBinaryattachment=(contentmaintype!="text")

			if addPGPextension:
				self.debug("addPGPextension gpg.encrypt_file")
				result,pl=gpg.encrypt_file(binary=isBinaryattachment)
			else:
				result=False

			if result==True:

				if isBinaryattachment:
					payload.set_payload(str(base64.encodebytes(pl),"ascii"))

					try:
						del payload["Content-Transfer-Encoding"]
					except:
						pass

					payload["Content-Transfer-Encoding"]="base64"
				else:
					payload.set_payload(pl)

					if 'Content-Transfer-Encoding' in payload:
						del payload['Content-Transfer-Encoding']

					payload["Content-Transfer-Encoding"]="8bit"

				payload.set_type( 'application/octet-stream')

				if payload["Content-Disposition"]:
					del payload["Content-Disposition"]

				payload.add_header( 'Content-Disposition',
									'attachment; filename*="%s"'%pgpFilenamecD)
				payload.set_param( 'name', pgpFilenamecT )
		else:

			if 'Content-Transfer-Encoding' in payload:
				del payload['Content-Transfer-Encoding']

			payload["Content-Transfer-Encoding"]="8bit"
			result,pl=gpg.encrypt_file(binary=False)

			if result==True:

				if contenttype=="text/html":
					pl=(htmlheader+"\n<br>\n"
						+re.sub('\n',"<br>\n",pl)
						+"<br>\n"
						+htmlfooter)

				if "Content-Transfer-Encoding" in payload:
					del payload["Content-Transfer-Encoding"]

				payload["Content-Transfer-Encoding"]=tencoding
				payload.set_payload(pl)
			else:
				self.log("Error during encryption: payload will be "
						"unencrypted!","m")
				payload= None

		self._del_tempfile(fp.name)
		return payload

	###########
	#_split_msg
	###########

	@_dbg
	def _split_msg(self,message):
		"""returns header and body separated, None in both cases if an error
		occured"""

		if isinstance(message,str):
			raw_message=email.message_from_string(message)
		else:
			raw_message=message

		splitmsg=re.split("\n\n",raw_message.as_string(),1)

		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",raw_message.as_string(),1)

		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part "
						"(mailsize=%i)"%len(raw_message.as_string()))
			return None,None

		header,body=splitmsg
		header+="\r\n\r\n"
		return header,body

	##########################################
	#_change_stringpayload_to_multipartpayload
	##########################################

	@_dbg
	def _change_stringpayload_to_multipartpayload(self,message):

		if not isinstance(message.get_payload(),str):
			return None

		self.debug("message payload is str")
		maintype=message.get_content_maintype()
		subtype=message.get_content_subtype()
		is_attachment=False
		filename=message.get_filename()

		if filename:
			filename=decode_filename(filename)
		
		try:
			cf=message["Content-Disposition"]

			if "attachment" in cf.lower():
				is_attachment=True
		except:
			pass

		if maintype == 'text':
			charset=message.get_param("charset")

			if charset==None:
				self.debug("charset==None")
				charset="UTF8"

			self.debug("charset %s"%charset)
			self.debug("maintype==text")

			if message['Content-Transfer-Encoding'] == '8bit':
				content=message.get_payload(decode=False).encode("UTF8")

			else:

				is_text=message.get_content_maintype()=="text"
				cte=message["Content-Transfer-Encoding"]
				content = message.get_payload(decode=not is_text)

				if is_text:
					content=decodetxt(content,cte,charset)

			msg = MIMEText(content,
					_subtype=subtype,_charset=charset)
		elif maintype == 'image':
			self.debug("maintype==image")
			msg = MIMEImage(message.get_payload(decode=True), _subtype=subtype)
		elif maintype == 'audio':
			self.debug("maintype==audio")
			msg = MIMEAudio(message.get_payload(decode=True), _subtype=subtype)
		else:
			self.debug("maintype== other ('%s')"%maintype)
			msg = MIMEBase(maintype, subtype)
			msg.set_payload(message.get_payload(decode=True))

		if is_attachment:

				if 'Content-Disposition' not in msg:
					msg.add_header('Content-Disposition', 'attachment',
					filename=filename)

		return msg

	##############
	#_copy_headers
	##############

	@_dbg
	def _copy_headers(self, oldmessage,newmessage):
		keys=[]

		for k in oldmessage.keys():

			if k in keys:
				continue
			else:
				keys.append(k)

			for p in oldmessage.get_all(k):
				if k != "Content-Type" and k!="MIME-Version":
					newmessage.add_header(k,p)

	##############################
	#_make_multipart_mixed_message
	##############################

	@_dbg
	def _make_multipart_mixed_message(self, message):

		if isinstance(message,str):
			self.debug("message is string, converting ...")
			message=email.message_from_string(message)

		contenttype=message.get_content_type()
		self.debug("CONTENTTYPE %s"%contenttype)

		if contenttype=="multipart/mixed":
			self.debug("message is already multipart/mixed")
			return message

		newmsg=MIMEMultipart()
		self._copy_headers(message,newmsg)
		self.debug("payload is instance str %s"%isinstance(
								message.get_payload(),str))
		msgpl=message.get_payload()

		if contenttype=="multipart/alternative":
			alternative=MIMEMultipart(_subtype="alternative")

			for pl in msgpl:
				alternative.attach(pl)

			newmsg.attach(alternative)

		elif isinstance(msgpl,list):

			for pl in msgpl:
				newmsg.attach(pl)

		elif isinstance(msgpl,str):
			pl=self._change_stringpayload_to_multipartpayload(message)
			newmsg.attach(pl)
		else:
			newmsg.attach(message.get_payload())

		return newmsg

	#######################
	#encrypt_pgpinline_mail
	#######################

	@_dbg
	def encrypt_pgpinline_mail(  self,
							message,
							gpguser,
							from_addr,
							to_addr,
							use_container=False,
							include_contentpdf=False):
		"""
		returns the string 'message' as an PGP/INLINE encrypted mail as
		an email.Message object
		returns None if encryption was not possible
		"""

		if use_container==True:
			message=self.zip_attachments_one_container(
										message,
										gpguser,
										from_addr,
										to_addr,
										include_contentpdf=include_contentpdf)
			if message==None:
				self.debug("message==None")
				return None

		if isinstance(message,str):
			self.debug("message is string, converting ...")
			message=email.message_from_string(message)

		counter=0
		attach_list=list()
		appointment=localedb(self,"appointment")
		cal_fname="%s.ics.pgp"%appointment

		if isinstance(message,list):
			self.debug("message is instance list")
			msg=message
		else:
			self.debug("message is not instance list => walk")
			msg=message.walk()
			contenttype=message.get_content_type()
			self.debug("CONTENTTYPE %s"%contenttype)

			if isinstance( message.get_payload(),str ):
				self.debug("encrypt_pgpinline: type( get_payload() ) == str")
				charset=message.get_param("charset",header="Content-Type")
				pdfmsg=None

				if use_container==False and include_contentpdf==True:
					pdfmsg=self._create_contentpdf(message,
											filename=localedb(self,"content"))
					self.debug("include contentpdf outside container")

				if (charset==None
				or charset.upper()=="ASCII"):
					message.set_param("charset",charset)

				message=self._make_multipart_mixed_message(message)

				if pdfmsg!=None:
					message.attach(pdfmsg)

				return self.encrypt_pgpinline_mail( message,
						gpguser,
						from_addr,
						to_addr,
						use_container=False,
						include_contentpdf=False)

			if use_container==False and include_contentpdf==True:
				pdfmsg=self._create_contentpdf(message,
											filename=localedb(self,"content"))
				self.debug("include contentpdf outside container")

				if pdfmsg!=None:

					if message.get_content_type()=="multipart/alternative":
						message=self._make_multipart_mixed_message(message)

					message.attach(pdfmsg)

					if isinstance(message,list):
						self.debug("message is instance list")
						msg=message
					else:
						self.debug("message != list =>walk")
						msg=message.walk()

		for payload in msg:
			content=payload.get_content_maintype()

			if ((content in ("application","image","audio","video" ))
			and payload.get_param( 'inline',
									None,
									'Content-Disposition' )
			is None):
				self.debug("inline change header to attachment")
				payload.add_header('Content-Disposition', 'attachment;"')

			if payload.get_content_maintype() == 'multipart':
				self.debug("multipart continue")
				continue

			if  isinstance( payload.get_payload() , list ):
				self.debug("list continue")
				continue
			else:
				self.debug("in schleife for _encrypt payload %s" %type(payload))
				res=self._encrypt_payload( 	payload,
											gpguser,
											from_addr=from_addr,
											counter=counter )

				if not res:
					self.debug("payload could not be encrypted")
					return None

				if (res and payload.get_content_type()=="text/calendar"
				and payload.get_param(  'attachment',
										None,
										'Content-Disposition' ) is  None):
					CAL=MIMEText(   res.get_payload(decode=True),
									_subtype="calendar",
									_charset="UTF-8")
					CAL.add_header('Content-Disposition',
									'attachment',
									filename=cal_fname)
					CAL.set_param( 'name', cal_fname)
					payload.set_payload("")
					payload.set_type("text/plain")
					attach_list.append(CAL)

				if (content in ("application","image","audio","video" )):
					counter+=1

				self.debug("for loop next")

			self.debug("for loop end")


		for a in attach_list:
			message.attach(a)

		return message

	#####################
	#encrypt_pgpmime_mail
	#####################

	@_dbg
	def encrypt_pgpmime_mail(	self,
							message,
							gpguser,
							from_addr,
							to_addr):
		"""
		returns the string 'message' as an PGP/MIME encrypted mail as
		an email.Message object
		returns None if encryption was not possible
		"""
		if isinstance(message,str):
			raw_message=email.message_from_string(message)
		else:
			raw_message=message

		splitmsg=re.split("\n\n",raw_message.as_string(),1)

		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",raw_message.as_string(),1)

		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part "
						"(mailsize=%i)"%len(raw_message.as_string()))
			return None

		header,body=splitmsg
		header+="\r\n\r\n"

		try:
			newmsg=email.message_from_string( header)
		except:
			self.log("creating new message failed","w")
			self.log_traceback()
			return None

		contenttype="text/plain"
		contenttransferencoding=None
		contentdisposition=None
		contentboundary=None
		subject=None
		msgid=None
		msg_from=None
		msg_to=None
		c=newmsg.get("Content-Type")
		f=newmsg.get_filename()
		contentdisposition=newmsg.get("Content-Disposition")

		if contentdisposition!=None:
			del newmsg["Content-Disposition"]

		if c==None:
			self.debug("Content-Type not set, set default 'text/plain'.")
			newmsg.set_type("text/plain")

		boundary=make_boundary(message)

		try:
			newmsg.set_boundary(boundary)
		except:
			self.log("Error setting boundary")
			self.log_traceback()

		res= re.search("boundary=.*\n",raw_message.as_string(),re.IGNORECASE)

		if res:
			_b=message.as_string()[res.start():res.end()]
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

		try:
			subject=newmsg["Subject"]
			self.debug("Subject:'%s'"%str(subject))
		except:
			self.log("subject could not be found")
			self.log_traceback()

		try:
			msgid=newmsg["Message-ID"]
			self.debug("Message-ID:'%s'"%str(msgid))
		except:
			self.log("Message-ID could not be found")
			self.log_traceback()

		try:
			msg_from=newmsg["From"]
			self.debug("From:'%s'"%str(msg_from))
		except:
			self.log("From could not be found")
			self.log_traceback()

		try:
			msg_to=newmsg["To"]
			self.debug("To:'%s'"%str(msg_to))
		except:
			self.log("To could not be found")
			self.log_traceback()

		if self.pgpmime_do_encryptsubject(to_addr):
			del newmsg["Subject"]
			newmsg["Subject"]=localedb(self,"encryptedsubject")

		del newmsg["Content-Type"]
		newmsg.set_type("multipart/encrypted")
		newmsg.set_param("protocol","application/pgp-encrypted")
		newmsg.preamble=('This is an OpenPGP/MIME encrypted message'
						' (RFC 4880 and 3156)')

		if 'Content-Transfer-Encoding' in newmsg:
			del newmsg['Content-Transfer-Encoding']

		gpg =self.gpg_factory()
		gpg.set_recipient(gpguser)
		gpg.set_fromuser(from_addr)
		fp=self._new_tempfile()
		self.debug("encrypt_mime new tempfile %s"%fp.name)

		if contenttype ==None:
			contenttype="multipart/mixed"

		protocol=""

		if contenttype=="multipart/signed":
			protocol=" protocol=\"application/pgp-signature\";\r\n"

		msgheader=('Content-Type: %(ctyp)s;\r\n%(protocol)s '
					'boundary="%(bdy)s"\r\n'
			%{  "bdy":contentboundary,
				"ctyp":contenttype,
				"protocol":protocol})

		if contenttransferencoding !="None":
			msgheader+=(	"Content-Transfer-Encoding: %s\r\n"%
							contenttransferencoding)

		bodymsg=email.message.Message()

		if "multipart" in contenttype:
			bodymsg["Content-Type"]=contenttype
		else:
			bodymsg["Content-Type"]="multipart/mixed"

		if (contenttransferencoding!="None"
		and contenttransferencoding!=None
		and len(contenttransferencoding)>0):
			bodymsg["Content-Transfer-Encoding"]=contenttransferencoding

		bodymsg["Subject"]=subject
		rawpayload=raw_message.get_payload()
		protectedheader=email.message.Message()
		protectedheader["Content-Type"]="text/rfc822-headers; protected-headers=\"v1\""
		protectedheader["Content-Disposition"]="inline"
		pheader="""From: %s\r\nTo: %s\r\nSubject: %s\r\n""" %(newmsg["From"],newmsg["To"],subject)
		protectedheader.set_payload(pheader)

		if isinstance (rawpayload, str):
			self.debug("Payload==String len=%i"%len(rawpayload))

			if contenttype ==None:
				contenttype="multipart/mixed"

			protocol=""
			charset=""

			if contenttype=="multipart/signed":
				protocol=" protocol=\"application/pgp-signature\";\r\n"

			_ch=self._find_charset(header)
			self.debug("Charset:%s"%str(_ch))
			bdy=""
			fname=""
			params=[]
			params.append("protected-headers=\"v1\"")

			if contentboundary!=None:
				bdy='boundary="%s"'%contentboundary
				params.append(bdy)

			if ("text/" in contenttype) and _ch!= None and len(_ch)>0 :
				charset="charset=\"%s\""%_ch
				params.append(charset)
				self.debug("content-type: '%s' "
								"charset: '%s'"%(contenttype,charset))

			if f and len(f)>0:
				n1,n2=encode_filename(f)
				fname="name=\"%s\""%n2
				params.append(fname)

			if len(params)>0:
				params="\r\n\t%s\r\n"%";\r\n\t".join(params)
			else:
				params="\r\n"

			msgheader=('Content-Type: %(ctyp)s;'
			'%(params)s'%{  "ctyp":contenttype, "params":params})
			self.debug("msgheader:	'%s'"%str(msgheader))
			self.debug("new boundary: '%s'"%str(boundary))

			if contenttransferencoding !=None:
				msgheader+=(
					"Content-Transfer-Encoding: %s\r\n"%contenttransferencoding)

			if contentdisposition!=None:
				msgheader+="Content-Disposition: %s\r\n"%contentdisposition

			if subject!=None:
				msgheader+="Subject: %s\r\n"%subject

			if msg_from!=None:
				msgheader+="From: %s\r\n"%msg_from

			if msg_to!=None:
				msgheader+="To: %s\r\n"%msg_to

			if msgid!=None:
				msgheader+="Message-ID: %s\r\n"%msgid

			body=msgheader+"\r\n"+body

			if self.pgpmime_do_encryptsubject(to_addr):
				m=self._make_multipart_mixed_message(body)
				m.set_param("protected-headers","v1")
				p=m.get_payload()
				p.insert(0,protectedheader)

				if 'MIME-Version' in m:
					del m["MIME-Version"]

				body=m.as_string()

		else:
			self.debug("Payload==Msg")

			if self.pgpmime_do_encryptsubject(to_addr):
				bodymsg.attach(protectedheader)

			for p in rawpayload:
				bodymsg.attach(p)

			body=bodymsg.as_string()

		fp.write(body.encode("UTF-8",unicodeerror))
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
			self.log("Error during encryption pgpmime: payload will be "
					"unencrypted!","m")
			self._del_tempfile(fp.name)
			return None

		newmsg.set_payload(attachment)
		newmsg.set_boundary(boundary)
		attachment.set_boundary(contentboundary)
		attachment.set_masterboundary(boundary)
		self._del_tempfile(fp.name)
		return newmsg

	#################
	#encrypt_pgp_mail
	#################

	@_dbg
	def encrypt_pgp_mail(   self,
							message,
							use_pgpmime,
							gpguser,
							from_addr,
							to_addr):
		"""
		returns the string 'message' as an PGP encrypted mail (either PGP/INLINE
		or PGP/MIME depending on the configuration) as an email.Message object
		returns None if encryption was not possible
		"""
		if isinstance(message,str):
			message=email.message_from_string(message)

		if self.is_encrypted( message ):
			self.debug("encrypt_pgp_mail, is already encrypted")
			return None

		self.log("Encrypting email to: %s" % to_addr )

		if use_pgpmime:
			mail = self.encrypt_pgpmime_mail(message,
											gpguser,
											from_addr,
											to_addr )
		else:
			#PGP Inline
			mail = self.encrypt_pgpinline_mail(message,
									gpguser,
									from_addr,
									to_addr,
									use_container=self._GPGINLINE_ZIPCONTAINER,
									include_contentpdf=self._GPGINLINE_CONTENTPDF)

		if mail==None:
			return None

		self._count_encryptedmails+=1

		if use_pgpmime:
			self._count_pgpmimemails+=1
		else:
			self._count_pgpinlinemails+=1

		return mail

	###################
	# encrypt_smime_mail
	###################

	@_dbg
	def encrypt_smime_mail( self,
							mailtext,
							smimeuser,
							from_addr,
							to_addr):
		"""
		returns the string 'message' as an S/MIME encrypted mail as
		an email.Message object
		returns None if encryption was not possible
		"""
		if isinstance(mailtext,str):
			raw_message=email.message_from_string(mailtext)
		else:
			raw_message=mailtext

		contenttype="text/plain"
		contenttransferencoding=None
		contentboundary=None

		if self.is_encrypted(raw_message):
			self.debug("encrypt_smime_mail:mail is already encrypted")
			self.debug("Mail was already encrypted")
			return None

		splitmsg=re.split("\n\n",raw_message.as_string(),1)

		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",raw_message.as_string(),1)

		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part"
						"(mailsize=%i)"%len(raw_message.as_string()))
			return None

		header,body=splitmsg
		header+="\r\n\r\n"

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
		res= re.search("boundary=.*\r\n",raw_message.as_string(),re.IGNORECASE)

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
		f=newmsg.get_filename()
		contentdisposition=newmsg.get("Content-Disposition")

		if newmsg["Content-Disposition"]:
			del newmsg["Content-Disposition"]

		newmsg.add_header(  'Content-Disposition', 'attachment; '
							'filename="smime.p7m"')
		newmsg.set_param( 'smime-type', 'enveloped-data',requote=False)
		newmsg.set_param( 'name', 'smime.p7m')
		newmsg.del_param("charset")
		newmsg.del_param("boundary")
		protocol=newmsg.get_param("protocol")
		newmsg.del_param("protocol")

		if newmsg["Content-Transfer-Encoding"]:
			del newmsg["Content-Transfer-Encoding"]

		newmsg.add_header('Content-Transfer-Encoding', 'base64')
		smime = self.smime_factory()
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

		if (contenttransferencoding!="None"
		and contenttransferencoding!=None
		and len(contenttransferencoding)>0):
			bodymsg["Content-Transfer-Encoding"]=contenttransferencoding

		rawpayload=raw_message.get_payload()

		if isinstance(rawpayload,str):
			self.debug("Payload==String len=%i"%len(rawpayload))

			if contenttype ==None:
				contenttype="multipart/mixed"

			protocol=""
			charset=""

			if contenttype=="multipart/signed":
				protocol=" protocol=\"application/pgp-signature\";\r\n"

			_ch=self._find_charset(header)
			self.debug("Charset:%s"%str(_ch))
			bdy=""
			fname=""
			params=[]

			if contentboundary!=None:
				bdy='boundary="%s"'%contentboundary
				params.append(bdy)

			if (("text/" in contenttype) and _ch!= None and len(_ch)>0):
				charset="charset=\"%s\""%_ch
				params.append(charset)
				self.debug("content-type: '%s' charset: '%s'"%(
							contenttype,
							charset))

			if f and len(f)>0:
				n1,n2=encode_filename(f)
				fname="name=\"%s\""%n2
				params.append(fname)

			if len(params)>0:
				params="\r\n\t%s\r\n"%";\r\n\t".join(params)
			else:
				params="\r\n"

			msgheader="Content-Type: %(ctyp)s;%(params)s"%{
						"ctyp":contenttype,
						"params":params}
			self.debug("msgheader:	'%s'"%str(msgheader))

			if contenttransferencoding !=None:
				msgheader+=("Content-Transfer-Encoding: %s\r\n" %
								contenttransferencoding)

			if contentdisposition!=None:
				msgheader+="Content-Disposition: %s\r\n"%contentdisposition

			body=msgheader+"\r\n"+body
		else:
			self.debug("Payload==Msg")

			for p in rawpayload:
				bodymsg.attach(p)

			body=bodymsg.as_string()

		fp.write(body.encode("UTF-8",unicodeerror))
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
			self.debug("encrypt_smime_mail: error encrypting mail, "
						"send unencrypted")

			newmsg=None

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
		user=email.utils.parseaddr(user)[1]
		_u=user

		try:
			_u=self._backend.usermap(user)
		except:
			pass

		try:
			self.debug("get_preferred encryptionmap %s"%_u)
			_m=self._backend.encryptionmap(_u)[0].upper()
		except:
			pass

		domain=maildomain(user)

		if len(_m)==0:

			if len(domain)>0:

				try:
					_m=self._backend.encryptionmap("*@%s"%domain)[0].upper()
					self.debug("preferencedencryptionmethod for "
								"*@%s=%s"%(domain,_m))
				except:
					self.debug("get_preferredencryptionmethod User"
							" '%s/%s' not found"%(user,_u))
					self.debug("get_preferredencryptionmethod: "
					"returning default encryption method %s" % (method))
					return method

		if _m in ("PGPMIME","PGPINLINE","SMIME","PDF","NONE"):
			self.debug("get_preferredencryptionmethod User "
						"%s (=> %s) :'%s'"%(user,_u,_m))
			return _m
		else:
			self.debug("get_preferredencryptionmethod: Method "
						"'%s' for user '%s' unknown" % (_m,_u))
			self.debug("get_preferredencryptionmethod: "
			"returning default encryption method %s" % (method))
			return method

	###############
	#_decode_header
	###############

	@_dbg
	def _decode_header(self,header):

		if not header:
			return ""

		h=email.header.decode_header(header)
		result=""

		for m in h:

			try:

				if m[1]==None:

					if isinstance(m[0],str):
						result+=m[0]+" "
					else:
						result+=m[0].decode("UTF-8",unicodeerror)+" "

				else:
					result+=m[0].decode(m[1],unicodeerror)+" "
			except:
				pass

		return result

	#######################
	# _send_pdfpasswordmail
	#######################

	@_dbg
	def _send_pdfpasswordmail(self,from_addr,to_addr,password,newmsg):
	
		domain=maildomain(from_addr)

		if not domain in self._HOMEDOMAINS:
			return

		msgtxt=self._load_mailmaster("01-pdfpassword",
			"<table><tr><td>Subject:</td><td>%SUBJECT%</td></tr>"
			"<tr><td>From:</td><td>%FROM%</td></tr><tr><td>To:</td>"
			"<td>%TO%</td></tr><tr><td>Date:</td><td>%DATE%</td></tr>"
			"<tr><td>Password:</td><td>%PASSWORD%</td></tr></table>")
		msgtxt=replace_variables(msgtxt,
				{"FROM":html.escape(from_addr),
				 "TO":html.escape(self._decode_header(newmsg["To"])),
				 "DATE":newmsg["Date"],
				 "PASSWORD":html.escape(password),
				 "SUBJECT":html.escape(self._decode_header(
													newmsg["Subject"]
				 ))})
		msg=MIMEMultipart()
		msg.set_type("multipart/alternative")
		res,htmlheader,htmlbody,htmlfooter=self._split_html(msgtxt)
		htmlmsg=MIMEText(msgtxt,"html")
		plainmsg=MIMEText(htmlbody)
		msg.attach(plainmsg)
		msg.attach(htmlmsg)
		pwheader=localedb(self,"passwordfor")
		msg['Subject'] = ('%s: %s' %(pwheader,
							self._decode_header(newmsg["To"])))
		msg['To'] = from_addr
		msg['From'] = self._SYSTEMMAILFROM
		self.send_mails(msg.as_string(),from_addr)

	#########################
	# _send_pdfpasswordscript
	#########################

	@_dbg
	def _send_pdfpasswordscript(self,from_addr,to_addr,password,newmsg):

		if self._PDFPASSWORDSCRIPT==None:
			self.log("PDF password script is not defined","e")
			return

		mail=self._new_tempfile()
		mail.write(newmsg.as_bytes())
		mail.close()
		cmd=[os.path.expanduser(self._PDFPASSWORDSCRIPT),
				from_addr,
				to_addr,
				password,
				mail.name
			]
		p1 = subprocess.Popen(	cmd,
								stdin=None,
								stdout=None,
								stderr=subprocess.PIPE )
		output1,error1=p1.communicate()
		_result=p1.poll()
		self._del_tempfile(mail.name)

		if _result != 0:
			self.log("Error executing command (Error code %d)"%_result,
							"e")
			self.log(error1.decode("utf8",unicodeerror),"e")

	###################
	# send_pdf_password
	###################

	@_dbg
	def send_pdfpassword(self,from_addr,to_addr,password,newmsg):

		if self._PDFPASSWORDMODE==self.pdf_none:
			return
		elif self._PDFPASSWORDMODE==self.pdf_script:
			self._send_pdfpasswordscript(from_addr,to_addr,password,newmsg)
		else:
			self._send_pdfpasswordmail(from_addr,to_addr,password,newmsg)
 
	##################
	# encrypt_pdf_mail
	##################

	@_dbg
	def encrypt_pdf_mail(   self,
							message,
							pdfuser,
							from_addr,
							to_addr,
							send_password=True
							):
		"""
		returns the string 'message' as an PDF encrypted mail as an 
		email.Message object, attachments will be moved to a zip file as 
		attachment
		returns None if encryption was not possible
		"""
		if isinstance(message,str):
			message=email.message_from_string(message)

		splitmsg=re.split("\n\n",message.as_string(),1)

		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",message.as_string(),1)

		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part "
						"(mailsize=%i)"%len(message.as_string()))
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

		pdf=self.pdf_factory()
		fp=self._new_tempfile()
		fp.write(message.as_string().encode("UTF-8",unicodeerror))
		fp.close()
		pdf.set_filename(fp.name)
		pw=self.get_pdfpassword(pdfuser)
		self.debug("Password '%s'"%pw)
		result,pdffile=pdf.create_pdffile(pw,from_addr)

		if result==True:

			if send_password:
				self.send_pdfpassword(from_addr,to_addr,pw,newmsg)

			msgtxt=self._load_mailmaster("02-pdfmail",
					   "Content of this e-mail is stored in an pdf attachment.")
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
			f=localedb(self,"content")
			msg.add_header( 'Content-Disposition',
							'attachment',
							filename="%s.pdf"%f)
			email.encoders.encode_base64(msg)
			newmsg.attach(msg)
			self._count_pdfmails+=1
			self._count_encryptedmails+=1
		else:
			return None

		oldmsg=message
		attachments=0
		tempdir = tempfile.mkdtemp()

		if self._USE7ZARCHIVE:
			Zip=self.a7z_factory()
		else:
			Zip=self.zip_factory()

		try:
			Zip.set_zipcipher(self._backend.encryptionmap(pdfuser)[1])
		except:

			try:
				domain=maildomain(pdfuser)

				if len(domain)>0:
					Zip.set_zipcipher(self._backend.encryptionmap("*@%s"
																%domain)[1])
			except:
				pass

		for m in oldmsg.walk():

			if m.get_param( 'attachment',
							None,
							'Content-Disposition' ) is not None:
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
				newfilename=os.path.join(tempdir,filename)
				f1,ext=os.path.splitext(newfilename)
				fncount=0

				while os.path.exists(newfilename):
					fncount+=1
					newfilename=os.path.join(tempdir,f1+str(fncount)+ext)

				fp=open(newfilename,mode="wb")

				try:
					fp.write(payload)
				except:
					self.log("File '%s' could not be written"%filename)
					self.log_traceback()

				fp.close()
				attachments+=1

		if attachments>0:

			if self._PDFSECUREZIPCONTAINER==True and self._USE7ZARCHIVE==False:
				content=localedb(self,"content")
				content="%s.zip"%content
			else:
				content=None

			result,zipfile=Zip.create_zipfile(tempdir,pw,containerfile=content)

			if result==True:

				if self._USE7ZARCHIVE:
					msg= MIMEBase("application", "7z")
					extension="7z"
				else:
					msg= MIMEBase("application", "zip")
					extension="zip"

				msg.set_payload(zipfile)
				f=localedb(self,"attachment")
				filenamecD,filenamecT=encode_filename("%s.%s"%(f,extension))
				msg.add_header( 'Content-Disposition',
								'attachment; filename*="%s"' % filenamecD)
				msg.set_param( 'name', filenamecT )
				email.encoders.encode_base64(msg)
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

	##################
	#_handle_virusmail
	##################

	@_dbg
	def _handle_virusmail(		self,
								information,
								queue_id,
								mailtext,
								from_addr,
								to_addr):
		self.log("Virus found in e-mail from %s to %s"%(from_addr,to_addr),"w")
		self._count_viruses+=1

		for i in information:
			self.log("Virusinfo: %s"% i,"w")

		_time=time.time()

		if self._RUNMODE==self.m_daemon:
			fname=self._store_temporaryfile(mailtext,
											quarantinedir=True)
			self._virus_queue.append([ 	fname,
											from_addr,
											to_addr,
											_time])

		self._remove_mail_from_queue(queue_id)
		#now send infomail
		fdomain= maildomain(from_addr)
		tdomain= maildomain(from_addr)
		new_toaddr=None

		if len(fdomain)>0:
			new_toaddr=from_addr

		if not domain in self._HOMEDOMAINS and len(tdomain)>0:
			domain = tdomain
			new_toaddr=to_addr

		infotxt=""

		for i in information:
			infotxt+="%s<br>"%i

		if domain in self._HOMEDOMAINS:
			msgtxt=self._load_mailmaster("03-virusinformation",
				"""The email from %FROM% to %TO% with id %ID% was stopped,<br>
				because it contains a virus.<br><br>Details:<br>
				%INFORMATION%
				""")
			msgtxt=replace_variables(msgtxt,
					{"FROM":html.escape(from_addr),
					 "TO":html.escape(to_addr),
					 "ID":str(_time),
					 "INFORMATION":infotxt
					})
			msg=MIMEMultipart()
			msg.set_type("multipart/alternative")
			res,htmlheader,htmlbody,htmlfooter=self._split_html(msgtxt)
			htmlmsg=MIMEText(msgtxt,"html")
			plainmsg=MIMEText(htmlbody)
			msg.attach(plainmsg)
			msg.attach(htmlmsg)
			msg['Subject'] = 'Virus mail information'
			msg['To'] = new_toaddr
			msg['From'] = self._SYSTEMMAILFROM
			self.send_mails(msg.as_string(),from_addr)

	###################
	#_check_bounce_mail
	###################

	@_dbg
	def _check_bounce_mail(	self,
							from_addr,
							to_addr):

		if not self._SECURITYLEVEL==self.s_bounce:
			return False

		from_domain=maildomain(from_addr)

		if not from_domain in self._HOMEDOMAINS:
			return False
		#=>from_domain in homedomain
		to_domain=maildomain(to_addr)

		if to_domain in self._HOMEDOMAINS:
			return self._BOUNCEHOMEDOMAIN

		return True

	#######################
	#_send_unencrypted_mail
	#######################

	@_dbg
	def _send_unencrypted_mail(	self,
								queue_id,
								mailtext,
								message,
								from_addr,
								to_addr,
								in_bounce_process=False
								):

		if isinstance(mailtext,str):
			mailtext=email.message_from_string(mailtext)

		if self._SECURITYLEVEL==self.s_script:

			if self._BOUNCESCRIPT==None:
				self.log("Bounce script is not defined","e")
				return False

			self.debug("_send_unencrypted bouncescript '%s'"%os.path.expanduser(
															self._BOUNCESCRIPT))
			mail=self._new_tempfile()
			mail.write(mailtext.as_string().encode("UTF-8",unicodeerror))
			mail.close()
			cmd=[os.path.expanduser(self._BOUNCESCRIPT),
					from_addr,
					to_addr,
					mail.name
				]

			p1 = subprocess.Popen(	cmd,
									stdin=None,
									stdout=None,
									stderr=subprocess.PIPE )
			output1,error1=p1.communicate()
			_result=p1.poll()
			self._del_tempfile(mail.name)

			if _result != 0:
				self.log("Error executing command (Error code %d)"%_result,
								"e")
				self.log(error1.decode("utf8",unicodeerror),"e")

			return False
			
		elif (self._check_bounce_mail(from_addr,to_addr)
			and not in_bounce_process):
				self.debug("_send_unencrypted bouncemail")

				if isinstance(mailtext,str):
					newmsg=email.message_from_string( mailtext)
				else:
					newmsg=mailtext

				msgtxt=self._load_mailmaster("04-bouncemail",
					"Mail was not encrypted and thus not delivered<br>"
					"<table><tr><td>Subject:</td><td>%SUBJECT%</td></tr>"
					"<tr><td>From:</td><td>%FROM%</td></tr><tr><td>To:</td>"
					"<td>%TO%</td></tr><tr><td>Date:</td><td>%DATE%</td></tr>"
					"</table>")
				msgtxt=replace_variables(msgtxt,
						{"FROM":html.escape(from_addr),
						 "TO":html.escape(self._decode_header(newmsg["To"])),
						 "DATE":str(datetime.datetime.now()),
						 "SUBJECT":html.escape(self._decode_header(
															newmsg["Subject"]
						 ))})
				msg=MIMEMultipart()
				msg.set_type("multipart/alternative")
				res,htmlheader,htmlbody,htmlfooter=self._split_html(msgtxt)
				htmlmsg=MIMEText(msgtxt,"html")
				plainmsg=MIMEText(htmlbody)
				msg.attach(plainmsg)
				msg.attach(htmlmsg)
				pwheader=localedb(self,"bouncemail")
				msg['Subject'] = pwheader
				msg['To'] = from_addr
				msg['From'] = self._SYSTEMMAILFROM
				self.log("bounce mail from %s to %s"%(from_addr,to_addr))
				result=self._encrypt_single_mail(-1,msg,
												from_addr,
												to_addr,
												in_bounce_process=True)
				self._remove_mail_from_queue(queue_id)

				if result:
					return True
				else:
					return False

		self.debug("send_unencrypted may: %s"%message)
		return self._send_rawmsg(  queue_id,
							mailtext.as_string(),
							message,
							from_addr,
							to_addr)

	############
	#_get_header
	############

	@_dbg
	def _get_header(self,mail):

		if not isinstance(mail,str):
			mail=mail.as_string()

		splitmsg=re.split("\n\n",mail,1)

		if len(splitmsg)!=2:
			splitmsg=re.split("\r\n\r\n",mail,1)

		if len(splitmsg)!=2:
			self.debug("Mail could not be split in header and body part "
						"(mailsize=%i)"%len(mail))
			return None

		header,body=splitmsg
		lines=header.splitlines()
		result=[]
		in_ignoreheader=False
		for l in lines:

			if in_ignoreheader:

				if l.startswith(" "):
					continue
				else:
					in_ignoreheader=False

			if not in_ignoreheader:
				if (l.startswith("Content-Type")
				or l.startswith("Content-Disposition")
				or l.startswith("Content-Description")
				or l.startswith("Content-Transfer-Encoding")
				or l.startswith("X-GPGMailencrypt")
				):
					in_ignoreheader=True
				else:
					result.append(l)

		return "\r\n".join(result)

	#####################
	#decrypt_pgpmime_mail
	#####################

	@_dbg
	def decrypt_pgpmime_mail(self,mailtext,from_addr,to_addr):

		if not self.is_pgpmimeencrypted(mailtext):
				return None

		g_r,to_gpg=self.check_gpgrecipient(to_addr)

		if not g_r:
			self.debug("no gpg user key found")
			return None

		if isinstance(mailtext,str):
			mailtext=email.message_from_string(mailtext)

		gpg =self.gpg_factory()
		gpg.set_recipient(to_gpg)
		gpg.set_fromuser(from_addr)
		fp=self._new_tempfile()
		fp.write(mailtext.as_string().encode("UTF-8",unicodeerror))
		fp.close()
		result,encdata=gpg.decrypt_file(filename=fp.name)
		self._del_tempfile(fp.name)

		if result==False:
			self.log("Error during decrypting pgpmime: couldn't decrypt mail")
			return None

		header=self._get_header(mailtext)

		if header:
			return header +"\r\n"+encdata
		else:
			return None

	#################
	#_decrypt_payload
	#################

	@_dbg
	def _decrypt_payload(   self,
							payload,
							recipient,
							counter=0 ):

		charset=payload.get_param("charset",header="Content-Type")
		is_text=payload.get_content_maintype()=="text"
		cte=payload["Content-Transfer-Encoding"]

		if not cte:
			cte="8bit"

		self.debug("_decrypt_payload: charset %s"%charset)

		if charset!=None:

			try:
				"test".encode(charset)
			except:
				charset="UTF-8"

		if charset==None or charset.upper()=="ASCII" or len(charset)==0:
			charset="UTF-8"

		gpg =self.gpg_factory()
		gpg._set_counter(counter)
		gpg.set_recipient(recipient)
		raw_payload = payload.get_payload(decode=not is_text)

		contenttype=payload.get_content_type()
		
		if is_text:
			raw_payload=decodetxt(raw_payload,cte,charset)

		fp=self._new_tempfile()
		self.debug("_decrypt_payload _new_tempfile %s"%fp.name)
		filename = payload.get_filename()

		if contenttype=="text/html":
			raw_payload=raw_payload.replace("<br>","").replace("<BR>","")
			lines=raw_payload.splitlines()
			_r=[]

			for l in lines:
				_r.append(l.strip())

			raw_payload="\r\n".join(_r)

		if is_text:

			try:
				raw_payload.encode("ascii")
			except:
				self.log_traceback()

			raw_payload=raw_payload.encode(charset,unicodeerror)

		fp.write(raw_payload)
		fp.close()

		isAttachment = payload.get_param(   'attachment',
											None,
											'Content-Disposition' ) is not None
		gpg.set_filename( fp.name )
		contentmaintype=payload.get_content_maintype()

		if ( isAttachment):
			self.debug("DECRYPT PAYLOAD ATTACHMENT")
			removePGPextension=True

			if filename==None:
				count=""

				if counter>0:
					count="%i"%counter

				f=localedb(self,"file")
				filename=('%s%s.'%(f,count))+guess_fileextension(contenttype)

			f,e=os.path.splitext(filename)
			ext=".pgp"
			removePGPextension=(e.lower()==ext)

			if not removePGPextension:
				ext=".gpg"
				removePGPextension=(e.lower()==ext)
			
			if removePGPextension:
				pgpFilename = f
			else:
				pgpFilename=filename

			self.debug("Filename:'%s'"%filename)
			pgpFilenamecD,pgpFilenamecT=encode_filename(pgpFilename)
			isBinaryattachment=(contentmaintype!="text")

			if removePGPextension:
				self.debug("removePGPextension gpg.decrypt_file")
				result,pl=gpg.decrypt_file(binary=isBinaryattachment)
			else:
				result=False

			if result==True:

				if isBinaryattachment:
					payload.set_payload(str(base64.encodebytes(pl),"ascii"))

					if 'Content-Transfer-Encoding' in payload:
						del payload['Content-Transfer-Encoding']

					payload["Content-Transfer-Encoding"]="base64"
				else:
					payload.set_payload(pl)

					if 'Content-Transfer-Encoding' in payload:
						del payload['Content-Transfer-Encoding']

					payload["Content-Transfer-Encoding"]="8bit"

				t='application/octet-stream'
				mt=guess_mimetype(pgpFilename)

				if mt!= None:
					t=mt

				payload.set_type(t)

				if payload["Content-Disposition"]:
					del payload["Content-Disposition"]

				payload.add_header( 'Content-Disposition',
									'attachment; filename*="%s"'%pgpFilenamecD)
				payload.set_param( 'name', pgpFilenamecT )
		else:

			if 'Content-Transfer-Encoding' in payload:
				del payload['Content-Transfer-Encoding']

			result,pl=gpg.decrypt_file(binary=False)

			if result==True:

				if "Content-Transfer-Encoding" in payload:
					del payload["Content-Transfer-Encoding"]

				payload["Content-Transfer-Encoding"]="base64"
				payload.set_payload(base64.encodestring(pl.encode("UTF-8",
														unicodeerror)))
			else:
				self.log("Error during decryption: payload will stay "
						"encrypted!","m")
				payload= None

		self._del_tempfile(fp.name)
		return payload

	#######################
	#decrypt_pgpinline_mail
	#######################

	@_dbg
	def decrypt_pgpinline_mail(  self,
							mail,
							from_addr,
							to_addr):

		g_r,to_gpg=self.check_gpgrecipient(to_addr)

		if not g_r:
			self.debug("no gpg user key found")
			return None

		if isinstance(mail,str):
			message=email.message_from_string(mail)
		else:
			message=mail

		counter=0

		if isinstance(mail,list):
			msg=message
		else:
			msg=message.walk()

		for payload in msg:
			content=payload.get_content_maintype()

			if payload.get_content_maintype() == 'multipart':
				continue

			if  isinstance( payload.get_payload() , list ):
				continue
			else:
				self.debug("in schleife for _decrypt payload %s" %type(payload))
				self._decrypt_payload( 	payload,
											to_gpg,
											counter=counter )

				if (content in ("application","image","audio","video" )):
					counter+=1

			counter+=1

		return message.as_string()

	##############
	#decrypt_smime
	##############

	@_dbg
	def decrypt_smime_mail(self,mailtext,from_addr,to_addr):
		self.log("START decrypt smime")

		if not self.is_smimeencrypted(mailtext):
				return None

		self.debug("decrypt smime")
		s_r,to_smime=self.check_smimerecipient(to_addr)

		if not s_r:
			self.debug("no smime user key found")
			return None

		if not isinstance(mailtext,str):
			mailtext=mailtext.as_string()

		smime =self.smime_factory()
		smime.set_recipient(to_smime)
		smime.set_fromuser(from_addr)
		fp=self._new_tempfile()
		fp.write(mailtext.encode("UTF-8",unicodeerror))
		fp.close()
		result,encdata=smime.decrypt_file(filename=fp.name)
		self._del_tempfile(fp.name)

		if result==False:
			self.log("Error during decrypting smime: couldn't decrypt mail")
			return None

		header=self._get_header(mailtext)

		if header:
			return header +"\r\n"+encdata
		else:
			return None

	#################
	#decrypt_pdf_mail
	#################

	@_dbg
	def decrypt_pdf_mail(self, mailtext,from_addr,to_addr):

		if not isinstance(mailtext,email.message.Message):
			m=email.message_from_string(mailtext)
		else:
			m=mailtext

		if isinstance(m,list):
			p=m
		else:
			p=m.walk()

		result=False
		pdf=self.pdf_factory()

		for payload in p:

			if payload.get_content_type()=="application/pdf":
				raw_payload = payload.get_payload(decode=True)
				fp=self._new_tempfile()
				fp.write(raw_payload)
				fp.close()
				r,fname=pdf.decrypt_file(fp.name,from_addr,to_addr)

				if r==True:
					pdffile=open(fname,"rb")
					pl=pdffile.read()
					pdffile.close()
					self._del_tempfile(fp.name)
					payload.set_payload(str(base64.encodebytes(pl),"ascii"))

					if "Content-Transfer-Encoding" in payload:
						del payload["Content-Transfer-Encoding"]

					payload["Content-Transfer-Encoding"]="base64"
					result=True

		if result:

			if m["X-PDFEncrypted"]:
					del m["X-PDFEncrypted"]

			if m and m[self._encryptheader]:
				del m[self._encryptheader]

			return m.as_string()
		else:
			return None

	############
	#decrypt_zip
	############

	@_dbg
	def decrypt_zip(self, mailtext,from_addr,to_addr):

		if not isinstance(mailtext,email.message.Message):
			m=email.message_from_string(mailtext)

		if isinstance(m,list):
			p=m
		else:
			p=m.walk()

		result=False
		zip=self.zip_factory()

		for payload in p:

			ct=payload.get_content_type()
			if ct in ("application/zip","application/7z"):
				raw_payload = payload.get_payload(decode=True)
				fp=self._new_tempfile()
				fp.write(raw_payload)
				fp.close()
				r,fname=zip.decrypt_zipfile(fp.name,from_addr,to_addr)

				if r==True:
					zipfile=open(fname,"rb")
					pl=zipfile.read()
					zipfile.close()
					self._del_tempfile(fp.name)
					payload.set_payload(str(base64.encodebytes(pl),"ascii"))
					payload["Content-Transfer-Encoding"]="base64"
					result=True

		if result:

			if m["X-PDFEncrypted"]:
					del m["X-PDFEncrypted"]

			if m and m[self._encryptheader]:
				del m[self._encryptheader]

			return m.as_string()
		else:
			return None

	##############
	#_decrypt_mail
	##############

	@_dbg
	def decrypt_mail(self,mailtext,from_addr,to_addr):
		mresult=None

		if self.is_pgpmimeencrypted(mailtext):
			mresult=self.decrypt_pgpmime_mail(mailtext,from_addr,to_addr)

		elif self.is_pgpinlineencrypted(mailtext):
			mresult=self.decrypt_pgpinline_mail(mailtext,from_addr,to_addr)

		elif self.is_smimeencrypted(mailtext):
			mresult=self.decrypt_smime_mail(mailtext,from_addr,to_addr)

		elif self.is_pdfencrypted(mailtext):
			mresult=self.decrypt_pdf_mail(mailtext,from_addr,to_addr)

			if mresult:
				res=self.decrypt_zip(mresult,from_addr,to_addr)

				if res:
					mresult=res
		if mresult!=None:
			self._count_decryptedemails+=1
		return mresult

	#############################
	#_send_already_encrypted_mail
	#############################

	@_dbg
	def _send_already_encrypted_mail(	self,
										queue_id,
										mailtext,
										from_addr,
										to_addr,
										decrypt=True):
		mresult=None

		if self._DECRYPT and decrypt:
			mresult=self.decrypt_mail(mailtext,from_addr,to_addr)
			has_virus=False

			if mresult:

				if 	(self._VIRUSCHECK==True and self._virus_checker==None):
					self._virus_checker=_virus_check(parent=self)

				if (self._VIRUSCHECK==True and self._virus_checker!=None):
					has_virus,virusinfo=self._virus_checker.has_virus(mailtext)

				if has_virus:
						self._handle_virusmail(	virusinfo,
												queue_id,
												mresult,
												from_addr,
												to_addr)
						return

				m="decrypted"
				self._send_rawmsg( queue_id,
								mresult,
								m,
								from_addr,
								to_addr )
				return

		m="Email already encrypted"
		self.debug(m)
		self._count_alreadyencryptedmails+=1
		self._send_rawmsg(queue_id,mailtext,m,from_addr,to_addr)

	#####################
	#_encrypt_single_mail
	#####################

	@_dbg
	def _encrypt_single_mail(	self,
								queue_id,
								mailtext,
								from_addr,
								to_addr,
								is_spam=spamscanners.S_NOSPAM,
								has_virus=False,
								virusinfo=None,
								in_bounce_process=False,
								decrypt=False):
		_pgpmime=False
		_prefer_gpg=True
		_prefer_pdf=False
		_prefer_smime=False
		mresult=None
		self._count_totalmails+=1
		from_addr=from_addr.lower()
		to_addr=to_addr.lower()

		if isinstance(mailtext,str):
			mailtext=email.message_from_string(mailtext)		

		if self.is_encrypted(mailtext):
			self._send_already_encrypted_mail(	queue_id,
												mailtext,
												from_addr,
												to_addr,
												decrypt)
			return None

		if has_virus:
				self._handle_virusmail(	virusinfo,
										queue_id,
										mailtext,
										from_addr,
										to_addr)
				return None
		elif virusinfo!=None and len(virusinfo)>0:
				self.log(
				"No virus found, but received the following messages",
				"w")

				for i in virusinfo:
					self.log("Virusinfo: %s"% i,"w")

		if is_spam!=spamscanners.S_NOSPAM:
			m="Email is SPAM"
			self._send_unencrypted_mail(queue_id,mailtext,m,from_addr,to_addr)
			return None

		_encrypt_subject=self.check_encryptsubject(mailtext)

		try:
			to_pdf=self._backend.usermap(to_addr)
		except:
			self.debug("preferpdf _addressmap to_addr not found")
			to_pdf=to_addr

		if _encrypt_subject:
			self.debug("remove #encrypt from subject")
			subject=self._decode_header(mailtext["Subject"])[9:]
			del mailtext["Subject"]
			mailtext["Subject"]=subject

		g_r,to_gpg=self.check_gpgrecipient(to_addr,from_addr=from_addr)
		s_r,to_smime=self.check_smimerecipient(to_addr)
		method=self.get_preferredencryptionmethod(to_addr)
		self.debug("GPG encrypt possible %i / %s"%(g_r,to_gpg))
		self.debug("SMIME encrypt possible %i / %s"%(s_r,to_smime))
		self.debug("Prefer PDF %i / %s"%(_prefer_pdf,to_pdf))
		domain=maildomain(from_addr)

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

			if domain in self._HOMEDOMAINS:
				_prefer_pdf=True

		if method=="NONE":
			g_r=False
			s_r=False

		if (not s_r
		and not g_r
		and not _prefer_pdf
		and not _encrypt_subject):
			m="Email not encrypted, public key for '%s' not found"%to_addr

			if self._ZIPATTACHMENTS:
				mailtext=self.zip_attachments(mailtext)

			self._send_unencrypted_mail(queue_id,
										mailtext,
										m,
										from_addr,
										to_addr,
										in_bounce_process=in_bounce_process)
			return None

		if ((   not _prefer_pdf
				and not _encrypt_subject)
		or (	_encrypt_subject
				and (g_r or s_r))):

			if self._ZIPATTACHMENTS:
				mailtext=self.zip_attachments(mailtext)

		if _prefer_gpg:
			self.debug("PREFER GPG")

			if g_r:
				mresult=self.encrypt_pgp_mail(  mailtext,
												_pgpmime,
												to_gpg,
												from_addr,
												to_addr)
			elif s_r:
				mresult=self.encrypt_smime_mail(mailtext,
												to_smime,
												from_addr,
												to_addr)
		elif _prefer_smime :
			self.debug("PREFER S/MIME")

			if s_r:
				mresult=self.encrypt_smime_mail(mailtext,
												to_smime,
												from_addr,
												to_addr)
			elif g_r:
				mresult=self.encrypt_pgp_mail(  mailtext,
												_pgpmime,
												to_gpg,
												from_addr,
												to_addr)

		if 	(self._use_pdf
			and (not mresult and (_encrypt_subject or _prefer_pdf))):

			if domain in self._HOMEDOMAINS:
				mresult=self.encrypt_pdf_mail(  mailtext,
												to_pdf,
												from_addr,
												to_addr)

		if mresult:
			self.debug("send encrypted mail")
			self._send_msg( queue_id,
							mresult,
							from_addr,
							to_addr )
		else:
			m="Email could not be encrypted"
			self._send_unencrypted_mail(  queue_id,
								mailtext,
								m,
								from_addr,
								to_addr,
								in_bounce_process=in_bounce_process)
		return mresult

	############
	# send_mails
	############

	@_dbg
	def send_mails(  self,
						mailtext,
						recipients,
						in_bounce_process=False,
						decrypt=True):
		"""
		Main function of this library:
			mailtext is the mail as a string
			recipient is a list of receivers
		The emails will be encrypted if possible and sent as defined
		in /etc/gpgmailencrypt.conf
		example:
		send_mails(myemailtext,['agentj@mib','agentk@mib'])
		"""

		if self._debug_keepmail(mailtext): #DEBUG
			self._store_temporaryfile(mailtext)

		if isinstance(recipients,str):
			recipients=[recipients]

		spamlevel=spamscanners.S_NOSPAM
		score=0
		has_virus=False
		virusinfo=None

		if isinstance(mailtext,str):
			raw_message = email.message_from_bytes( mailtext.encode("utf8") )
		else:
			raw_message=mailtext

		raw_message=self.try_repair_email(raw_message)
			

		from_addr = raw_message['From']

		if self._SPAMCHECK and self._spam_checker==None:
			self._spam_checker=spamscanners.get_spamscanner(self._SPAMSCANNER,
												parent=self,
												leveldict=self._spam_leveldict)

			if self._spam_checker!=None:
				self.log("SPAMCHECKER '%s' activated"%self._SPAMSCANNER)
			else:
				self.log("NOSPAMCHECKER")

		try:

			if self._SMIMEAUTOMATICEXTRACTKEYS:
				self.debug("_SMIMEAUTOMATICEXTRACTKEYS")
				s=self.smime_factory()
				s.extract_publickey_from_mail(  raw_message,
												self._SMIMEKEYEXTRACTDIR)

			if self._GPGAUTOMATICEXTRACTKEYS:
				self.debug("_GPGAUTOMATICEXTRACTKEYS")
				s=self.gpg_factory()
				s.extract_publickey_from_mail(  raw_message,
												self._GPGKEYEXTRACTDIR)

			if self._SPAMCHECK and self._spam_checker!=None:
				self.debug("Spamcheck is_spam")
				spamlevel,score=self._spam_checker.is_spam(mailtext)
				scoretext=str(score)
				is_spam=(spamlevel==spamscanners.S_SPAM)

				if spamlevel==spamscanners.S_SPAM:
					self._count_spam+=1
					self.log("SPAM from %s to %s" %(
										from_addr,
										",".join(recipients)))

				if spamlevel==spamscanners.S_MAYBESPAM:
					self._count_maybespam+=1
					self.log("MAYBE SPAM from %s to %s" %(
										from_addr,
										",".join(recipients)))

				self.debug("Spamresult: spamlevel %i, score %f"%(spamlevel,
																score))

				if self._SPAMADDHEADER:

					h="X-Spam-Score"
					if raw_message[h]:
						del raw_message[h]

					h="X-Spam-Level"
					if raw_message[h]:
						del raw_message[h]

					h="X-Spam-Flag"
					if raw_message[h]:
						del raw_message[h]

					h="X-Spam-Maybe"
					if raw_message[h]:
						del raw_message[h]

					sc_level=int(score)

					if sc_level>50:
						sc_level=50

					raw_message.add_header("X-Spam-Score",scoretext)
					raw_message.add_header("X-Spam-Level","*"*sc_level)
					raw_message.add_header("X-Spam-Flag",str(is_spam))
					raw_message.add_header("X-Spam-Maybe",
									str(spamlevel==spamscanners.S_MAYBESPAM))

			if self._SPAMCHANGESUBJECT:
				subject=self._decode_header(raw_message["Subject"])

				if spamlevel==spamscanners.S_MAYBESPAM:
						subject="%s %s"%(	self._SPAMSUSPECTSUBJECT,
											subject)
				elif spamlevel==spamscanners.S_SPAM:
						subject="%s %s"%(	self._SPAMSUBJECT,
												subject)
				del raw_message["Subject"]
				raw_message["Subject"]=subject


			if 	(self._VIRUSCHECK==True and self._virus_checker==None):
				self._virus_checker=_virus_check(parent=self)

			if (self._VIRUSCHECK==True and self._virus_checker!=None):
				has_virus,virusinfo=self._virus_checker.has_virus(mailtext)

			for to_addr in recipients:
				self.debug("encrypt_mail for user '%s'"%to_addr)

				if self._RUNMODE==self.m_daemon:
					fname=self._store_temporaryfile(raw_message.as_string(),
													spooldir=True)

				if self._RUNMODE==self.m_daemon:
					self._email_queue[self._queue_id]=[ fname,
														from_addr,
														to_addr,
														time.time()]
				else:
					self._queue_id=-1

				mailid=self._queue_id

				if self._RUNMODE==self.m_daemon:
					self._queue_id+=1

				self._encrypt_single_mail(   mailid,
											raw_message,
											from_addr,
											to_addr,
											spamlevel,
											has_virus,
											virusinfo,
											in_bounce_process=in_bounce_process,
											decrypt=decrypt)

			newfrom="%s <%s>"%(	self._SENTADDRESS,
					 			email.utils.parseaddr(from_addr)[1])

			if (self._USE_SENTADDRESS and
				spamlevel==spamscanners.S_NOSPAM and
				newfrom not in from_addr and
				maildomain(from_addr) in self._HOMEDOMAINS):
					 del raw_message['From']
					 raw_message['From']=newfrom
					 self.send_mails(	raw_message.as_string(),
					 					from_addr,
					 					decrypt=False)

		except:
			self._count_deferredmails+=1
			self.log_traceback()

	#######################################
	#END definition of encryption functions
	#######################################
	
	###########
	#scriptmode
	###########

	@_dbg
	def scriptmode(self,recipient):
		"run gpgmailencrypt a script"

		try:
			#read message

			if len(self._INFILE)>0:

				try:
					f=open(self._INFILE,mode="rb")
					m=email.message_from_binary_file(f)
					f.close()
					m=self.try_repair_email(m)
					if m==None:
						exit(2)
					raw=m.as_string()
					
				except:
					self.log("Could not open Inputfile '%s'"%self._INFILE,"e")
					self.log_traceback()
					exit(2)

			else:
				sys.stdin = TextIOWrapper(sys.stdin.buffer,
										  encoding='UTF-8',
										  errors=unicodeerror)
				raw = sys.stdin.read()

			#do the magic
			self.send_mails(raw,recipient)
		except SystemExit as m:
			self.debug("Exitcode:'%s'"%m)
			exit(int(m.code))
		except:
			self.log("Bug:Exception occured!","e")
			self.log_traceback()
			exit(4)
		else:
			self.debug("Program exits without errors")

	################
	#_sigthuphandler
	################

	def _sighuphandler(self,signum, frame):
		self.init()
		self._parse_commandline()

	################
	#_sigtermhandler
	################

	def _sigtermhandler(self,signum, frame):
		self.log("Got SIGTERM signal,shutting down server.")
		raise SystemExit

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
			self.del_old_virusmails()

		#####################

		self._RUNMODE=self.m_daemon
		self._daemonstarttime=datetime.datetime.now()
		alarm=_mytimer()
		alarm.start(0,3600,alarmfunction=_deferredlisthandler)

		try:
			self._count_alarms=24//self._STATISTICS_PER_DAY
		except:
			self._count_alarms=0

		signal.signal(signal.SIGTERM, self._sigtermhandler)
		signal.signal(signal.SIGHUP, self._sighuphandler)
		self.load_deferred_list()
		self.load_virus_list()
		_deferredlisthandler()
		self.log("gpgmailencrypt %s starts as daemon on %s:%s"%(
					VERSION,
					self._SMTPD_HOST,
					self._SMTPD_PORT) )

		try:
			server = _gpgmailencryptserver(
						  self,
						  (self._SMTPD_HOST, self._SMTPD_PORT),
						  use_auth=self._SMTPD_USE_AUTH,
						  use_smtps=self._SMTPD_USE_SMTPS,
						  use_tls=self._SMTPD_USE_STARTTLS,
						  force_tls=self._SMTPD_FORCETLS,
						  sslkeyfile=self._SMTPD_SSL_KEYFILE,
						  sslcertfile=self._SMTPD_SSL_CERTFILE)
		except:
			self.log("Couldn't start mail server")
			self.log_traceback()
			alarm.stop()
			exit(5)

		try:
			server.start()
		except SystemExit:
			alarm.stop()
			exit(0)
		except (KeyboardInterrupt,EOFError):
			self.log("Keyboard Exit")
		except:
			self.log("Bug:Exception occured!","e")
			self.log_traceback()

		alarm.stop()

	@_dbg
	def pgpmime_do_encryptsubject(self,user):
		"returns True if the header fields like 'Subject' will be"
		" also encrypted"
		try:
			do=self._backend.pgpmime_do_encryptsubject(user)
		except:
			return self._GPGMIME_ENCRYPTSUBJECT
		
		return do

	############################
	#pdf_additionalencryptionkey
	############################

	@_dbg
	def pdf_additionalencryptionkey(self,user):
		"returns a list of all additional gpg encryption keys, "
		"with which an email should be encrypted"
		return self._backend.pdf_additionalencryptionkey(user)

	#############################
	#gpg_additionalencryptionkeys
	#############################

	@_dbg
	def gpg_additionalencryptionkeys(self,user):
		"returns a list of all additional gpg encryption keys, "
		"with which an email should be encrypted"
		return self._backend.gpg_additionalencryptionkeys(user)

	###############################
	#smime_additionalencryptionkeys
	###############################

	@_dbg
	def smime_additionalencryptionkeys(self,user):
		"returns a list of all additional smime encryption keys, "
		"with which an email should be encrypted"
		return self._backend.smime_additionalencryptionkeys(user)

	##############
	#adm_get_users
	##############

	@_dbg
	def adm_get_users(self):
		"returns a list of all users and whether or not the user is a admin"
		return self._backend.adm_get_users()

	#############
	#adm_set_user
	#############

	@_dbg
	def adm_set_user(   self,
						user,
						password):
		"adds a user, if the user already exists it changes the password"
		return self._backend.adm_set_user(user,password)

	#############
	#adm_del_user
	#############

	@_dbg
	def adm_del_user(self,user):
		"deletes a user"
		return self._backend.adm_del_user(user)

	###############
	#adm_get_pwhash
	###############

	@_dbg
	def adm_get_pwhash(self,user):
		"returns the password hash from the user"
		return self._backend.adm_get_pwhash(user)

#####
#main
#####

def main():
	"main routine which will be called when gpgmailencrypt "
	"is started as a script, not as a module"

	with gme() as g:
		recipient=g._parse_commandline()
		g._set_logmode()

		if g._RUNMODE==g.m_daemon:
			g.daemonmode()
		else:
			g.scriptmode(recipient)

############################
#gpgmailencrypt main program
############################

if __name__ == "__main__":
	main()


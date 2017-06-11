#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import asynchat
import asyncore
import binascii
import datetime
import os
import select
import smtpd
import socket
import ssl
import sys
from	.child 			import _gmechild
from	.version		import *
from .storagebackend import _sql_backend
from .password        import pw_hash,pw_verify,_deprecated_get_hash

######################
#_gpgmailencryptserver
######################

class _gpgmailencryptserver(smtpd.SMTPServer):
	"encryption smtp server based on smtpd"
	#can't be member of _gmechild because smtpd.SMTPServer uses the name debug
	ADMINCOMMANDS=[ "CREATETABLE",
					"DEBUG",
					"DELUSER",
					"FLUSH",
					"MESSAGES",
					"RELOAD",
					"RESETMESSAGES",
					"RESETSTATISTICS",
					"SETUSER",
					"STATISTICS",
					"QUARANTINE",
					"USERS"]
	ADMINALLCOMMANDS=ADMINCOMMANDS+["HELP","QUIT"]

	def __init__(self,
			parent,
			localaddr,
			sslcertfile=None,
			sslkeyfile=None,
			sslversion=ssl.PROTOCOL_SSLv23,
			use_smtps=False,
			use_tls=False,
			use_auth=False,
			force_tls=False,
			data_size_limit=smtpd.DATA_SIZE_DEFAULT):

		try:
			smtpd.SMTPServer.__init__(  self,
										localaddr,
										None,
										data_size_limit=data_size_limit,
										decode_data=True)
		except socket.error as e:

			if parent:
				parent.log("_gpgmailencryptserver: error",e)
			raise

		smtpd.__version__="gpgmailencrypt smtp server %s"%VERSION
		self.parent=parent
		self.sslcertfile=None

		if sslcertfile!=None:
			self.sslcertfile=os.path.expanduser(sslcertfile)

		self.sslkeyfile=None

		if sslkeyfile!=None:
			self.sslkeyfile=os.path.expanduser(sslkeyfile)

		self.sslversion=sslversion
		self.use_smtps=use_smtps
		self.force_tls=False

		if not use_smtps:
			self.use_tls=use_tls

			if use_tls:
				self.force_tls=force_tls

		self.use_authentication=use_auth
		_sslpossible=True

		try:
			f=open(self.sslcertfile)
			f.close()
		except:
			_sslpossible=False

		try:
			f=open(self.sslkeyfile)
			f.close()
		except:
			_sslpossible=False

		if _sslpossible==False:
			self.use_tls=False
			self.use_smtps=False
			self.force_tls=False
			self.parent.log("SSL connection not possible. Cert- and/or key "
							"file couldn't be opened","e")

	######
	#start
	######

	def start(self):
		asyncore.loop()

	#####################
	#create_sslconnection
	#####################

	def create_sslconnection(self,conn):
		newconn=None

		try:
			newconn=ssl.wrap_socket(conn,
				server_side=True,
				certfile=self.sslcertfile,
				keyfile=self.sslkeyfile,
				ssl_version=self.sslversion,
				do_handshake_on_connect=False
				)

			while True:

				try:
					newconn.do_handshake()
					break
				except ssl.SSLWantReadError:
					select.select([newconn], [], [])
				except ssl.SSLWantWriteError:
					select.select([], [newconn], [])
				except :
					self.parent.log("Client did break off STARTTLS","w")
					self.parent.log_traceback()
					break

		except:
			self.parent.log("_gpgmailencryptserver: Exception: Could not"
							" start SSL connection")
			self.parent.log_traceback()

		return newconn

	##############
	#handle_accept
	##############

	def handle_accept(self):
		pair = self.accept()

		if pair is not None:
			conn, addr = pair
			self.socket.setblocking(0)

			if self.use_smtps:
					conn=self.create_sslconnection(conn)

					if conn==None:
						return

			self.parent.debug("_gpgmailencryptserver: Incoming connection "
								"from %s" % repr(addr))
			channel = _hksmtpchannel(self,
						conn,
						addr,
						parent=self.parent,
						use_auth=self.use_authentication,
						use_tls=self.use_tls,
						force_tls=self.force_tls,
						sslcertfile=self.sslcertfile,
						sslkeyfile=self.sslkeyfile,
						sslversion=self.sslversion)

	################
	#process_message
	################

	def process_message(	self,
							peer,
							mailfrom,
							recipient,
							data):
		self.parent.debug("_gpgmailencryptserver: _gpgmailencryptserver "
						"from '%s' to '%s'"%(mailfrom,recipient))

		try:
			self.parent.send_mails(data,recipient)
		except:
			self.parent.log("_gpgmailencryptserver: Bug:Exception!")
			self.parent.log_traceback()

		return


	#############
	#authenticate
	#############

	def authenticate(  self,
					user,
					password):
		"checks user authentication against a password file"
		self.parent.debug("authenticate")
		pw=self.parent.adm_get_pwhash(user)

		if pw==_deprecated_get_hash(password):

			self.parent.debug("mailencryptserver: User '%s' with deprecated password hash algorithm authenticated"%user)
			self.parent.adm_set_user(user,password)
			pw=self.parent.adm_get_pwhash(user)

		if pw_verify(password,pw,parent=self.parent):
			self.parent.debug("mailencryptserver: User '%s' password verifed"
								%user)
			return True

		self.parent.debug("mailencryptserver: User '%s' password wrong"%user)
		return False


###############
#_hksmtpchannel
###############

class _hksmtpchannel(smtpd.SMTPChannel):
	"helper class for _gpgmailencryptserver"
	#can't be member of _gmechild because smtpd.SMTPChannel uses the name debug

	def __init__(self,
				smtp_server,
				newsocket,
				fromaddr,
				use_auth,
				parent,
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
		self.is_authenticated=False
		self.is_admin=False
		self.adminmode=False
		self.use_authentication=use_auth
		self.user=""
		self.password=""
		self.in_loginauth=0 # 0=False, 1 get user, 2 get password
		self.seen_greeting=False
		self.data_size_limit=0
		self.fqdn=socket.getfqdn()
		_sslpossible=True

		try:
			f=open(self.sslcertfile)
			f.close()
		except:
			_sslpossible=False

		try:
			f=open(self.sslkeyfile)
			f.close()
		except:
			_sslpossible=False

		if _sslpossible and self.sslversion:
			self.starttls_available=True

	######################
	#collect_incoming_data
	######################

	#the following method is taken from SMTPChannel and is corrected to not
	#throw an encoding error if something else than unciode comes
	#through the line
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

		for e in [  "UTF-8",
					"ISO8859-15",
					"UTF-16"]:

			try:
				encodeddata=data.decode(e,unicodeerror)
				break
			except:
				pass

		if encodeddata==None:
			encodeddata=data.decode("UTF-8",unicodeerror)

		self.received_lines.append(encodeddata)

	#################
	#found_terminator
	#################

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

		if ((self.use_authentication or self.adminmode)
		and not self.is_authenticated):

			if self.in_loginauth:

				if self.in_loginauth==1:
					self.user=binascii.a2b_base64(
										line).decode("UTF-8",unicodeerror)
					self.in_loginauth=2
					self.push('334 %s'%binascii.b2a_base64(
								"Password:".encode("UTF8",
											unicodeerror)).decode("UTF8",
											unicodeerror)[:-1])
					self._SMTPChannel__line=[]
					return
				elif self.in_loginauth==2:
					self.password=binascii.a2b_base64(
										line).decode("UTF-8",unicodeerror)

					if self.smtp_server.authenticate(
										self.user,
										self.password):
						self.push("235 Authentication successful.")
						self.is_authenticated=True
						self.is_admin=self.parent.is_admin(self.user)
					else:
						self.push("454 Temporary authentication failure.")
						self.parent.log(
							"User '%s' failed to AUTH LOGIN login"%self.user
							,"w")

					self.in_loginauth=0
					self._SMTPChannel__line=[]
					return

			if not command in (SIMPLECOMMANDS+["AUTH"]):
				self.push("530 Authentication required.")
				self._SMTPChannel__line=[]
				return

		if not self.is_admin:

			if command in _gpgmailencryptserver.ADMINCOMMANDS:
				self.push("530 Admin authentication required.")
				self._SMTPChannel__line=[]
				return

		if self.use_tls and self.force_tls and not self.tls_active:

			if not command in (SIMPLECOMMANDS+
				_gpgmailencryptserver.ADMINCOMMANDS):
				self.parent.log("STARTTLS before authentication required."
								" Command was '%s'"%command)
				self.push("530 STARTTLS before authentication required.")
				self._SMTPChannel__line=[]
				return

		smtpd.SMTPChannel.found_terminator(self)

	######
	#_dash
	######

	def _dash(self,count):

		if count>0:
			return "-"
		else:
			return " "

	#############
	#reset_values
	#############

	def reset_values(self):
		self.parent.debug("_gpgmailencryptserver: reset_values")
		self.is_authenticated=False
		self.is_admin=False
		self.user=""
		self.password=""
		self.seen_greeting=False

	#############
	#handle_error
	#############

	def handle_error(self):
		self.parent.debug("handle_error")
		self.handle_close()

	#SMTP Commands

	##########
	#smtp_HELO
	##########

	def smtp_HELO(self,arg):
		self.parent.debug("_gpgmailencryptserver: HELO")

		if not arg:
				   self.push('501 Syntax: HELO hostname')
				   return

		if self.seen_greeting:
			self.push('503 Duplicate HELO/EHLO')
		else:
			self.seen_greeting = True
			self.push('250 %s' % self.fqdn)

	##########
	#smtp_EHLO
	##########

	def smtp_EHLO(self, arg):
		self.parent.debug("_gpgmailencryptserver: EHLO")

		if not arg:
			self.push('501 Syntax: EHLO hostname')
			return

		if self.seen_greeting:
			self.push('503 Duplicate HELO/EHLO')
			return
		else:
			self.seen_greeting = arg
			self.extended_smtp = True

		_starttls=self.use_tls and not self.tls_active
		_size=self.data_size_limit>0
		_auth=(self.use_authentication
				   and (not self.force_tls
				   or (self.force_tls and self.tls_active))
			  )
		countentries=  _starttls+_size+_auth
		self.push('250%s%s' % (self._dash(countentries),self.fqdn) )
		countentries-=1

		if _starttls:
			self.push('250%sSTARTTLS'%self._dash(countentries))
			countentries-=1

		if _size:
			self.push('250%sSIZE %s' % (self._dash(countentries),
										self.data_size_limit))
			countentries-=1

		if _auth:
			self.push('250%sAUTH LOGIN PLAIN'%self._dash(countentries))
			countentries-=1

	##########
	#smtp_RSET
	##########

	def smtp_RSET(self, arg):
		self.parent.debug("_gpgmailencryptserver: RSET")
		self.reset_values()
		smtpd.SMTPChannel.smtp_RSET(self,arg)

	##########
	#smtp_AUTH
	##########

	def smtp_AUTH(self,arg):
		self.parent.debug("_gpgmailencryptserver: AUTH")

		if not self.use_authentication and not self.adminmode:
			self.push("503 Error: authentication not enabled")
			return

		if not arg:
			self.push("501 Syntax error: AUTH PLAIN")
			return

		res=arg.split()

		if self.in_loginauth==0:

			for command in res:

				if "LOGIN" in command.upper():
					self.in_loginauth=1

					if len(res)>1:
						self.username=binascii.a2b_base64(
										res[1]).decode("UTF-8",unicodeerror)
						self.in_loginauth=2
					else:
						 self.push('334 %s'%binascii.b2a_base64(
							"Username:".encode("UTF8",
									unicodeerror)).decode("UTF8",
									unicodeerror)[:-1])
					return

		if len(res)<2:
		   self.push("454 Temporary authentication failure.")
		   return

		command=res[0]
		command,encoded=res

		if "PLAIN" in command.upper():
			self.parent.debug("_gpgmailencryptserver: PLAIN decoding")

			try:
				d=binascii.a2b_base64(encoded).decode(
								"UTF-8",
								unicodeerror).split('\x00')
			except:
				self.parent.debug(
							"_gpgmailencryptserver: error decode base64 '%s'"%
							sys.exc_info()[1])
				d=[]

			if len(d)<2:
				self.push("454 Temporary authentication failure.")
				return

			while len(d)>2:
				del d[0]

			user=d[0]
			password=d[1]

			if (self.smtp_server.authenticate(user,password)):
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

	##############
	#smtp_STARTTLS
	##############

	def smtp_STARTTLS(self,arg):
		self.parent.debug("_gpgmailencryptserver: STARTTLS")

		if self.use_tls==False:
				self.push("454 TLS not available due to temporary reason")
				self.parent.log("STARTTLS called, but is not active","w")
				return

		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return

		self.push("220 Go ahead")
		conn=self.smtp_server.create_sslconnection(self.conn)
		self.conn=conn
		self.set_socket(conn)
		self.reset_values()
		self.tls_active=True

	#ADMIN functions

	###########
	#smtp_DEBUG
	###########

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

	################
	#smtp_QUARANTINE
	################

	def smtp_QUARANTINE(self,arg):
		syntaxerror=("501 Syntax error: QUARANTINE SHOW|DELETE xxx|RELEASE xxx"
			"|FORWARD xxx email@tld")

		if not arg:
			self.push(syntaxerror)
			return

		res=arg.split()
		command=res[0].upper()

		if ((command=="SHOW" and len(res)!=1)
		or (command in ["DELETE","RELEASE"] and len(res)!=2)
		or (command=="FORWARD" and len(res)!=3)):
			self.push(syntaxerror)
			return

		if command=="SHOW":
			l=self.parent.get_quarantinelist()
			c=len(l)-1

			if c>=0:
				for i in l:
					dash=self._dash(c)
					c-=1
					msg="%s %s %s"%(i[3],i[1],i[2])
					self.push("250%s%s"%(dash,msg))
			else:
				self.push("250 No viruses found")

		elif command=="DELETE":

			try:
				v_id=float(res[1])
				res=self.parent.quarantine_remove(v_id)
			except:
				self.parent.log("could not convert id to float","w")

			if res:
				self.push("250 OK")
			else:
				self.push("501 Couldn't delete %s"%str(v_id))

		elif command=="RELEASE":

			try:
				v_id=float(res[1])
				res=self.parent.quarantine_release(v_id)
			except:
				self.parent.log("could not convert id to float","w")

			if res:
				self.push("250 OK")
			else:
				self.push("501 Couldn't release %s"%str(v_id))

		elif command=="FORWARD":

			try:
				v_id=float(res[1])
				res=self.parent.quarantine_forward(v_id,res[2])
			except:
				self.parent.log("could not convert id to float","w")

			if res:
				self.push("250 OK")
			else:
				self.push("501 Couldn't forward %s"%str(v_id))

		else:
			self.push(syntaxerror)

	#####################
	#smtp_RESETSTATISTICS
	#####################

	def smtp_RESETSTATISTICS(self,arg):

		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return

		self.parent.reset_statistics()
		self.parent.log("smtp_RESETSTATISTICS")
		self.push("250 OK")

	###################
	#smtp_RESETMESSAGES
	###################

	def smtp_RESETMESSAGES(self,arg):

		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return

		self.parent.reset_messages()
		self.parent.log("smtp_RESETMESSAGES")
		self.push("250 OK")

	################
	#smtp_STATISTICS
	################

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

			self.push("250%s%s %s"%(dash,
									s.ljust(25),
									str(statistics[s]).rjust(4)) )
			c+=1

	##############
	#smtp_MESSAGES
	##############

	def smtp_MESSAGES(self,arg):

		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return

		_messages=self.parent._systemmessages
		c=0
		self.push("250-gpgmailencrypt version %s (%s)"%(VERSION,DATE))
		_now=datetime.datetime.now()
		self.push("250-Server runs %s"%(_now-self.parent._daemonstarttime))

		if len(_messages)==0:
			self.push("250 No messages.")
			return

		for s in _messages:
			dash="-"

			if c==len(_messages)-1:
				dash=" "

			self.push("250%s%s"%(dash,str(s)) )
			c+=1

	###########
	#smtp_FLUSH
	###########

	def smtp_FLUSH(self,arg):
		self.parent.log("FLUSH")
		self.parent.check_deferred_list()
		self.parent.check_mailqueue()
		self.push("250 OK")

	############
	#smtp_RELOAD
	############

	def smtp_RELOAD(self,arg):

		if arg:
			self.push("501 Syntax error: no arguments allowed")
			return

		self.parent.log("smtp_RELOAD configuration")
		self.parent.init()
		self.parent._parse_commandline()
		self.push("250 OK")

	###########
	#smtp_USERS
	###########

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

	#############
	#smtp_SETUSER
	#############

	def smtp_SETUSER(self,arg):

		if not arg:
			self.push("501 Syntax error: SETUSER user password")
			return

		res=arg.split()

		if len(res)!=2:
			self.push("501 Syntax error: SETUSER user password")
			return

		r=self.parent.adm_set_user(res[0],res[1])

		if r:
			self.push("250 OK")
		else:
			self.push("454 User could not be set")

	#############
	#smtp_DELUSER
	#############

	def smtp_DELUSER(self,arg):

		if not arg:
			self.push("501 Syntax error: DELUSER user")
			return

		res=arg.split()

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

	###########
	#smtp_ADMIN
	###########

	def smtp_ADMIN(self,arg):
		self.adminmode=True
		self.push("250 OK")
		return

	#################
	#smtp_CREATETABLE
	#################

	def smtp_CREATETABLE(self,arg):

		if not arg:
			self.push("501 Syntax error: CREATETABLE table")
			return

		res=arg.split()

		if len(res)!=1:
			self.push("501 Syntax error: CREATETABLE table")
			return

		if not self.parent._backend.create_table(res[0].lower(),logerror=True):
			self.push("454 Table definition '%s' could not be created"
				% res[0].lower())
			return

		self.push("250 OK")




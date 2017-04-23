#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import email
import email.utils
import os
import re
import subprocess
import tempfile
from	.child 			import _gmechild
from	.version		import *
from	._dbg 			import _dbg

#############
#CLASS _SMIME
#############

class _SMIME(_gmechild):
	"""class to encrypt and decrypt files for SMIME via openssl
	Don't call this class directly, use gme.smime_factory() instead!
	"""

	def __init__(   self,
					parent,
					keyhome=None):
		_gmechild.__init__(self,parent,filename=__file__)
		self.debug("_SMIME.__init__ %s"%self.parent._SMIMEKEYHOME)

		if type(keyhome)==str:
			self._keyhome = os.path.expanduser(keyhome)
		else:
			self._keyhome=os.path.expanduser(self.parent._SMIMEKEYHOME)

		self._recipient = ''
		self._filename=''
		self._recipient=None
		self.debug("_SMIME.__init__ end")

	############
	#public_keys
	############

	@_dbg
	def public_keys(self):
		"returns a list of all available public keys"
		return self.parent._backend.smimepublic_keys()

	#############
	#private_keys
	#############

	@_dbg
	def private_keys(self):
		"returns a list of all available private keys"
		return self.parent._backend.smimeprivate_keys()

	#############
	#set_filename
	#############

	@_dbg
	def set_filename(self, fname):
		"sets the filename of the file, which content has to be encrypted"

		if isinstance(fname,str):
			self._filename=fname.strip()
		else:
			self._filename=''

	############
	#set_keyhome
	############

	@_dbg
	def set_keyhome(self,keyhome):
		"sets the directory where the smime keys are stored"

		if isinstance(keyhome,str):
			self._keyhome=os.path.expanduser(keyhome.strip())
		else:
			self._keyhome=''

	############
	#get_keyhome
	############

	@_dbg
	def get_keyhome(self):
		"gets the directory where the smime keys are stored"

		return self._keyhome

 	##############
	#set_recipient
	##############

	@_dbg
	def set_recipient(self, recipient):
		"set the recipient e-mail address, for which the data will be encrypted"

		if isinstance(recipient, str):
			self._recipient=email.utils.parseaddr(recipient)[1]

	##########
	#recipient
	##########

	@_dbg
	def recipient(self):
		"returns the recipient address"
		return self._recipient

	###############
	#has_public_key
	###############

	@_dbg
	def has_public_key(self,key):
		"""returns True if a public key for e-mail address 'key' exists,
			else False
		"""

		if not isinstance(key,str):
			self.debug("smime has_public_key, key not of type str")
			return False

		key=key.lower()
		key=email.utils.parseaddr(key)[1]

		try:
			_u=self.parent._backend.smimeuser(key)
		except:
		   self.debug("smime has_public_key, key not found for '%s'"%key)
		   return False

		return True

	#############
	#encrypt_file
	#############

	@_dbg
	def encrypt_file(   self,
						filename=None,
						binary=False,
						recipient=None):
		"""
		encrypts the content of a file.

		return values:
		result: True if success, else False
		encdata: If 'result' is True, a (binary) string with the encrypted data
				 else None
		"""
		result=False

		if filename:
			self.set_filename(filename)

		if len(self._filename) == 0:
			self.log( 'Error: _SMIME: filename not set',"m")
			return result,''

		if recipient:
			self.set_recipient(recipient)

		if len(self._recipient)==0:
			self.log("SMIME encrypt file: No recipient set!","e")
			return result,None

		try:
			_recipient=self.parent._backend.smimeuser(self._recipient)
		except:
			return result, None

		f=self.parent._new_tempfile()
		self.debug("_SMIME.encrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call(
				' '.join(self._command_encrypt_fromfile( f.name,
														 binary))
			   ,shell=True )
		self.debug("Encryption command: '%s'" %
						' '.join(self._command_encrypt_fromfile(f.name,binary)))

		if _result != 0:
		  self.log("Error executing command (Error code %d)"%_result,"e")
		  self.log(' '.join(self._command_encrypt_fromfile(f.name,binary)),"e")
		  return result,None
		else:
			result=True

		res=open(f.name,encoding="UTF-8",errors=unicodeerror)
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		m=email.message_from_string(encdata)
		return result,m.get_payload()

	##########################
	#_command_encrypt_fromfile
	##########################

	@_dbg
	def _command_encrypt_fromfile(  self,
									sourcefile,
									binary):
		try:
			_recipient=self.parent._backend.smimeuser(self._recipient)
		except:
			_recipient=["norecipient"]
			self.log_traceback()

		encrypt="des3" # RFC 3583

		if _recipient[1]=="AES256":
			encrypt="aes-256-cbc"
		elif _recipient[1]=="AES128":
			encrypt="aes-128-cbc"
		elif _recipient[1]=="AES192":
			encrypt="aes-192-cbc"

		cmd=[   self.parent._SMIMECMD,
				"smime",
				"-%s" %encrypt,
				"-encrypt",
				"-in",self._filename,
				"-out", sourcefile,
				_recipient[0] ]
		return cmd

	#############
	#decrypt_file
	#############

	@_dbg
	def decrypt_file(   self,
						filename=None,
						binary=False,
						recipient=None):
		"""
		decrypts the content of a file.

		return values:
		result: True if success, else False
		encdata: If 'result' is True, a (binary) string with the decrypted data
				 else None
		"""
		result=False

		if filename:
			self.set_filename(filename)

		if len(self._filename) == 0:
			self.log( 'Error: _SMIME: filename not set',"m")
			return result,''

		if recipient:
			self.set_recipient(recipient)

		f=self.parent._new_tempfile()
		self.debug("_SMIME.decrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call(
				' '.join(self._command_decrypt_fromfile(f.name,
														binary))
				,shell=True )
		self.debug("Decryption command: '%s'" %
				' '.join(self._command_decrypt_fromfile(f.name,binary)))

		if _result != 0:
			self.log("Error executing command (Error code %d)"%
						_result,"e")
			self.log(' '.join(self._command_decrypt_fromfile(f.name,binary))
			,"e")
		else:
			result=True

		res=open(f.name,encoding="UTF-8",errors=unicodeerror)
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		m=email.message_from_string(encdata)
		return result,m.get_payload()

	###########################
	#_command_decrypt_from_file
	###########################

	@_dbg
	def _command_decrypt_fromfile(  self,
									sourcefile,
									binary):
		_recipient=self.parent._backend.smimeuser(self._recipient)
		cmd=[self.parent._SMIMECMD,
				"smime",
				"-decrypt",
				"-in",self._filename,
				"-out", sourcefile,
				"-inkey" , _recipient[2] ]
		return cmd

	############
	#_opensslcmd
	############

	@_dbg
	def _opensslcmd(self,cmd):
		result=""
		p = subprocess.Popen(   cmd.split(" "),
								stdin=None,
								stdout=subprocess.PIPE,
								stderr=subprocess.PIPE )
		result=p.stdout.read()
		return result, p.returncode

	#######################
	#get_certemailaddresses
	#######################

	@_dbg
	def get_certemailaddresses(self,certfile):
		"""returns a list of all e-mail addresses the 'certfile' for which
		is valid."""
		cmd=[   self.parent._SMIMECMD,
				"x509",
				"-in",certfile,
				"-text",
				"-noout"]
		cert,returncode=self._opensslcmd(" ".join(cmd))
		cert=cert.decode("utf-8",unicodeerror)
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

	####################
	#get_certfingerprint
	####################

	@_dbg
	def get_certfingerprint(self,cert):
		"""
		returns the fingerprint of a cert file
		"""
		cmd=[self.parent._SMIMECMD,
				"x509",
				"-fingerprint",
				"-in",cert,
				"-noout"]
		fingerprint,returncode=self._opensslcmd(" ".join(cmd))
		found= re.search(   "(?<=SHA1 Fingerprint=)(.*)",
							fingerprint.decode("UTF-8",unicodeerror))

		if found != None:

			try:
				fingerprint=fingerprint[found.start():found.end()]
			except:
				pass

		return fingerprint

	############################
	#extract_publickey_from_mail
	############################

	@_dbg
	def extract_publickey_from_mail(self,
									mail,
									targetdir):
		"""
		smime messages usually contain the public key of the sender address.
		This function extracts the key and stores it in the directory
		'targetdir'.
		"""
		self.debug("extract_publickey_from_mail to '%s'"%targetdir)
		f=tempfile.NamedTemporaryFile(mode='wb',delete=False,prefix='mail-')
		fname=f.name

		if isinstance(mail,email.message.Message):
			mail=mail.as_string()

		if not isinstance(mail,str):
			self.log("smimeclass mail object of wrong type","e")
			return None

		mailfile=self.parent._new_tempfile()
		mailfile.write(mail.encode("UTF-8",unicodeerror))
		mailfile.close()

		cmd=[   self.parent._SMIMECMD,
				"smime",
				"-in", mailfile.name,
				"-pk7out",
				"2>/dev/null","|",

				self.parent._SMIMECMD,
				"pkcs7",
				"-print_certs",
				"-out",f.name,
				"2>/dev/null"]
		self.debug("extractcmd :'%s'"%" ".join(cmd))
		_result = subprocess.call( " ".join(cmd) ,shell=True)
		f.close()
		size=os.path.getsize(fname)
		self.parent._del_tempfile(mailfile.name)

		if size==0:
			os.remove(fname)
			return None

		fp=self.get_certfingerprint(fname)
		targetname=os.path.join(targetdir,"%s.pem"%fp)
		self._copyfile(fname,targetname)
		os.remove(fname)
		return targetname

	###############
	#create_keylist
	###############

	@_dbg
	def create_keylist(self,directory):
		"""
		returns a dictonary of e-mail addresses with its key, automatically
		created from the files in 'directory'
		"""
		result={}
		directory=os.path.expanduser(directory)

		try:
			_udir=os.listdir(directory)
		except:
			self.log("class _SMIME.create_keylist, "
			"couldn't read directory '%s'"%directory)
			return result

		_match="^(.*?).pem"

		for _i in _udir:

			  if re.match(_match,_i):
				  f=os.path.join(directory,_i)
				  emailaddress=self.get_certemailaddresses(f)

				  if len(emailaddress)>0:

					  for e in emailaddress:
						  result[e.lower()] = [f,self.parent._SMIMECIPHER]

		return result

	###################
	#verify_certificate
	###################

	@_dbg
	def verify_certificate(self,cert):
		"""
		returns True if the certificate  in the file 'cert' is valid,
		else False
		"""
		cmd=[   self._SMIMECMD,
				"verify",cert,"&>/dev/null"]
		_result = subprocess.call( " ".join(cmd) ,shell=True)
		return _result==0

	##########
	#_copyfile
	##########

	@_dbg
	def _copyfile(self,src, dst):
		length=16*1024

		try:

			with open(os.path.expanduser(src), 'rb') as fsrc:

				with open(os.path.expanduser(dst), 'wb') as fdst:

						while 1:
							buf = fsrc.read(length)

							if not buf:
									break

							fdst.write(buf)
		except:
			self.log("Class smime._copyfile: Couldn't copy file!","e")
			self.log_traceback()



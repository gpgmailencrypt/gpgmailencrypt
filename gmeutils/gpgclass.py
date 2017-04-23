#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import email
import email.utils
from   email.generator	import Generator
from   io 				import StringIO
import os
import re
import subprocess
from	.child 			import _gmechild
from   	.helpers 		import *

from	.version		import *
from	._dbg 			import _dbg
###########
#CLASS _GPG
###########

class _GPG(_gmechild):
	"""class to encrypt and decrypt files via gpg
	Don't call this class directly, use gme.gpg_factory() instead!
	"""

	def __init__(   self,
					parent,
					keyhome=None):
		_gmechild.__init__(self,parent,filename=__file__)
		self._recipient = ''
		self._filename=''
		self.count=0
		self.debug("_GPG.__init__")
		self._localGPGkeys=list()
		self._local_from_user=None
		self.set_recipient(None)

		if isinstance(keyhome,str):
			self._keyhome = os.path.expanduser(keyhome)
		elif self.parent and self.parent._GPGKEYHOME:
			self._keyhome=os.path.expanduser(self.parent._GPGKEYHOME)
		else:
			self._keyhome=os.path.expanduser('~/.gnupg')

		self._local_gpg_dir=""
		self.debug("_GPG.__init__ end")

	#############
	#_set_counter
	#############

	@_dbg
	def _set_counter(self,counter):
		self.count=counter

	############
	#set_filname
	############

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
		"sets the directory where the gpg keyring is stored"

		if isinstance(keyhome,str):
			self._keyhome=os.path.expanduser(keyhome.strip())
		else:
			self._keyhome=''

	############
	#get_keyhome
	############

	@_dbg
	def get_keyhome(self):
		"gets the directory where the gpg keyring is stored"

		return self._keyhome

 	##############
 	#set_recipient
 	##############

	@_dbg
	def set_recipient(self, recipient):
		"set the recipient e-mail address, for which the data will be encrypted"

		if isinstance(recipient, str):
			self._recipient=email.utils.parseaddr(recipient)[1]
			self.parent._GPGkeys = list()

	##########
	#recipient
	##########

	@_dbg
	def recipient(self):
		"returns the recipient address"
		return self._recipient

	#############
	#set_fromuser
	#############

	@_dbg
	def set_fromuser(self, user):
		user=email.utils.parseaddr(user)[1].lower()
		domain=None
		addr=user.split('@')

		if len(addr)==2:
			domain = addr[1]

		if domain and (domain in self.parent._HOMEDOMAINS):

			if self._local_from_user!= user:
				self._get_public_keys_from(from_user=user)

	#########
	#fromuser
	#########

	def fromuser(self):
		return self._local_from_user

	############
	#public_keys
	############

	@_dbg
	def public_keys(self):
		"returns a list of all available public keys"

		if len(self.parent._GPGkeys)==0:
			self._get_public_keys()

		return self.parent._GPGkeys

	#############
	#private_keys
	#############

	@_dbg
	def private_keys(self):
		"returns a list of all available private keys"

		if len(self.parent._GPGprivatekeys)==0:
			self._get_private_keys()

		return self.parent._GPGprivatekeys

	###############
	#has_public_key
	###############

	@_dbg
	def has_public_key(self,key):
		"""returns True if a public key for e-mail address 'key' exists,
			else False
		"""
		self.debug("gpg.has_public_key '%s'"%key)

		if len(self.parent._GPGkeys)==0:
			self._get_public_keys()

		if not isinstance(key,str):
			self.debug("has_public_key, key not of type str")
			return False
		key=email.utils.parseaddr(key)[1]
		key=key.lower()

		if key in self._localGPGkeys:
			self.debug("has_publickey, key %s found in _localGPGkeys"%key)
			return True
		elif key in self.parent._GPGkeys:
			return True
		else:
			self.debug("has_publickey, key not in _GPGkeys")
			self.debug("_GPGkeys '%s'"%str(self.parent._GPGkeys))
			return False

	#################
	#_get_public_keys
	#################

	@_dbg
	def _get_public_keys( self):
		self._get_public_keys_from(from_user=None)

	######################
	#_get_public_keys_from
	######################

	@_dbg
	def _get_public_keys_from( self, from_user=None ):
		self.debug("_GPG._get_public_keys")

		if from_user==None:
			self.parent._GPGkeys = list()
			keys=self.parent._GPGkeys
			keyhome=self._keyhome.replace("%user",self._recipient)
		else:
			self._localGPGkeys=list()
			self._local_from_user=from_user
			self._local_gpg_dir=os.path.join(	self._keyhome,
												clean_filename(from_user))
			keys=self._localGPGkeys
			keyhome=self._local_gpg_dir

			if not os.path.exists(keyhome):
				os.makedirs(keyhome)
				os.chmod(keyhome,0o700)
				self.debug("_GPG.public_keys homedirectory '%s' created"%
							keyhome)

		cmd = '%s --homedir %s --list-keys --with-colons' % (
					self.parent._GPGCMD, keyhome)
		self.debug("_GPG.public_keys command: '%s'"%cmd)

		try:
			p = subprocess.Popen(   cmd.split(' '),
									stdin=None,
									stdout=subprocess.PIPE,
									stderr=subprocess.PIPE )
			p.wait()

			for line in p.stdout.readlines():
				res=line.decode(self.parent._encoding,unicodeerror).split(":")

				if (res[0]=="pub"
				or res[0]=="uid"):
					email=res[9]
					mail_id=res[4]

					try:
					   found=re.search(
					   "[-a-zA-Z0-9_%\+\.]+@[-_0-9a-zA-Z\.]+\.[-_0-9a-zA-Z\.]+",
					   email)
					except:
						self.log_traceback()

					if found != None:

						try:
							email=email[found.start():found.end()]
						except:
							self.log("splitting email address (%s) "
											"didn't work"%email,"w")
							email=""

						email=email.lower()

						if (len(email)>0
						and keys.count(email) == 0):
							keys.append(email)

		except:
			self.log("Error opening keyring (Perhaps wrong "
							"directory '%s'?)"%keyhome,"e")
			self.log_traceback()

	##################
	#_get_private_keys
	##################

	@_dbg
	def _get_private_keys( self ):
		self.debug("_GPG._get_private_keys")
		self.parent._GPGprivatekeys = list()
		cmd = '%s --homedir %s --list-secret-keys --with-colons' % (
					self.parent._GPGCMD,
					self._keyhome.replace("%user",self._recipient))
		self.debug("_GPG.private_keys command: '%s'"%cmd)

		try:
			p = subprocess.Popen(   cmd.split(' '),
									stdin=None,
									stdout=subprocess.PIPE,
									stderr=subprocess.PIPE )
			p.wait()

			for line in p.stdout.readlines():
				res=line.decode(self.parent._encoding,unicodeerror).split(":")

				if res[0]=="pub" or res[0]=="uid":
					email=res[9]
					mail_id=res[4]

					try:
						found=re.search(
						"[-a-zA-Z0-9_%\+\.]+@[-_0-9a-zA-Z\.]+"
						"\.[-_0-9a-zA-Z\.]+",
						email)
					except:
						self.log_traceback()

					if found != None:

						try:
							email=email[found.start():found.end()]
						except:
							self.log("splitting email address (%s) "
											"didn't work"%email,"w")
							email=""

						email=email.lower()

						if (len(email)>0
						and self.parent._GPGprivatekeys.count(email) == 0):
							self.parent._GPGprivatekeys.append(email)

		except:
			self.log("Error opening keyring (Perhaps wrong "
							"directory '%s'?)"%self._keyhome,"e")
			self.log_traceback()

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
			self.log( 'Error: GPGEncrypt: filename not set',"e")
			return result,None

		if recipient:
			self.set_recipient(recipient)

		if len(self._recipient)==0:
			self.log("GPG encrypt file: No recipient set!","e")
			return result,None

		f=self.parent._new_tempfile()
		self.debug("_GPG.encrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call(
					' '.join(self._encryptcommand_fromfile(f.name,binary)),
					shell=True )
		self.debug("Encryption command: '%s'" %
					' '.join(self._encryptcommand_fromfile(f.name,binary)))

		if _result != 0:
			self.log("Error executing command (Error code %d)"%_result,
							"e")
			self.log(' '.join(self._encryptcommand_fromfile(f.name,binary)),"e")
			return result,None
		else:
			result=True

		if binary:
			res=open(f.name,mode="br")
			self.debug("GPG.encrypt_file binary open")
		else:
			res=open(f.name,encoding="UTF-8",errors=unicodeerror)
			self.debug("GPG.encrypt_file text open")

		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		return result,encdata

	#########################
	#_encryptcommand_fromfile
	#########################

	@_dbg
	def _encryptcommand_fromfile(   self,
									sourcefile,
									binary):

		if self._recipient in self._localGPGkeys:
			keyhome=self._local_gpg_dir
		else:
			keyhome=self._keyhome.replace("%user",self._recipient)

		cmd=[self.parent._GPGCMD,
								"--trust-model", "always",
								"-r",self._recipient,
								"--homedir", keyhome,
								"--batch",
								"--yes",
								"--pgp7",
								"-q",
								"--no-secmem-warning",
								"--output",sourcefile, "-e",self._filename ]

		if self.parent._ALLOWGPGCOMMENT==True:
			cmd.insert(1,"'%s'"%self.parent._encryptgpgcomment)
			cmd.insert(1,"--comment")

		if not binary:
			cmd.insert(1,"-a")

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

		if recipient:
			self.set_recipient(recipient)

		if filename:
			self.set_filename(filename)

		if len(self._filename) == 0:
			self.log( 'Error: GPGDecrypt: filename not set',"e")
			return result,None

		f=self.parent._new_tempfile()
		self.debug("_GPG.decrypt_file _new_tempfile %s"%f.name)
		f.close()
		_result = subprocess.call(
			' '.join(self._decryptcommand_fromfile(f.name,binary)),shell=True )
		self.debug("Encryption command: '%s'" %
			' '.join(self._decryptcommand_fromfile(f.name,binary)))

		if _result != 0:
			self.log("Error executing command (Error code %d)"%_result,
							"e")
			self.log(' '.join(self._decryptcommand_fromfile(f.name,binary)),"e")
		else:
			result=True

		if binary:
			res=open(f.name,mode="br")
			self.debug("GPG.decrypt_file binary open")
		else:
			res=open(f.name)
			self.debug("GPG.decrypt_file text open")

		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		return result,encdata

	#########################
	#_decryptcommand_fromfile
	#########################

	@_dbg
	def _decryptcommand_fromfile(   self,
									sourcefile,
									binary):
		cmd=[self.parent._GPGCMD,
					"--trust-model", "always",
					"-q",
					"-r",self._recipient,
					"--homedir", self._keyhome.replace("%user",self._recipient),
					"--batch",
					"--yes",
					"--pgp7",
					"--no-secmem-warning",
					"--output",sourcefile,
					"-d",self._filename ]

		if not binary:
			cmd.insert(1,"-a")

		return cmd

	############################
	#extract_publickey_from_mail
	############################

	@_dbg
	def extract_publickey_from_mail(self,
									mail,
									targetdir):
		"""
		messages can contain the public key of the sender address.
		This function extracts the key and stores it in the directory
		'targetdir'. 'mail' is a email.message.Message object
		"""
		self.debug("gpgclass extract_publickey_from_mail to '%s'"%targetdir)

		if isinstance(mail,str):
			mail=email.message_from_string(mail)

		if not isinstance(mail,email.message.Message):
			self.log("gpgclass mail object of wrong type","e")
			return None

		for part in mail.walk():
			contenttype=part.get_content_type()

			if contenttype!="application/pgp-keys":
				continue

			filename = part.get_filename()
			payload=part.get_payload(decode=True)

			if not payload:
				self.log("pgpkey attachment returned None as payload","e")
				continue

			targetname=os.path.expanduser(os.path.join(targetdir,filename))

			try:

				with open(targetname,"wb") as f:
					f.write(payload)

				self.debug("write to file %s"%targetname)

			except:
				self.log("gpg key could not be written","e")
				self.log_traceback()


#############################
#CLASS GPGENCRYPTEDATTACHMENT
#############################

class _GPGEncryptedAttachment(email.message.Message,_gmechild):

	def  __init__(self,parent=None):
		email.message.Message. __init__(self)
		_gmechild.__init__(self,parent,filename=__file__)
		self._masterboundary=None
		self._filename=None
		self.set_type("text/plain")

	##########
	#as_string
	##########

	def as_string(self, unixfrom=False):
		fp = StringIO()
		g = Generator(fp)
		g.flatten(self, unixfrom=unixfrom)
		return fp.getvalue()

	#############
	#set_filename
	#############

	def set_filename(self,f):
		self._filename=f

	#############
	#get_filename
	#############

	def get_filename(self):

		if self._filename != None:
			return self._filename
		else:
			return decode_filename(email.message.Message.get_filename(self))

	###################
	#set_masterboundary
	###################

	def set_masterboundary(self,b):
		self._masterboundary=b

	###############
	#_write_headers
	###############

	def _write_headers(self,g):
		print ("Content-Type: application/pgp-encrypted",file=g._fp)
		print ("Content-Description: PGP/MIME version identification\r\n"
				"\r\nVersion: 1\r\n",file=g._fp)
		print ("--%s"%self._masterboundary,file=g._fp)
		fname=self.get_filename()

		if fname == None:
			fname="encrypted.asc"

		print ('Content-Type: application/octet-stream; name="%s"'%fname,
																file=g._fp)
		print ('Content-Description: OpenPGP encrypted message',file=g._fp)
		print ('Content-Disposition: inline; filename="%s"\r\n'%fname,file=g._fp)

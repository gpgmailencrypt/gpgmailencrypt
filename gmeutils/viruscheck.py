#!/usr/bin/env python3
import datetime
import email
import email.message
import os
import pyclamd
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(1,"/home/horst/Programmierecke/gpgmailencrypt")

from gpgmailencrypt import _ZIP,_baseunpacker


class parentdummy:
	def __init__(self):
		self._daemonstarttime=datetime.datetime.now()
		self._ZIPCIPHER="AES128"
		self._7ZIPCMD=shutil.which("7za")
		self._VIRUSSCANUSER="horst"

	def init(self):
		pass
	def debug(self,msg):
		print(msg)
	def log(self,msg,txt=""):
		self.debug(msg)
	def log_traceback(self):
		raise
	def is_admin(self,name):
		return True
	def get_statistics(self):
		return {"test":"result"}
	def reset_statistics(self):
		pass
	def _parse_commandline(self):
		pass
	def adm_get_users(self):
		"returns a list of all users and whether or not the user is a admin"
		users=[{"user":"xyz","admin":True}]
		return users
	def adm_set_user(self,user,password):
		pass
	def adm_del_user(self,user):
		pass
	def check_deferred_list(self):
		pass
	def check_mailqueue(self):
		pass
	def set_debug(self,d):
		pass
	def zip_factory(self):
		"returns a ZIP class"
		return _ZIP(self)

#####
#_TAR
#####

class _TAR(_baseunpacker):
	def __init__(self):
		self._cmd=shutil.which("tar")

	################
	#uncompress_file
	################

	def uncompress_file(self, filename,directory=None):
		result=False

		if directory==None:
			directory = tempfile.mkdtemp()
			print("tar mkdtmpdir",directory)

		untarcmd=' '.join(self._tarcommand_indir(filename,directory))
		print("tar",untarcmd)		
		_result = subprocess.call(untarcmd, shell=True) 

		if _result !=0:
		  #self.parent.log("Error executing command (Error code %d)"%_result,"e")
		  return result,None
		else:
			result=True

		return result,directory
	
	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["TAR","TARBZ2","TARBZ","TARGZ"]

	##################
	#_tarcommand_indir
	##################

	def _tarcommand_indir(  self,
									sourcefile,
									directory):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()

		if extension in ["bz2","tbz2"]:
			format="j"
		elif extension in ["xz"]:
			format="J"
		elif extension in ["gz","tgz"]:
			format="x"
		
		cmd=[   self._cmd, 
				"-x%s"%format,
				"-f",sourcefile,
				"-C%s"%directory,
			]
		return cmd

#####
#_BZ2
#####

class _BZ2(_baseunpacker):
	def __init__(self):
		self._cmd=shutil.which("bunzip2")

	################
	#uncompress_file
	################

	def uncompress_file(self, filename,directory=None):
		result=False

		if directory==None:
			directory = tempfile.mkdtemp()
			print("bz2 mkdtmpdir",directory)

		unbz2cmd=' '.join(self._bz2command_indir(filename,directory))
		print("bz2",unbz2cmd)		
		_result = subprocess.call(unbz2cmd, shell=True) 

		if _result !=0:
		  #self.parent.log("Error executing command (Error code %d)"%_result,"e")
		  return result,None
		else:
			result=True

		return result,directory
	
	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["BZIP","BZIP2"]

	##################
	#_bz2command_indir
	##################

	def _bz2command_indir(  self,
									sourcefile,
									directory):
		format=""
		print("TODO in Unterverzeichnis entpacken")
		cmd=[   self._cmd, 
				"-d",sourcefile,
				#"\"-C%s\""%directory,
			]
		return cmd

#####
#_RAR
#####

class _RAR(_baseunpacker):
	def __init__(self):
		self._cmd=shutil.which("unrar")

	################
	#uncompress_file
	################

	def uncompress_file(self, filename,directory=None):
		result=False

		if directory==None:
			directory = tempfile.mkdtemp()
			print("rar mkdtmpdir",directory)

		unrarcmd=' '.join(self._rarcommand_indir(filename,directory))
		print("rar",unrarcmd)		
		_result = subprocess.call(unrarcmd, shell=True) 

		if _result !=0:
		  #self.parent.log("Error executing command (Error code %d)"%_result,"e")
		  return result,None
		else:
			result=True

		return result,directory
	
	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["RAR"]

	##################
	#_rarcommand_indir
	##################

	def _rarcommand_indir(  self,
									sourcefile,
									directory):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()

		cmd=[   self._cmd, 
				"e",sourcefile,
				directory,
				">/dev/null"
			]
		return cmd

#####
#_ARJ
#####

class _ARJ(_baseunpacker):

	def __init__(self):
		self._cmd=shutil.which("arj")

	################
	#uncompress_file
	################

	def uncompress_file(self, filename,directory=None):
		result=False

		if directory==None:
			directory = tempfile.mkdtemp()
			print("ARJ mkdtmpdir",directory)

		unarjcmd=' '.join(self._unarjcommand_indir(filename,directory))
		print("ARJ",unarjcmd)		
		_result = subprocess.call(unarjcmd, shell=True) 

		if _result !=0:
		  #self.parent.log("Error executing command (Error code %d)"%_result,"e")
		  return result,None
		else:
			result=True

		return result,directory

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ARJ"]
 
	############################
	#_ununarjcommand_indir
	############################

	def _unarjcommand_indir(  self,
									sourcefile,
									directory):
		#arj x  package.arj "-httarget" -u -y -r
		cmd=[   self._cmd, 
				"x",sourcefile,
				"\"-ht%s\""%directory,
				"-u",
				"-y",
				"-r",
				">/dev/null"]
		return cmd

class _basevirusscanner:
	def __init__(self):
		pass

	def has_virus(self,directory):
		raise NotImplementedError

############
#_clamavscan
############

class _clamavscan(_basevirusscanner):
	def __init__(self):
		self.clamd=pyclamd.ClamdAgnostic()
		pass

	def has_virus(self,directory):
		result=False
		scanresult=self.clamd.scan_file(directory)
		information=[]

		if scanresult!=None and len(scanresult)>0:
			result=True

			for a in scanresult:
				filename=os.path.split(a)[1]
				information.append(["CLAMAV",filename,scanresult[a][1]])
			
		return result,information

###########
#viruscheck
###########

class viruscheck():
	
	def __init__(self,parent):
		self.parent=parent 
		self.debug("viruscheck __init__")
		self.archivemap={}
		self.unpacker={}
		self.virusscanner={}
		self._search_archivemanager()
		self._search_virusscanner()

	######
	#debug
	######

	def debug(self,dbg):
		self.parent.debug(dbg)
		
	#########
	#
	#########

	def log(self,lg,infotype="m"):
		self.parent.log(lg,infotype)
		
	##############
	#log_traceback
	##############

	def log_traceback(self):
		self.parent.log_traceback()
		
	###########
	#_mktempdir
	###########
	def _mktempdir(self,directory=None):
		return tempfile.mkdtemp(dir=directory)

	def _chmod(self,directory):
		for root, directories, files in os.walk(directory):  

			for d in directories:  
				pathd=os.path.join(root,d)
				os.chmod(pathd,0o770)

			for f in files:
				pathf=os.path.join(root,f)
				os.chmod(pathf,0o640)

			os.chmod(directory,0o770)
				
	#####################
	#_search_virusscanner
	#####################

	def _search_virusscanner(self):

		try:
			clamd=pyclamd.ClamdAgnostic()
			scanner=_clamavscan()
			self.virusscanner["CLAMAV"]=scanner
		except:
			pass

	#######################
	#_search_archivemanager
	#######################

	def _search_archivemanager(self):
		self.unpacker["SEVENZIP"]=_ZIP(self.parent)
		_archivemanager={}
		_archivemanager["SEVENZIP"]=self.unpacker["SEVENZIP"].unpackingformats()
		arj=shutil.which("arj")

		if len(arj)>0:
			self.unpacker["ARJ"]=_ARJ()
			_archivemanager["ARJ"]=self.unpacker["ARJ"].unpackingformats()
	
		tar=shutil.which("tar")

		if len(tar)>0:
			self.unpacker["TAR"]=_TAR()
			_archivemanager["TAR"]=self.unpacker["TAR"].unpackingformats()
	
		bz2=shutil.which("bunzip2")

		if len(bz2)>0:
			self.unpacker["BUNZIP2"]=_BZ2()
			_archivemanager["BUNZIP2"]=self.unpacker["BUNZIP2"].unpackingformats()
	
		rar=shutil.which("unrar")

		if len(bz2)>0:
			self.unpacker["RAR"]=_RAR()
			_archivemanager["RAR"]=self.unpacker["RAR"].unpackingformats()
	
		for a in _archivemanager:
			self.log("Found archivemanager '%s'"%a)
			archiveformats=_archivemanager[a]

			for f in archiveformats:
				ff=f.upper()

				try:
					self.archivemap[ff]
				except:
					self.archivemap[ff]=a

	##################
	#_print_archivemap
	##################

	def _print_archivemap(self):
			for f in self.archivemap:
				print(("Format %s"%f).ljust(20)+"Unpacker %s"%self.archivemap[f]) 
		
	############
	#_is_archive
	############

	def _is_archive(self,filename,filetype):
		maintype,subtype=filetype.lower().split("/")
		fname, extension = os.path.splitext(filename)
		print("is_archive",filename,filetype)
		archivetype=None
		result=False
		subtypes={
			"zip":"ZIP",
			"x-compressed":"Z",
			"x-compress":"Z",
			"x-gzip":"GZIP",
			"x-gtar":"TGZ",
			"x-lzip":"LZ",
			"x-lzma":"LZMA",
			"x-lzh":"LZH",
			"x-lzip":"LZ",
			"x-lzop":"LZO",
			"x-zoo":"ZOO",
			"x-rar-compressed":"RAR",
			"x-7z-compressed":"7Z",
			"x-bzip":"BZIP",
			"x-bzip2":"BZIP2",
			"vnd.android.package-archive":None,
			"x-snappy-framed":None,
			"x-xz":"XZ",
			"x-ace-compressed":None,
			"x-astrotite-afa":None,
			"x-alz-compressed":None,
			"x-b1":None,
			"x-dar":None,
			"x-dgc-compressed":None,
			"x-apple-diskimage":None,
			"x-apple-diskimage":None,
			"x-lzx":"LZX",
			"x-arj":"ARJ",
			"x-tar":"TAR",
			"vnd.ms-cab-compressed":"CAB",
			"x-cfs-compressed":None,
			"x-stuffit":None,
			"x-stuffitx":None
			}
						  
		extensions={"zip":"ZIP","bz2":"BZIP2ARJ","deb":"DEB","tgz":"TARGZ",
				"bz":"BZIP","gz":"GZIP","7z":"7Z","s7z":"7ZRAR","ar":"AR",
				"xar":"AR","cpio":"CPIO","lz":"LZ","lzh":"LZH","lha":"LHA",
				"lzo":"LZO","lzma":"LZMA","xz":"Z","z":"Z","apk":"ZIP",
				"cab":"CABRPM","jar":"ZIP","zoo":"ZOO"}


		if maintype=="application":

			fname=os.path.split(filename)[1].lower()
			print("fname",fname)
			extension=extension[1:]
			tar=(".tar" in fname)
			print("istar",tar)
			
			print("EXTENSION",extension,subtype)

			if tar:
				if extension =="bz2":
					archivetype="TARBZ2"
				elif extension =="gz":
					archivetype="TARGZ"

				if archivetype!= None:
					result=True
					
					return result,archivetype
					

			try:
				archivetype=extensions[extension]
				result=True
				return result,archivetype
			except:
				pass	

			try:
				archivetype=subtypes[subtype]
				result=True
				return result,archivetype
			except:
				pass
				
		if archivetype!=None:
			result=True
			
		return result, archivetype

	##############
	#_unpack_email
	##############

	def _unpack_email(self, mail):

		if isinstance(mail,str):
			mail=email.message_from_string(mail)

		tmpdir=self._mktempdir()
		self.debug("has_virus tmpdir '%s'"%tmpdir)
		_c=0

		for payload in mail.walk():
			self.debug("\npayload %i"%_c)
			_c+=1
			is_attachment = payload.get_param(   
								'attachment', 
								None, 
								'Content-Disposition' ) is not None
			is_inline = payload.get_param( 
								'inline', 
								None, 
								'Content-Disposition' ) is not None

			if not is_attachment:
				self.debug("not an attachment")
				continue
			
			filename = payload.get_filename()
			fname=os.path.join(tmpdir,filename)
			contenttype = payload.get_content_type()

			try:
				with open(fname,"wb") as attachment:
					attachment.write(payload.get_payload(decode=True))
			except:
				self.log("file '%s' could not be stored"%filename)
				self.log_traceback()

			isarchive,archivetype=self._is_archive(filename,contenttype)
			_unpacker=None

			try:
				_unpacker=self.archivemap[archivetype]
			except:
				pass
			
			self.debug("File %s, is archive %s of type %s,unpacker %s"
						%(filename,isarchive,archivetype,_unpacker))

			if isarchive and _unpacker!=None:
				_u=None
				
				try:
					_u=self.unpacker[_unpacker]
				except:
					continue

				subdir=self._mktempdir(directory=tmpdir)
				_u.uncompress_file(fname,directory=os.path.join(tmpdir,subdir))

				try:
					self.debug("_remove_mail_from_queue file '%s'"%fname)
					os.remove(fname)
				except:
					pass

		self._chmod(tmpdir)

		return tmpdir

	##########
	#has_virus
	##########

	def has_virus(self,mail):
		self.debug("viruscheck has_virus")

		if mail==None:
			return False

		directory=self._unpack_email(mail)			
		self._print_archivemap()
		#print(self.virusscanner)
		#print(directory)
		result=False

		for scanner in self.virusscanner:
			hasvirus,info=self.virusscanner[scanner].has_virus(directory)

			if hasvirus:	
				self.log("Virus found")
				print("INFO",info)
				result=True
				break

		try:
			shutil.rmtree(directory)
		except:
			pass
	
		return result




p=parentdummy()
v=viruscheck(p)

fname="/home/horst/testmailtar.eml"
with open(fname) as txt:
		mymail=txt.read()

v.has_virus(mymail)

u=_BZ2()
u.uncompress_file("/home/horst/tst2/paket.tar.bz2")

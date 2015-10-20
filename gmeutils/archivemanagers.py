#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import tempfile
sys.path.insert(1,"/home/horst/Programmierecke/gpgmailencrypt")

####################
#CLASS _baseunpacker
####################

class _baseunpacker():

	def __init__(self,parent,chdir=False):
		self.cmd=""
		self.chdir=chdir
		self.parent=parent

	def uncompresscommand( 	self,
							sourcefile,
							directory):
		raise NotImplementedError

	def unpackingformats(self):
		raise NotImplementedError

	def keep_for_viruscheck(self):
		return False

	################
	#uncompress_file
	################

	def uncompress_file(self, filename,directory=None):
		result=False

		if directory==None:
			directory = tempfile.mkdtemp()
		
		if self.chdir:
			os.chdir(directory)
			_origdir=os.getcwd()

		uncompresscmd=' '.join(self.uncompresscommand(filename,directory))
		_result = subprocess.call(uncompresscmd, shell=True) 
		if self.chdir:
			os.chdir(_origdir)

		if _result !=0:
		  return result,None
		else:
			result=True

		return result,directory

####
#_AR
####

class _AR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.cmd=shutil.which("ar")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["AR","DEB"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"-x",
				sourcefile,
				">/dev/null"]
		return cmd

#####
#_ARJ
#####

class _ARJ(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("arj")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ARJ"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"x",sourcefile,
				"\"-ht%s\""%directory,
				"-u",
				"-y",
				"-r",
				">/dev/null"]
		return cmd

#####
#_BZ2
#####

class _BZ2(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("bzip2")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["BZIP","BZIP2"]

	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		format=""
		path,origname=os.path.split(sourcefile)
		fname, extension = os.path.splitext(origname)
		extension=extension.lower()
		new_ext=""

		if extension in [".tbz2",".tbz"]:
			new_ext=".tar"
		elif extension not in [".bz2",".bz"]:
			new_ext=".out"
		
		directory=os.path.join(directory,fname+new_ext)	
		cmd=[   self.cmd, 
				"-cd",sourcefile,
				"> \"%s\""%directory,
			]
		return cmd

#####
#_CAB
#####

class _CAB(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("cabextract")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["CAB"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"-d%s"%directory,
				sourcefile,
				">/dev/null"]
		return cmd

######
#_CPIO
######

class _CPIO(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.cmd=shutil.which("cpio")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["CPIO"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"-i",
				"--quiet",
				"-F",sourcefile,
				">/dev/null"]
		return cmd

######
#_GZIP
######

class _GZIP(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("gzip")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["GZIP","Z"]

	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		format=""
		path,origname=os.path.split(sourcefile)
		fname, extension = os.path.splitext(origname)
		extension=extension.lower()
		new_ext=""

		if extension in [".tgz"]:
			new_ext=".tar"
		elif extension not in [".gz"]:
			new_ext=".out"
		
		directory=os.path.join(directory,fname+new_ext)	
		cmd=[   self.cmd, 
				"-cd",sourcefile,
				"> \"%s\""%directory,
			]
		return cmd

#####
#_LHA
#####

class _LHA(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("lha")


	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["LHA"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"-w=%s"%directory,
				"-e",
				sourcefile,
				">/dev/null"]
		return cmd

#####
#_LZO
#####

class _LZO(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("lzop")


	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["LZO"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"-p%s"%directory,
				"-d",
				"-P",
				sourcefile,
				">/dev/null"]
		return cmd

#####
#_RAR
#####

class _RAR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("unrar")
	
	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["RAR"]

	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()

		cmd=[   self.cmd, 
				"e",sourcefile,
				directory,
				">/dev/null"
			]
		return cmd

########
#_RIPOLE
########

class _RIPOLE(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("ripole")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["DOC","XLS","DOT","XLT","PPS","PPT"]

	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()

		cmd=[   self.cmd, 
				"-i",sourcefile,
				"-d",directory,
				">/dev/null"
			]
		return cmd

	####################
	#keep_for_viruscheck
	####################

	def keep_for_viruscheck(self):
		return True

#####
#_TAR
#####

class _TAR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("tar")
	
	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["TAR","TARBZ2","TARBZ","TARGZ"]

	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
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
		
		cmd=[   self.cmd, 
				"-x%s"%format,
				"-f",sourcefile,
				"-C%s"%directory,
			]
		return cmd

######
#_TNEF
######

class _TNEF(_baseunpacker):
	"handles winmail.dat files"

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("tnef")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["TNEF"]
 
	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		cmd=[   self.cmd, 
				"-C \"%s\""%directory,
				"-f",sourcefile,
				">/dev/null"]
		return cmd

#####
#_XZ
#####

class _XZ(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("xz")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["XZ","LZMA"]

	##################
	#uncompresscommand
	##################

	def uncompresscommand(  self,
									sourcefile,
									directory):
		format=""
		path,origname=os.path.split(sourcefile)
		fname, extension = os.path.splitext(origname)
		extension=extension.lower()
		lzma=(extension==".lzma")
		new_ext=""

		if extension in [".txz",".tlzma"]:
			new_ext=".tar"
		elif extension not in [".xz",".lzma"]:
			new_ext=".out"
		
		directory=os.path.join(directory,fname+new_ext)	
		cmd=[   self.cmd, 
				"-cd",sourcefile,
				"> \"%s\""%directory,
			]

		if lzma:
			cmd.insert(3,"--format=lzma")
		return cmd

###########
#CLASS _ZIP
###########

class _ZIP(_baseunpacker):
	"""
	Class to create or unzip zipfiles.
	Don't call this class directly, use gme.zip_factory() instead!
	"""

	def __init__(self, parent):
		self.parent=parent
		self.zipcipher=self.parent._ZIPCIPHER
		self.cmd=shutil.which("7za")

	##############
	#set_zipcipher
	##############

	def set_zipcipher(self,cipher):
		"valid ciphers are ZipCrypto,AES128,AES256"
		self.zipcipher=cipher.upper()
 
	###############
	#create_zipfile
	###############

	def create_zipfile( self,
						directory,
						password=None,
						containerfile=None):
		"""to create a zipfile put all files, that should be included in the
		directory 'directory'.
		if you want to have the zipfile password secured set the password.
	
		A normal zipfile will always display a list of it contents, even when it
		is secured with a password. If you want to avoid this set containerfile 
		to a freely selected name. Then this class creates a password secured 
		zip-file with the name of "containerfile" and puts it in the zipfile 
		which will be returned by this routine. So one can just see, that the 
		zipfile contains another zipfile, but without the password no one can 
		see what it contains.

		This functions returns 2 values:
	
		result : True if everything worked correctly, else False
		encdata: if 'result' is True encdata returns a binary string with the 
				 zip-file, else None
		"""
		f=self.parent._new_tempfile()
		self.parent.debug("_PDF.create_file _new_tempfile %s"%f.name)
		f.close()
		fname=f.name
		result=False

		if containerfile!=None:
			tempdir = tempfile.mkdtemp()
			fname=os.path.join(tempdir,containerfile)
			self.parent.debug("ZIP creation command: '%s'" %
					   ' '.join(self._createzipcommand_fromdir(fname,
															   directory,
															   password)))
			_result = subprocess.call( 
					   ' '.join(self._createzipcommand_fromdir(fname,
															   directory,
															   None,
															   compress=False)),
						shell=True ) 
			directory=tempdir

			if _result !=0:
				self.parent.log("Error executing command"
								" (Error code %d)"%_result,"e")

				try:
					shutil.rmtree(tempdir)
				except:
					pass

				return result,None

		self.parent.debug("ZIP creation command: '%s'" %
			' '.join(self._createzipcommand_fromdir(f.name,
													directory,
													password)))
		_result = subprocess.call( 
						' '.join(self._createzipcommand_fromdir( f.name,
																 directory,
																 password)),
						shell=True ) 

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
 
	##########################
	#_createzipcommand_fromdir
	##########################

	def _createzipcommand_fromdir(  self,
									resultfile,
									directory,
									password, 
									compress=True):
		cipher="ZipCrypto"

		if self.zipcipher=="AES128":
			cipher="AES128"
		elif self.zipcipher=="AES192":
			cipher="AE192"
		elif self.zipcipher=="AES256":
			cipher="AES256"

		cmd=[   self.cmd, 
				"a",resultfile, 
				os.path.join(directory,"*"),
				"-tzip",
				"-mem=%s"%cipher,">/dev/null"]

		if password!=None:
			cmd.insert(4,"-p%s"%password)

		if compress==True:
			cmd.insert(4,"-mx%i"%self.parent._ZIPCOMPRESSION)

		return cmd

	###############
	#get_zipcontent
	###############

	def get_zipcontent( self,
						zipfile,
						password=None,
						containerfile=None):
		"""like ZIP.unzip_file, just the return values are different
	
		This functions returns 2 values:
		
		result :	 True if everything worked correctly, else False
		encdatalist: if 'result' is True it returns a list of 
					 'filename'/'binarydata' tuples, else None
		"""
		res,directory=self.unzip_file(  zipfile,
										password=password,
										containerfile=containerfile)		
		if res==False:
			return False, None

		encdatalist=[]

		for root, subdirs, files in os.walk(directory):

			for filename in files:
				longfilename=os.path.join(root,filename)

				try:
					_f=open(longfilename,"rb")
					data=_f.read()
					_f.close()
					encdatalist.append((filename,data))
				except:
					self.parent.log("Data of file '%s' could not be read"%
									filename)

		try:
			shutil.rmtree(directory)
		except:
			pass
					
		return True,encdatalist

	################
	#uncompress_file
	################

	def uncompress_file( self,
					zipfile,
					directory=None
					):
		"universal command for all unpacker classes"
		self.unzip_file(zipfile=zipfile,directory=directory)
		
	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["7z","APK","JAR","ZIP","EXE"]

	###########
	#unzip_file
	###########

	def unzip_file( self,
					zipfile,
					password=None,
					directory=None,
					containerfile=None):
		"""unzips a zip archive to the directory 'directory'. If none is given
		a temporary directory will be created. For the variables see function
		ZIP.create_zipfile().
	
		This functions returns 2 values:
		
		result :	True if everything worked correctly, else False
		directory:  if 'result' is True it returns the directory with the 
					content of the zip-file, else None
		"""
		if directory==None:
			directory = tempfile.mkdtemp()
			self.parent.debug("create end directory %s"%directory)

		directory1=tempfile.mkdtemp()
		result=False
		unzipcmd=' '.join(self._createunzipcommand_indir(   zipfile,
															directory1,
															password))
		self.parent.debug("UNZIP command: '%s'" % unzipcmd)
		_result = subprocess.call(unzipcmd, shell=True) 

		if _result !=0:
		  self.parent.log("Error executing command (Error code %d)"%_result,"e")
		  return result,None
		else:
			result=True

		directory2=""

		if containerfile!=None:
			result=False
			directory2 = tempfile.mkdtemp()
			unzipcmd=' '.join(self._createunzipcommand_indir(
							os.path.join(directory1,"%s.zip"%containerfile),
										 directory2,
										 password))
			self.parent.debug("UNZIP command2: '%s'" % unzipcmd)
			_result = subprocess.call(unzipcmd, shell=True) 

			if _result==0:
				self.parent.debug("shutil 1 move %s, %s"%(directory2,directory))
				source = os.listdir(directory2)

				for s in source:
					 shutil.move(os.path.join(directory2,s),directory)
		else:
			source = os.listdir(directory1)

			for s in source:
					 shutil.move(os.path.join(directory1,s),directory)
			
		if _result !=0:
		  self.parent.log("Error executing command (Error code %d)"%_result,"e")
		  return result,None
		else:
			result=True

		try:
			shutil.rmtree(directory1)
		except:
			pass

		try:
			shutil.rmtree(directory2)
		except:
			pass

		return result,directory
 
	##########################
	#_createunzipcommand_indir
	##########################

	def _createunzipcommand_indir(  self,
									sourcefile,
									directory,
									password):
		cmd=[  	self.cmd, 
				"e",sourcefile,
				"-o%s"%directory,
				">/dev/null"]
		if password!=None:
			cmd.insert(4,"-p%s"%password)
		return cmd

def get_archivemanager(manager, parent):
	manager=manager.upper().strip()

	if manager=="AR":
		return _AR(parent=parent)
	elif manager=="ARJ":
		return _ARJ(parent=parent)
	elif manager=="BZIP2":
		return _BZ2(parent=parent)
	elif manager=="CAB":
		return _CAB(parent=parent)
	elif manager=="CPIO":
		return _CPIO(parent=parent)
	elif manager=="GZIP":
		return _GZIP(parent=parent)
	elif manager=="LHA":
		return _LHA(parent=parent)
	elif manager=="LZO":
		return _LZO(parent=parent)
	elif manager=="RAR":
		return _RAR(parent=parent)
	elif manager=="RIPOLE":
		return _RIPOLE(parent=parent)
	elif manager=="TAR":
		return _TAR(parent=parent)
	elif manager=="TNEF":
		return _TNEF(parent=parent)
	elif manager=="XZ":
		return _XZ(parent=parent)
	elif manager=="ZIP":
		return _ZIP(parent=parent)
	
	return None

def get_managerlist():
	return ["AR","ARJ","BZIP2","CAB","CPIO","GZIP","LHA",
			"LZO","RAR","RIPOLE","TAR","TNEF","XZ","ZIP"]

#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import os
import shutil
import subprocess
import sys
import tempfile
from .child 			import _gmechild
from .version 			import *
from   ._dbg 			import _dbg

_filecmd=shutil.which("file")
_use_filecmd=(_filecmd!=None and len(_filecmd)>0)

####################
#CLASS _baseunpacker
####################

class _baseunpacker(_gmechild):

	def __init__(self,parent,chdir=False):
		_gmechild.__init__(self,parent=parent,filename=__file__)
		self.cmd=""
		self.chdir=chdir
		self.parent=parent

	def uncompresscommand( 	self,
							sourcefile,
							directory,
							password=None):
		raise NotImplementedError

	def unpackingformats(self):
		raise NotImplementedError

	def keep_for_viruscheck(self):
		return False

	#############
	#is_encrypted
	#############

	def is_encrypted(self, sourcefile):
		return False

	################
	#uncompress_file
	################

	@_dbg
	def uncompress_file(self, filename,directory=None,password=None):
		result=False

		if not os.path.exists(filename):
			self.log("file %s does not exist"%filename,"w")

		if self.is_encrypted(filename) and password==None:
			self.log("Encrypted file, but no password given")
			return False,None

		if directory==None:
			directory = tempfile.mkdtemp()

		if self.chdir:
			_origdir=os.getcwd()
			os.chdir(directory)
			self.debug("os.chdir(%s)"%_origdir)

		uncompresscmd=self.uncompresscommand(	filename,
												directory,
												password=password)
		self.debug("uncompresscommand:'%s'"%uncompresscmd)
		_result = subprocess.call(" ".join(uncompresscmd), shell=True)

		if self.chdir:
			os.chdir(_origdir)

		if _result !=0:
		  return result,None
		else:
			result=True

		return result,directory

##########################
#CLASS _basedeleteunpacker
##########################

class _basedeleteunpacker(_baseunpacker):

	################
	#uncompress_file
	################

	@_dbg
	def uncompress_file(self, filename,directory=None):
		result=False

		if directory==None:
			directory = tempfile.mkdtemp()

		if self.chdir:
			_origdir=os.getcwd()
			os.chdir(directory)

		origdir,fname=os.path.split(filename)
		targetname=os.path.join(directory,fname)
		shutil.move(filename,targetname)
		uncompresscmd=self.uncompresscommand(targetname,directory)
		self.debug("uncompresscommand:'%s'"%uncompresscmd)
		_result = subprocess.call(' '.join(uncompresscmd), shell=True)

		if self.chdir:
			os.chdir(_origdir)
			self.debug("os.chdir(%s)"%_origdir)

		if _result !=0:
		  return result,None
		else:
			result=True

		return result,directory

#####
#_ACE
#####

class _ACE(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent=parent,chdir=True)
		self.cmd=shutil.which("unace")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ACE"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"x",
				"-y",
				sourcefile,
				">/dev/null"]

		if password!=None:
			cmd.insert(2,"p%s"%password)

		return cmd

####
#_AR
####

class _AR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent=parent,chdir=True)
		self.cmd=shutil.which("ar")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["AR","DEB"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-x",
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

#####
#_ARC
#####

class _ARC(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent=parent,chdir=True)
		self.cmd=shutil.which("arc")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ARC"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"x",
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

#####
#_ARJ
#####

class _ARJ(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent=parent)
		self.cmd=shutil.which("arj")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ARJ"]

	#############
	#is_encrypted
	#############

	def is_encrypted(self, zipfile):
		#unrar x -p- -y -o+
		cmd=[  	self.cmd,
				"t",
				zipfile,
			]
		p=subprocess.Popen(	cmd,
							stdin=None,
							stdout=subprocess.PIPE,
							stderr=subprocess.PIPE )
		res=p.wait()

		for line in p.stdout.readlines():

			if "File is password encrypted" in line.decode("UTF-8","replace"):
				return True

		return False

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"x","\"%s\""%sourcefile,
				"\"-ht%s\""%directory,
				"-u",
				"-y",
				"-r",
				">/dev/null"]

		if password!=None:
			cmd.insert(5,"-g%s"%password)

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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
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
				"-cd","\"%s\""%sourcefile,
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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-d%s"%directory,
				"\"%s\""%sourcefile,
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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-i",
				"--quiet",
				"-F","\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

#####
#_DAR
#####

class _DAR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent=parent)
		self.cmd=shutil.which("dar")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["DAR"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		f,ext=os.path.splitext(sourcefile)

		if ext==".dar":
			f,ext=os.path.splitext(f)

			try:
				int(ext[1:])
				sourcefile=f
			except:
				pass

		cmd=[   self.cmd,
				"-O",
				"-q",
				"-wa",
				"-R",directory,
				"-x",
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

########
#_FREEZE
########

class _FREEZE(_basedeleteunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("unfreeze")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["FREEZE"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"\"%s\""%sourcefile,
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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
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
				"-cd","\"%s\""%sourcefile,
				"> \"%s\""%directory,
			]
		return cmd

#####
#_KGB
#####

class _KGB(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.cmd=shutil.which("kgb")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["KGB"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"\"%s\""%sourcefile,
				">/dev/null"]
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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-w=%s"%directory,
				"-e",
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

#######
#_LRZIP
#######

class _LRZIP(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("lrunzip")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["LRZIP"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-O \"%s\""%directory,
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

######
#_LZIP
######

class _LZIP(_basedeleteunpacker):

	def __init__(self,parent):
		_basedeleteunpacker.__init__(self,parent)
		self.cmd=shutil.which("lzip")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["LZIP"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-d",
				"-k",
				"\"%s\""%sourcefile,
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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-p%s"%directory,
				"-d",
				"-P",
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

#####
#_RAR
#####

class _RAR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("unrar")

		if self.cmd==None:
			self.cmd=shutil.which("rar")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["RAR"]

	#############
	#is_encrypted
	#############

	def is_encrypted(self, zipfile):
		#unrar x -p- -y -o+
		cmd=[  	self.cmd,
				"x",
				"-p-",
				"-y",
				"-o+",
				zipfile,
			]
		p=subprocess.Popen(	cmd,
							stdin=None,
							stdout=subprocess.PIPE,
							stderr=subprocess.PIPE )
		res=p.wait()

		for line in p.stderr.readlines():

			if "wrong password" in line.decode("UTF-8","replace"):
				return True

		return False

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()
		cmd=[   self.cmd,
				"x","\"%s\""%sourcefile,
				directory,
				">/dev/null"
			]

		if password!=None:
			cmd.insert(2,"-p%s"%password)

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
		return ["DOC","DOT","PPS","PPT","XLS","XLT"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()
		cmd=[   self.cmd,
				"-i","\"%s\""%sourcefile,
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
#_RPM
#####R

class _RPM(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.cmd=shutil.which("rpm2cpio")
		self.cmdcpio=shutil.which("cpio")

		if self.cmdcpio==None or len(self.cmdcpio)==0:
			self.cmd=None

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["RPM"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"\"%s\""%sourcefile,
				"| %s -dium"%self.cmdcpio]
		return cmd

######
#_RZIP
######

class _RZIP(_basedeleteunpacker):

	def __init__(self,parent):
		_basedeleteunpacker.__init__(self,parent)
		self.cmd=shutil.which("rzip")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["RZIP"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-d",
				"-k",
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

######
#_SHAR
######

class _SHAR(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.cmd=shutil.which("unshar")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["SHAR"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

############
#_snappytest
############

_snappytest="""
txt="testtext"
try:
	import snappy
	x=snappy.compress(txt)
	y=snappy.uncompress(x)
	if y!=txt:
		exit(2)
except:
	exit(1)
exit(0)
"""

########
#_SNAPPY
########

class _SNAPPY(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		f=tempfile.NamedTemporaryFile(  mode='w',
										delete=False,
										prefix='snappy-',
										suffix=".py",
									)
		f.write(_snappytest)
		f.close()
		py2=shutil.which("python2")

		if py2!=None:
			_result = subprocess.call("%s %s "%(py2,f.name), shell=True)

			if _result==0:
				self.cmd="snappyexists"

		try:
			os.remove(f.name)
		except:
			pass


	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["SNAPPY"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   "python",
				"-m",
				"snappy",
				"-d",
				"\"%s\""%sourcefile,
				"snappycontent",
				">/dev/null"]
		return cmd

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
		return ["TAR","TARBZ2","TARBZ","TARGZ","TARLZMA","TARLZO","TARXZ"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		format=""
		extension=os.path.splitext(sourcefile)[1].lower()

		if extension in ["bz2","tbz2"]:
			format="j"
		elif extension in ["xz","txz"]:
			format="J"
		elif extension in ["gz","tgz"]:
			format="x"

		cmd=[   self.cmd,
				"-x%s"%format,
				"-f","\"%s\""%sourcefile,
				"-C%s"%directory,
			]

		if extension in ["lzma","tlz"]:
			cmd.insert(2,"--lzma")
		elif extension in ["lzo","tlzo","lzop","tlzop"]:
			cmd.insert(2,"--lzop")

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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-C \"%s\""%directory,
				"-f","\"%s\""%sourcefile,
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

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
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
				"-cd","\"%s\""%sourcefile,
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
		_baseunpacker.__init__(self,parent)
		self.zipcipher=self.parent._ZIPCIPHER
		self.cmd=shutil.which("7za")

	##############
	#set_zipcipher
	##############

	@_dbg
	def set_zipcipher(self,cipher):
		"valid ciphers are ZipCrypto,AES128,AES256"
		self.zipcipher=cipher.upper()

	###############
	#create_zipfile
	###############

	@_dbg
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
		self.debug("_PDF.create_file _new_tempfile %s"%f.name)
		f.close()
		fname=f.name
		result=False

		if containerfile!=None:
			tempdir = tempfile.mkdtemp()
			fname=os.path.join(tempdir,containerfile)
			self.debug("ZIP creation command: '%s'" %
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
				self.log("Error executing command1"
								" (Error code %d)"%_result,"e")
				self.log("%s"%self._createzipcommand_fromdir(fname,
															   directory,
															   None,
															   compress=False))

				try:
					shutil.rmtree(tempdir)
				except:
					pass

				return result,None

		self.debug("ZIP creation command: '%s'" %
			' '.join(self._createzipcommand_fromdir(f.name,
													directory,
													password)))
		_result = subprocess.call( ' '.join(
									self._createzipcommand_fromdir( f.name,
																 directory,
																 password)),
						shell=True )

		try:
			shutil.rmtree(tempdir)
		except:
			pass

		if _result !=0:
		  self.log("Error executing command (Error code %d)2"%_result,"e")
		  self.log(self._createzipcommand_fromdir( 	f.name,
													directory,
													password),
					"e")
		  return result,None
		else:
			result=True

		res=open(f.name+".zip",mode="br")
		self.debug("ZIP_file binary open")
		encdata=res.read()
		res.close()
		os.rename(f.name+".zip",f.name)
		self.parent._del_tempfile(f.name)
		return result,encdata

	##########################
	#_createzipcommand_fromdir
	##########################

	@_dbg
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

	@_dbg
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
					self.log("Data of file '%s' could not be read"%
									filename)

		try:
			shutil.rmtree(directory)
		except:
			pass

		return True,encdatalist

	################
	#uncompress_file
	################

	@_dbg
	def uncompress_file( self,
					zipfile,
					directory=None
					):
		"universal command for all unpacker classes"
		self.unzip_file(zipfile=zipfile,
						directory=directory)

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["7z","APK","JAR","ZIP","EXE"]

	#############
	#is_encrypted
	#############

	def is_encrypted(self, zipfile):
		#7z l a.7z -slt
		cmd=[  	self.cmd,
				"l","%s"%zipfile,
				"-slt"
			]
		p=subprocess.Popen(	cmd,
							stdin=None,
							stdout=subprocess.PIPE,
							stderr=subprocess.PIPE )
		res=p.wait()

		for line in p.stdout.readlines():

			if "Encrypted = +" in line.decode("UTF-8","replace"):
				return True

		return False

	###########
	#unzip_file
	###########

	@_dbg
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

		if self.is_encrypted(zipfile) and password==None:
			self.log("Encrypted Zipfile but no password given")
			return False,None

		if directory==None:
			directory = tempfile.mkdtemp()
			self.debug("create end directory %s"%directory)

		directory1=tempfile.mkdtemp()
		result=False
		unzipcmd=self._createunzipcommand_indir(   zipfile,
															directory1,
															password)
		self.debug("UNZIP command: '%s'" % unzipcmd)
		_result = subprocess.call(" ".join(unzipcmd), shell=True)

		if _result !=0:
			self.log("Error executing command (Error code %d)"%_result,"e")
			self.log("%s"%unzipcmd)
			return result,None
		else:
			result=True

		directory2=""

		if containerfile!=None:
			result=False
			directory2 = tempfile.mkdtemp()
			unzipcmd=self._createunzipcommand_indir(
							os.path.join(directory1,"%s.zip"%containerfile),
										 directory2,
										 password)
			self.debug("UNZIP command2: '%s'" % unzipcmd)
			_result = subprocess.call(' '.join(unzipcmd), shell=True)

			if _result==0:
				self.debug("shutil 1 move %s, %s"%(directory2,directory))
				source = os.listdir(directory2)

				for s in source:
					 shutil.move(os.path.join(directory2,s),directory)
			else:
		  		self.log("Error executing command (Error code %d)4"%_result,"e")
		  		self.log(unzipcmd,"e")
		else:
			source = os.listdir(directory1)

			for s in source:
					 shutil.move(os.path.join(directory1,s),directory)

		if _result !=0:
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

	@_dbg
	def _createunzipcommand_indir(  self,
									sourcefile,
									directory,
									password):
		cmd=[  	self.cmd,
				"e","\"%s\""%sourcefile,
				"-o%s"%directory,
				"-y",
				">/dev/null"]

		if password!=None:
			cmd.insert(4,"-p%s"%password)

		return cmd

######
#_ZIP2
######

class _ZIP2(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent)
		self.cmd=shutil.which("unzip")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ZIP"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"\"%s\""%sourcefile,
				"-d",directory,
				">/dev/null"
			]
		return cmd

#####
#_ZOO
#####

class _ZOO(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.cmd=shutil.which("zoo")

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ZOO"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):
		cmd=[   self.cmd,
				"-extract","\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

######
#_ZPAQ
######

class _ZPAQ(_baseunpacker):

	def __init__(self,parent):
		_baseunpacker.__init__(self,parent,chdir=True)
		self.use_zpaqcmd=False
		self.cmd=shutil.which("zp")

		if self.cmd==None:
			self.cmd=shutil.which("zpaq")
			self.use_zpaqcmd=True

	#################
	#unpackingformats
	#################

	def unpackingformats(self):
		return ["ZPAQ"]

	##################
	#uncompresscommand
	##################

	@_dbg
	def uncompresscommand(  self,
							sourcefile,
							directory,
							password=None):

		if self.use_zpaqcmd:
			 extract="x"
		else:
			 extract="e"

		cmd=[   self.cmd,
				extract,
				"\"%s\""%sourcefile,
				">/dev/null"]
		return cmd

################################################################################

###################
#get_archivemanager
###################

def get_archivemanager(manager, parent):
	manager=manager.upper().strip()

	if manager=="ACE":
		return _ACE(parent=parent)
	elif manager=="AR":
		return _AR(parent=parent)
	elif manager=="ARC":
		return _ARC(parent=parent)
	elif manager=="ARJ":
		return _ARJ(parent=parent)
	elif manager=="BZIP2":
		return _BZ2(parent=parent)
	elif manager=="CAB":
		return _CAB(parent=parent)
	elif manager=="CPIO":
		return _CPIO(parent=parent)
	elif manager=="DAR":
		return _DAR(parent=parent)
	elif manager=="FREEZE":
		return _FREEZE(parent=parent)
	elif manager=="GZIP":
		return _GZIP(parent=parent)
	elif manager=="KGB":
		return _KGB(parent=parent)
	elif manager=="LHA":
		return _LHA(parent=parent)
	elif manager=="LRZIP":
		return _LRZIP(parent=parent)
	elif manager=="LZIP":
		return _LZIP(parent=parent)
	elif manager=="LZO":
		return _LZO(parent=parent)
	elif manager=="RAR":
		return _RAR(parent=parent)
	elif manager=="RIPOLE":
		return _RIPOLE(parent=parent)
	elif manager=="RPM":
		return _RPM(parent=parent)
	elif manager=="RZIP":
		return _RZIP(parent=parent)
	elif manager=="SHAR":
		return _SHAR(parent=parent)
	elif manager=="SNAPPY":
		return _SNAPPY(parent=parent)
	elif manager=="TAR":
		return _TAR(parent=parent)
	elif manager=="TNEF":
		return _TNEF(parent=parent)
	elif manager=="XZ":
		return _XZ(parent=parent)
	elif manager=="ZIP":
		return _ZIP(parent=parent)
	elif manager=="ZIP2":
		return _ZIP2(parent=parent)
	elif manager=="ZOO":
		return _ZOO(parent=parent)
	elif manager=="ZPAQ":
		return _ZPAQ(parent=parent)

	return None

################
#get_managerlist
################

def get_managerlist():
	return [	"ACE",
				"AR",
				"ARC",
				"ARJ",
				"BZIP2",
				"CAB",
				"CPIO",
				"DAR",
				"FREEZE",
				"GZIP",
				"KGB",
				"LHA",
				"LZIP",
				"LRZIP",
				"LZO",
				"RAR",
				"RIPOLE",
				"RPM",
				"RZIP",
				"SHAR",
				"SNAPPY",
				"TAR",
				"TNEF",
				"XZ",
				"ZIP",
				"ZIP2",
				"ZOO",
				"ZPAQ",
			]

################
#get_archivetype
################

def get_archivetype(filename,filetype):
	fname=os.path.split(filename)[1].lower()

	if _use_filecmd:
		cmd=[_filecmd,
			"-b",
			"--mime-type",
			filename
			]
		p=subprocess.Popen( cmd,
							stdin=None,
							stdout=subprocess.PIPE,
							stderr=subprocess.PIPE)
		result=p.communicate()[0].decode("UTF-8",unicodeerror).lower()

		if result[0]!="application/octet-stream":
			filetype=result

	maintype,subtype=filetype.lower().split("/")
	fname, extension = os.path.splitext(filename)
	archivetype=None
	subtypes={
		"java-archive":					"JAR",
		"ms-tnef":						"TNEF",
		"vnd.ms-cab-compressed":		"CAB",
		"vnd.android.package-archive":	"ZIP",
		"vnd.ms-tnef":					"TNEF",
		"x-7z-compressed":				"7Z",
		"x-ace":						"ACE",
		"x-ace-compressed":				"ACE",
		"x-arc":						"ARC",
		"x-arc-compressed":				"ARC",
		"x-archive":					"AR",
		"x-arj":						"ARJ",
		"x-bzip":						"BZIP",
		"x-bzip2":						"BZIP2",
		"x-compressed":					"GZIP",
		"x-compress":					"GZIP",
		"x-dar":						"DAR",
		"x-gtar":						"TGZ",
		"x-gzip":						"GZIP",
		"x-lharc":						"LHA",
		"x-lzh":						"LHA",
		"x-lzip":						"LZIP",
		"x-lzma":						"LZMA",
		"x-lzop":						"LZO",
		"x-shar":						"SHAR",
		"x-snappy":						"SNAPPY",
		"x-snappy-framed":				"SNAPPY",
		"x-tar":						"TAR",
		"x-rar-compressed":				"RAR",
		"x-xz":							"XZ",
		"zip":							"ZIP",
		"x-zoo":						"ZOO",
		}

	extensions={
				"7z":	"7Z",
				"7zip":	"7Z",
				"aar":	"ZIP",
				"ace":	"ACE",
				"ar":	"AR",
				"arc":	"ARC",
				"arj":	"ARJ",
				"apk":	"ZIP",
				"bz":	"BZIP",
				"bz2":	"BZIP2",
				"bzp2":	"BZIP2",
				"cab":	"CAB",
				"cb7":	"7Z",
				"cbr":	"RAR",
				"cbt":	"TAR",
				"cbz":	"ZIP",
				"cpio":	"CPIO",
				"dar":	"DAR",
				"deb":	"AR",
				"ear":	"JAR",
				"exe":	"EXE",
				"f":	"FREEZE",
				"gtar":	"TAR",
				"gz":	"GZIP",
				"iso":	"ISO",
				"jar":	"JAR",
				"kgb":	"KGB",
				"lz":	"LZIP",
				"lha":	"LHA",
				"lrz":	"LRZIP",
				"lzh":	"LHA",
				"lzma":	"LZMA",
				"lzo":	"LZO",
				"mar":	"BZIP2",
				"rar":	"RAR",
				"rpm":	"RPM",
				"rz":	"RZIP",
				"rzip":	"RZIP",
				"s7z":	"7Z",
				"shar":	"SHAR",
				"snappy":"SNAPPY",
				"sz":	"SNAPPY",
				"tar":	"TAR",
				"tbz":	"TARBZ",
				"tbz2":	"TARBZ2",
				"tgz":	"TARGZ",
				"tlz":	"TARLZMA",
				"ms-tnef":"TNEF",
				"txz":	"TARXZ",
				"uzip":	"ZIP",
				"war":	"ZIP",
				"wim":	"ZIP",
				"xar":	"AR",
				"xz":	"XZ",
				"z":	"GZIP",
				"zip":	"ZIP",
				"zipx":	"ZIP",
				"zoo":	"ZOO",
				"zpaq":	"ZPAQ",
				}

	if extension=="zipx":
		return None

	if maintype in ["application","other"]:
		extension=extension[1:]
		tar=(".tar" in fname)

		if tar:

			if extension =="bz":
				archivetype="TARBZ"
			elif extension =="bz2":
				archivetype="TARBZ2"
			elif extension =="gz":
				archivetype="TARGZ"
			elif extension =="lzma":
				archivetype="TARLZMA"
			elif extension in ["lzo","lzop"]:
				archivetype="TARLZO"
			elif extension =="xz":
				archivetype="TARXZ"

			return archivetype

		try:
			archivetype=extensions[extension]
			return archivetype
		except:
			pass

		try:
			archivetype=subtypes[subtype]
			return archivetype
		except:
			pass

		if fname.lower() in ["winmail.dat","win.dat"]:
			archivetype="TNEF"

	return archivetype


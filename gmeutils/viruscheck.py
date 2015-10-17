#!/usr/bin/env python3
import datetime
import email
import email.message
import os

try:
	import pyclamd
except:
	pass
	
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(1,"/home/horst/Programmierecke/gpgmailencrypt")

import gmeutils.archivemanagers as archivemanagers
import gmeutils.virusscanners as virusscanners

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
		
	####
	#log
	####

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
			scanner=virusscanners._clamavscan()
			self.virusscanner["CLAMAV"]=scanner
		except:
			pass

	#######################
	#_search_archivemanager
	#######################

	def _search_archivemanager(self):
		_archivemanager={}

		for m in archivemanagers.get_managerlist():
			mngr=archivemanagers.get_archivemanager(m,self.parent)

			if mngr!=None and len(mngr._cmd)>0:
				self.unpacker[m]=mngr
				_archivemanager[m]=self.unpacker[m].unpackingformats()
		
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
		archivetype=None
		result=False
		subtypes={
			"zip":"ZIP",
			"x-compressed":"GZIP",
			"x-compress":"GZIP",
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
			"vnd.android.package-archive":"ZIP",
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
						  
		extensions={"7z":"7Z",
					"ar":"AR",
					"arj":"ARJ",
					"apk":"ZIP",
					"bz":"BZIP",
					"bz2":"BZIP2ARJ",
					"cab":"CABRPM",
					"cpio":"CPIO",
					"deb":"DEB",
					"exe":"EXE",
					"gz":"GZIP",
					"iso":"ISO",
					"jar":"ZIP",
					"lz":"LZ",
					"lha":"LHA",
					"lzh":"LZH",
					"lzma":"LZMA",
					"lzo":"LZO",
					"rar":"RAR",
					"s7z":"RAR",
					"tar":"TAR",
					"tgz":"TARGZ",
					"xar":"AR",
					"xz":"XZ",
					"z":"Z",
					"zip":"ZIP",
					"zoo":"ZOO"}


		if maintype in ["application","other"]:

			fname=os.path.split(filename)[1].lower()
			extension=extension[1:]
			tar=(".tar" in fname)

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

	#############################
	#check_directory_for_archives
	#############################

	def check_directory_for_archives(self,directory):
		self.debug("check_directory_for_archives '%s'"%directory)
		
		for root, directories, files in os.walk(directory):  
			for f in files:
				pathf=os.path.join(root,f)
				self.debug("check file %s"%f)
				isarchive,archivetype=self._is_archive(f,"other/other")
				_unpacker=None

				try:
					_unpacker=self.archivemap[archivetype]
				except:
					pass
			
				#self.debug("\nFile %s, is archive %s of type %s,unpacker %s"
				#			%(f,isarchive,archivetype,_unpacker))

				if isarchive and _unpacker!=None:
					_u=None
					
					try:
						_u=self.unpacker[_unpacker]
					except:
						return
					self.debug("unpack archive %s"%f)
					subdir=self._mktempdir(directory=directory)
					newdir=os.path.join(directory,subdir)
					self.debug("   new dir is %s"%newdir)
					_u.uncompress_file(pathf,directory=newdir)

					try:
						self.debug("_remove_mail_from_queue file '%s'"%pathf)
						os.remove(pathf)
					except:
						pass

					self.check_directory_for_archives(newdir)

	##################
	#unpack_attachment
	##################

	def unpack_attachment(self,payload,directory):
			filename = payload.get_filename()
			fname=os.path.join(directory,filename)
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
					return

				subdir=self._mktempdir(directory=directory)
				newdir=os.path.join(directory,subdir)
				_u.uncompress_file(fname,directory=newdir)
				self.check_directory_for_archives(newdir)

				if not _u.keep_for_viruscheck():
					try:
						self.debug("_remove_mail_from_queue file '%s'"%fname)
						os.remove(fname)
					except:
						self.debug("keep archive %s"%fname)
						pass
		
	#############
	#unpack_email
	#############

	def unpack_email(self, mail):

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

			if is_attachment:
				self.unpack_attachment(payload,tmpdir)
			else:
				self.debug("not an attachment")
			

		self._chmod(tmpdir)

		return tmpdir

	##########
	#has_virus
	##########

	def has_virus(self,mail):
		self.debug("viruscheck has_virus")
		description=[]

		if mail==None:
			return False,description

		directory=self.unpack_email(mail)			
		self._print_archivemap()
		#print(self.virusscanner)
		#print(directory)
		result=False

		for scanner in self.virusscanner:
			hasvirus,info=self.virusscanner[scanner].has_virus(directory)

			if hasvirus:	
				self.log("Virus found")
				result=True
				description=info
				break

		try:
			#shutil.rmtree(directory)
			pass
		except:
			pass
	
		return result,description



################
################




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


if __name__ == "__main__":
	p=parentdummy()
	v=viruscheck(p)

	fname="/home/horst/gesamtarchiv.eml"
	with open(fname) as txt:
			mymail=txt.read()

	print(v.has_virus(mymail))

	u=archivemanagers._XZ(p)
	u.uncompress_file("/home/horst/tst2/testtxt.txt.lzma")
	

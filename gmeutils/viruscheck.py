#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from 	.child 			import _gmechild
from 	.				import virusscanners
from 	.				import archivemanagers
from   	._dbg 			import _dbg
from	.helpers		import decode_filename
import email
import tempfile
import os
import re
import shutil

###########
#viruscheck
###########

class _virus_check(_gmechild):

	def __init__(self,parent):
		_gmechild.__init__(self,parent=parent,filename=__file__)
		self.debug("viruscheck __init__")
		self.parent=parent
		self.archivemap={}
		self.unpacker={}
		self.virusscanner={}
		self._search_archivemanager()
		self._search_virusscanner()

	###########
	#_mktempdir
	###########

	@_dbg
	def _mktempdir(self,directory=None):
		return tempfile.mkdtemp(dir=directory)

	#######
	#_chmod
	#######

	@_dbg
	def _chmod(self,directory):

		for root, directories, files in os.walk(directory):

			for d in directories:
				pathd=os.path.join(root,d)
				os.chmod(pathd,0o770)

			for f in files:
				pathf=os.path.join(root,f)

				if not os.path.islink(pathf):
					os.chmod(pathf,0o640)

			if not os.path.islink(directory):
				os.chmod(directory,0o770)

	#####################
	#_search_virusscanner
	#####################

	@_dbg
	def _search_virusscanner(self):

		for s in virusscanners.get_virusscannerlist():
			vscanner=virusscanners.get_virusscanner(scanner=s,parent=self)

			if vscanner!=None:
				self.virusscanner[s]=vscanner
				self.log("Virusscanner %s activated"%s)

		if len(self.virusscanner)==0:
			self.log("No virusscanners available!","e")

	#######################
	#_search_archivemanager
	#######################

	@_dbg
	def _search_archivemanager(self):

#				for exclude in self._DEBUGEXCLUDETEXT:
#
#					if exclude.lower() in searchtext:
#						return False




		for m in archivemanagers.get_managerlist():


			try:
				mngr=archivemanagers.get_archivemanager(m,self.parent)
			except:
				self.log("Archive manager %s crashed while trying to init"%m,
							"w")
				self.log_traceback()
				continue


			if mngr != None and mngr.cmd!=None and len(mngr.cmd)>0:
				self.unpacker[m]=mngr
				archiveformats=self.unpacker[m].unpackingformats()
				self.log("Archivemanager %s registered: Filetypes: %s"
							%(m,archiveformats))

				for f in archiveformats:
					ff=f.upper()

					try:
						self.archivemap[ff]
					except:
						self.archivemap[ff]=m

	#################
	#print_archivemap
	#################

	@_dbg
	def print_archivemap(self):

			for f in self.archivemap:
				print(("Format %s"%f).ljust(20)+
					"Unpacker %s"%self.archivemap[f])

	#############################
	#check_directory_for_archives
	#############################

	@_dbg
	def check_directory_for_archives(self,directory):
		self.debug("check_directory_for_archives '%s'"%directory)

		for root, directories, files in os.walk(directory):

			for f in files:
				pathf=os.path.join(root,f)
				self.debug("check file %s"%f)
				archivetype=archivemanagers.get_archivetype(pathf,"other/other")
				_unpacker=None

				try:
					_unpacker=self.archivemap[archivetype]
				except:
					pass

				if archivetype!=None and _unpacker!=None:
					_u=None

					try:
						_u=self.unpacker[_unpacker]
					except:
						return

					self.debug("unpack archive %s"%f)
					subdir=self._mktempdir(directory=directory)
					newdir=os.path.join(directory,subdir)
					self.debug("new dir is %s"%newdir)
					_u.uncompress_file(pathf,directory=newdir)

					if not _u.keep_for_viruscheck():

						try:
							self.debug("delete archive'%s'"%pathf)
							os.remove(pathf)
						except:
							self.debug("keep archive %s"%pathf)

					self.check_directory_for_archives(newdir)

	##################
	#unpack_attachment
	##################

	@_dbg
	def unpack_attachment(self,payload,directory):
			filename = payload.get_filename()
			filename=re.sub(r"(/|\\| )","_",decode_filename(filename))
			fname=os.path.join(directory,filename)
			contenttype = payload.get_content_type()

			try:

				with open(fname,"wb") as attachment:
					attachment.write(payload.get_payload(decode=True))
			except:
				self.log("file '%s' could not be stored"%filename)
				self.log_traceback()

			archivetype=archivemanagers.get_archivetype(fname,contenttype)
			_unpacker=None

			try:
				_unpacker=self.archivemap[archivetype]
			except:
				pass

			self.debug("File %s, is archivetype %s,unpacker %s"
						%(filename,archivetype,_unpacker))

			if archivetype!=None and _unpacker!=None:
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
						self.debug("delete archive '%s'"%fname)
						os.remove(fname)
					except:
						self.debug("keep archive %s"%fname)

	#############
	#unpack_email
	#############

	@_dbg
	def unpack_email(self, mail):

		if isinstance(mail,str):
			mail=email.message_from_string(mail)

		tmpdir=self._mktempdir()
		self.debug("has_virus tmpdir '%s'"%tmpdir)
		_c=0

		for payload in mail.walk():
			_c+=1
			is_attachment = payload.get_param(
								'attachment',
								None,
								'Content-Disposition' ) is not None
			is_inline = payload.get_param(
								'inline',
								None,
								'Content-Disposition' ) is not None
			contenttype=payload.get_content_type()

			if is_attachment:
				self.debug("payload %i"%_c)
				self.unpack_attachment(payload,tmpdir)
			elif contenttype=="text/html":
				self.debug("payload %i"%_c)
				f=tempfile.NamedTemporaryFile(  mode='wb',
											delete=False,
											prefix='content-',
											suffix=".html",
											dir=tmpdir)
				fname = f.name
				f.write(payload.get_payload(decode=True))
				f.close()

		self._chmod(tmpdir)
		return tmpdir

	##########
	#has_virus
	##########

	@_dbg
	def has_virus(self,mail):
		self.debug("viruscheck has_virus")
		description=[]

		if mail==None:
			return False,description

		if len(self.virusscanner)==0:
			description.append("No virusscanners available")
			return False,description

		directory=self.unpack_email(mail)
		result=False

		for scanner in self.virusscanner:
			self.debug("Use virus scanner %s ..."%scanner)
			try:
				hasvirus,info=self.virusscanner[scanner].has_virus(directory)

				if hasvirus:
					self.debug("_virus_check.has_virus Virus found")
					result=True
					description=info
					break
				else:
					self.debug("... %s: no virus found"%scanner)

			except:
				self.log("Error while scanning for viruses with scanner %s"
						%scanner,
						"e")
				self.log_traceback()

		try:

			if not self.parent._DEBUG:
				shutil.rmtree(directory)
			else:
				self.debug("keep directory %s for debugging reasons"%directory)

		except:
			self.log("temporary directory '%s' could not be deleted"%directory)
			self.log_traceback()

		return result,description



#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import email
import os
import re
import shutil
import subprocess
from	.child 			import _gmechild 
from	.version		import *
from	._dbg 			import _dbg
from	.thirdparty		import email2pdf

###########
#CLASS _PDF
###########

class _PDF(_gmechild):
	"""
	class to create encrypted PDF files out of E-mail files.
	Don't call this class directly, use gme.pdf_factory() instead!
	"""
	def __init__(   self, 
					parent,
					counter=0):
		_gmechild.__init__(self,parent=parent,filename=__file__)
		self._recipient = ''
		self._filename=''	
		self.parent=parent
		self.count=counter
		self._pdfencryptcmd=shutil.which("pdftk")
		self._pdfwkhtml2pdf=shutil.which("wkhtmltopdf")
 
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
 
	###############
	#create_pdffile
	###############

	@_dbg
	def create_pdffile( self,
						password,
						filename=None):
		"""
		creates a PDF file out of the content of a file and encrypts it.
		
		return values:
		result: True if success, else False
		encdata: If 'result' is True, a (binary) string with the encrypted data
				 else None
		"""
		result=False

		if filename:
			self.set_filename(filename)

		if len(self._filename) == 0:
			self.log( 'Error: create_pdffile: filename not set',"e")
			return result,None

		f=self.parent._new_tempfile(delete=True)
		self.debug("_PDF.create_file _new_tempfile %s"%f.name)
		f.close()

		try:
			os.remove(f.name)
		except:
			pass

		self.debug("PDF creation command: '%s'" %
						' '.join(self._createpdfcommand_fromfile(f.name)))
		_result=0

		try:
			email2pdf.main(self._createpdfcommand_fromfile(f.name),None,None)
		except:
			_result=1
			self.log_traceback()

		if _result !=0:
		  self.log("Error executing command (Error code )","e")
		  self.log(self._createpdfcommand_fromfile(f.name),"e")
		  return result,None
		else:
			result=True

		_res,encryptedfile=self._encrypt_pdffile(f.name,password)

		if _res==False:
		  self.log("Error encrypting pdf file (Error code %d)"%_res,"e")
		  return False,None

		res=open(encryptedfile,mode="br")
		self.debug("PDF.encrypt_file binary open")
		encdata=res.read()
		res.close()
		self.parent._del_tempfile(f.name)
		self.parent._del_tempfile(encryptedfile)
		return result,encdata
 
	###########################
	#_createpdfcommand_fromfile
	###########################

	@_dbg
	def _createpdfcommand_fromfile(self,resultfile):
		cmd=[  	"email2pdf",
				"-i",self._filename, 
				"-o",resultfile,
				"--headers",
				"--overwrite",
				"--no-attachments",
				"--mostly-hide-warning"]
		return cmd
 
	#################
	#_encrypt_pdffile
	#################

	@_dbg
	def _encrypt_pdffile(   self,
							inputfilename,
							password):
		result=False
		f=self.parent._new_tempfile()
		self.debug("_PDF.encrypt_file _new_tempfile %s"%f.name)
		self.debug("Encryption command: '%s'" %
			' '.join(self._encryptcommand_fromfile( inputfilename,
													f.name,password)))
		_result = subprocess.call( 
				' '.join(self._encryptcommand_fromfile(  inputfilename,
														 f.name,password))
				 ,shell=True ) 

		if _result != 0:
			self.log("Error executing command "
							"(Error code %d)"%_result,"e")
			self.log(' '.join(self._encryptcommand_fromfile(  inputfilename,
														 f.name,password))
					,"e")
			return result,None
		else:
			result=True

		return result,f.name
 
	#########################
	#_encryptcommand_fromfile
	#########################

	@_dbg
	def _encryptcommand_fromfile(
							self,
							fromfile,
							tofile,
							password):
		cmd=[   self._pdfencryptcmd,
				fromfile, 
				"output",tofile,
				"user_pw","\"%s\""%password]
		return cmd

	@_dbg
	def is_available(self):

		try:
			import bs4
		except:
			self.log("beautifulsoup4 not available","e")
			return False

		try:
			import PyPDF2
		except:
			self.log("pypdf2 not available","e")
			return False

		try:
			import magic
		except:
			self.log("python-magic not available","e")
			return False
		
		if ( self._pdfencryptcmd and len(self._pdfencryptcmd)>0
			and self._pdfwkhtml2pdf and len(self._pdfwkhtml2pdf)>0):
			return True
		else:
			self.log("pdftk and/or wkhtmltopdf not available","e")
			return False


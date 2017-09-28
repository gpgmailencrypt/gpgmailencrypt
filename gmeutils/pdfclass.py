#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import os
import PyPDF2
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
						from_addr,
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
			email2pdf.main(self._createpdfcommand_fromfile(f.name),None,None,self.parent)
		except:
			_result=1
			self.log_traceback()

		if _result !=0:
		  self.log("Error executing command (Error code )","e")
		  self.log(self._createpdfcommand_fromfile(f.name),"e")
		  return False,None
		else:
			result=True

		if password==None:
			res=open(f.name,mode="br")
			self.debug("return PDF unencrypted")
			encdata=res.read()
			res.close()
			self.parent._del_tempfile(f.name)
			return result,encdata

		_res,encryptedfile=self._encrypt_pdffile(f.name,password,from_addr)

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

		if not self.parent._PDFINCLUDEIMAGES:
			cmd.insert(5,"--no-remote-links")

		return cmd
 
	#################
	#_encrypt_pdffile
	#################

	@_dbg
	def _encrypt_pdffile(   self,
							inputfilename,
							password,
							from_addr):
		result=False
		f=self.parent._new_tempfile()
		self.debug("_PDF.encrypt_file _new_tempfile %s"%f.name)
		self.debug("Encryption command: '%s'" %
			' '.join(self._encryptcommand_fromfile( inputfilename,
													f.name,password,
													from_addr)))
		_result = subprocess.call( 
				' '.join(self._encryptcommand_fromfile(  inputfilename,
														 f.name,password,
													from_addr))
				 ,shell=True ) 

		if _result != 0:
			self.log("Error executing command "
							"(Error code %d)"%_result,"e")
			self.log(' '.join(self._encryptcommand_fromfile(  inputfilename,
														 f.name,password,
														from_addr))
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
							password,
							from_addr):
		cmd=[   self._pdfencryptcmd,
				fromfile, 
				"output",tofile,
				"user_pw","\"%s\""%password]
		pw=self.parent.pdf_additionalencryptionkey(from_addr)

		if pw!=None and len(pw)>0:
			cmd.append("owner_pw")
			cmd.append(pw)

		return cmd

	################
	#decrypt_pdffile
	################

	@_dbg
	def decrypt_pdffile(  self,
							inputfilename,
							outputfilename,
							password):
		cmd=self._decryptcommand_fromfile(	inputfilename,
											outputfilename,
											password)

		try:
			p=subprocess.Popen(	cmd,
								stdin=None,
								stdout=subprocess.PIPE,
								stderr=subprocess.PIPE)
			output1,error1=p.communicate()
			error=p.poll()
		except:
			self.debug("decrypt_pdffile Error execute command")
			return False

		if error != 0:
			return False

		return True

	#########################
	#_decryptcommand_fromfile
	#########################

	@_dbg
	def _decryptcommand_fromfile(	self,
									fromfile,
									tofile,
									password):
		#pdftk secured.pdf input_pw foopass output unsecured.pdf
		cmd=[   self._pdfencryptcmd,
				fromfile,
				"input_pw","%s"%password,
				"output",tofile]
		return cmd

	#############
	#decrypt_file
	#############

	@_dbg
	def decrypt_file(  self,
							inputfilename,
							from_addr=None,
							to_addr=None):
		result=False
		pw=None
		f=self.parent._new_tempfile()

		if hasattr(self.parent._backend,"_textbackend") :
			pw=self.parent._backend._textbackend.pdf_additionalencryptionkey(None)

			if pw!=None:
				result=self.decrypt_pdffile(inputfilename,f.name,pw)

		if not result:
			pw=self.parent._backend.get_pdfpassword(from_addr)

			if pw!=None:
				result=self.decrypt_pdffile(inputfilename,f.name,pw)

		if not result:
			pw=self.parent._backend.get_pdfpassword(to_addr)

			if pw!=None:
				result=self.decrypt_pdffile(inputfilename,f.name,pw)

		if not result:
			pw=self.parent._backend.pdf_additionalencryptionkey(to_addr)

			if pw!=None:
				result=self.decrypt_pdffile(inputfilename,f.name,pw)

		if not result:
			pw=self.parent._backend.pdf_additionalencryptionkey(from_addr)

			if pw!=None:
				result=self.decrypt_pdffile(inputfilename,f.name,pw)

		if result==True:
			return result,f.name
		else:
			self.parent._del_tempfile(f.name)
			return result,None

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

	@_dbg
	def is_encrypted(self,pdffile):

		try:
			f=open(pdffile, "rb")
			inputPdf = PyPDF2.PdfFileReader(f)
			f.close()
			return inputPdf.isEncrypted
		except:
			return False


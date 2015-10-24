#!/usr/bin/env python3
import os
import shutil
import subprocess

##################
#_basevirusscanner
##################

class _basevirusscanner:
	def __init__(self,parent):
		self.parent=parent

	def has_virus(self,directory):
		raise NotImplementedError
	
	def log(self,
			msg,
			infotype="m",
			ln=-1):

		if self.parent:
			self.parent.log(msg,infotype,ln)

	def log_traceback(self):
		if self.parent:
			self.parent.log_traceback()

	def debug(  self,
				msg,
				lineno=0):
		if self.parent:
			self.parent.debug(msg,lineno)
	
#################
#_bitdefenderscan
#################

class _bitdefenderscan(_basevirusscanner):
	def __init__(self,parent):
		self.cmd=shutil.which("bdscan")
		_basevirusscanner.__init__(self,parent)

	def has_virus(self,directory):
		cmd=[self.cmd,"--no-list","--action=ignore",directory]
		result=False
		information=[]
		skip_header=2
		
		try:
			p = subprocess.Popen(   cmd, 
									stdin=None, 
									stdout=subprocess.PIPE, 
									stderr=subprocess.PIPE )
			p.wait()
			in_virusinfo=False

			for line in p.stdout.readlines():
				_l=line.decode("UTF-8")

				if not in_virusinfo:

					if _l!="\n":
						continue
					else:
						in_virusinfo=True
						continue

				if skip_header>0:
					skip_header-=1
					continue	

				if _l=="\n":
					break

				_l=_l.replace(" ... ","")
				res=_l.split(" ")
				filename=os.path.split(res[0])[1]
				virusinfo=_l.split(":")[1][:-1]
				information.append(["BITDEFENDER",filename,virusinfo])
				result=True

		except:
			self.log_traceback()
		
		return result,information

############
#_clamavscan
############

try:
	import pyclamd
	
	class _clamavscan(_basevirusscanner):
		def __init__(self,parent):
			self.clamd=pyclamd.ClamdAgnostic()
			_basevirusscanner.__init__(self,parent)

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
	
	clamavscan_available=True
except:
	clamavscan_available=False
	raise

########
#_sophos
########

class _sophosscan(_basevirusscanner):
	def __init__(self,parent):
		self.cmd=shutil.which("savscan")
		_basevirusscanner.__init__(self,parent)

	def has_virus(self,directory):
		cmd=[self.cmd,"-ss","-nb","-f","-all","-rec","-sc",directory]
		
		result=False
		information=[]
		skip_header=2
		
		try:
			p = subprocess.Popen(   cmd, 
									stdin=None, 
									stdout=subprocess.PIPE, 
									stderr=subprocess.PIPE )
			p.wait()
			
			for line in p.stdout.readlines():
				_l=line.decode("UTF-8")
				virusinfo=_l.split("'")[1]
				res=_l.split(" ")
				filename=os.path.split(res[len(res)-1][:-1])[1]
				information.append(["SOPHOS",filename,virusinfo])
				result=True

		except:
			self.log_traceback()
		
		return result,information

################################################################################

def get_virusscannerlist():
	return ["BITDEFENDER","CLAMAV","SOPHOS"]

def get_virusscanner(scanner,parent):
	scanner=scanner.upper().strip()

	if scanner=="CLAMAV" and clamavscan_available:
		return _clamavscan(parent=parent)
	
	if scanner=="BITDEFENDER":
		bd= _bitdefenderscan(parent=parent)
		if len(bd.cmd)>0:
			return bd
			
	if scanner=="SOPHOS":
		bd= _sophosscan(parent=parent)
		if len(bd.cmd)>0:
			return bd
			
	return None



#!/usr/bin/env python3
import os
import re
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
	
#######
#_AVAST
#######

class _AVAST(_basevirusscanner):

	def __init__(self,parent):
		self.cmd=shutil.which("scan")
		_basevirusscanner.__init__(self,parent)

	def has_virus(self,directory):
		cmd=[self.cmd,"-u",directory]
		result=False
		information=[]
		
		try:
			p = subprocess.Popen(   cmd, 
									stdin=None, 
									stdout=subprocess.PIPE, 
									stderr=subprocess.PIPE )
			p.wait()
			
			for line in p.stdout.readlines():
				_l=line.decode("UTF-8")

				if _l.startswith("/"):
					found=_l.split("\t",1)
					virusinfo=found[1][:-1]
					filename=os.path.split(found[0])[1]
					information.append(["AVAST",filename,virusinfo])
					result=True

		except:
			self.log_traceback()
		
		return result,information

#############
#_BITDEFENDER
#############

class _BITDEFENDER(_basevirusscanner):
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

########
#_CLAMAV
########

try:
	import pyclamd
	
	class _CLAMAV(_basevirusscanner):
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

#######
#_FPROT
#######

class _FPROT(_basevirusscanner):
	def __init__(self,parent):
		self.cmd=shutil.which("fpscan")
		_basevirusscanner.__init__(self,parent)

	def has_virus(self,directory):
		cmd=[self.cmd,"--report","--mount","--adware",directory]
		result=False
		information=[]
		
		try:
			p = subprocess.Popen(   cmd, 
									stdin=None, 
									stdout=subprocess.PIPE, 
									stderr=subprocess.PIPE )
			p.wait()
			
			for line in p.stdout.readlines():
				_l=line.decode("UTF-8")
				if _l.startswith("["):
					found=(re.search("(?<=\<)(.*)(?=\>)",_l))
					virusinfo=_l[found.start():found.end()]
					res=_l.split(" ")
					filename=os.path.split(res[len(res)-1][:-1])[1]
					information.append(["FPROT",filename,virusinfo])
					result=True

		except:
			self.log_traceback()
		
		return result,information

########
#_SOPHOS
########

class _SOPHOS(_basevirusscanner):
	def __init__(self,parent):
		self.cmd=shutil.which("savscan")
		_basevirusscanner.__init__(self,parent)

	def has_virus(self,directory):
		cmd=[self.cmd,"-ss","-nb","-f","-all","-rec","-sc",directory]
		
		result=False
		information=[]
		
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
	return ["AVAST","BITDEFENDER","CLAMAV","FPROT","SOPHOS"]

def get_virusscanner(scanner,parent):
	scanner=scanner.upper().strip()

	if scanner=="AVAST":
		s= _AVAST(parent=parent)
		if  s.cmd and len(s.cmd)>0:
			return s

	if scanner=="CLAMAV" and clamavscan_available:
		return _CLAMAV(parent=parent)
	
	if scanner=="BITDEFENDER":
		s= _BITDEFENDER(parent=parent)
		if  s.cmd and len(s.cmd)>0:
			return s

	if scanner=="FPROT":
		s= _FPROT(parent=parent)
		if  s.cmd and len(s.cmd)>0:
			return s
			
	if scanner=="SOPHOS":
		s= _SOPHOS(parent=parent)
		if  s.cmd and len(s.cmd)>0:
			return s
			
	return None



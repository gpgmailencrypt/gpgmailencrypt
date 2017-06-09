#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import os
import re
import shutil
import subprocess
from   .child 			import _gmechild
from   ._dbg 			import _dbg
from .version 			import *

##################
#_basevirusscanner
##################

class _basevirusscanner(_gmechild):

	def __init__(self,parent):
		_gmechild.__init__(self,parent=parent,filename=__file__)

	def has_virus(self,directory):
		raise NotImplementedError

#######
#_AVAST
#######

class _AVAST(_basevirusscanner):

	def __init__(self,parent):
		self.cmd=shutil.which("scan")
		_basevirusscanner.__init__(self,parent)

	@_dbg
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
				_l=line.decode("UTF-8",unicodeerror)

				if _l.startswith("/"):
					found=_l.split("\t",1)
					virusinfo=found[1][:-1]
					filename=os.path.split(found[0])[1]
					information.append(["AVAST",filename,virusinfo])
					result=True

		except:
			self.log_traceback()

		return result,information

#####
#_AVG
#####

class _AVG(_basevirusscanner):

	def __init__(self,parent):
		self.cmd=shutil.which("avgscan")
		_basevirusscanner.__init__(self,parent)

	@_dbg
	def has_virus(self,directory):
		cmd=[self.cmd,"-a",directory]
		result=False
		information=[]

		try:
			p = subprocess.Popen(   cmd,
									stdin=None,
									stdout=subprocess.PIPE,
									stderr=subprocess.PIPE )
			p.wait()

			for line in p.stdout.readlines():
				_l=line.decode("UTF-8",unicodeerror)

				if _l.startswith(chr(27)):
					found=_l.split("  Virus identified ",1)

					if len(found)>1:
						virusinfo=found[1][:-1]
						filename=os.path.split(found[0])[1]
						information.append(["AVG",filename,virusinfo])
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

	@_dbg
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
				_l=line.decode("UTF-8",unicodeerror)

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

		@_dbg
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

	_clamavscan_available=True
except:
	_clamavscan_available=False

########
#_COMODO
########

class _COMODO(_basevirusscanner):

	def __init__(self,parent):
		self.cmd=shutil.which("cmdscan")

		if self.cmd==None:
			self.cmd=shutil.which("cmdscan",path="/opt/COMODO")

		_basevirusscanner.__init__(self,parent)

	@_dbg
	def has_virus(self,directory):
		cmd=[self.cmd,"-v -s",directory]
		result=False
		information=[]

		try:
			p = subprocess.Popen(   cmd,
									stdin=None,
									stdout=subprocess.PIPE,
									stderr=subprocess.PIPE )
			p.wait()

			for line in p.stdout.readlines():
				_l=line.decode("UTF-8",unicodeerror)
				found=_l.split(" ---> Found Virus, ",1)

				if len(found)>1:
					virusinfo=found[1][:-1]
					v=virusinfo.split(" is ")

					if len(v)>1:
						virusinfo=v[1]

					filename=os.path.split(found[0])[1]
					information.append(["COMODO",filename,virusinfo])
					result=True

		except:
			self.log_traceback()

		return result,information

#######
#_DRWEB
#######

class _DRWEB(_basevirusscanner):

	def __init__(self,parent):
		self.cmd=shutil.which("drweb")
		_basevirusscanner.__init__(self,parent)

	@_dbg
	def has_virus(self,directory):
		cmd=[self.cmd,"-lng=en_scanner.dwl","-sd","-al","-ha",directory]
		result=False
		information=[]

		try:
			p = subprocess.Popen(   cmd,
									stdin=None,
									stdout=subprocess.PIPE,
									stderr=subprocess.PIPE )
			p.wait()

			for line in p.stdout.readlines():
				_l=line.decode("UTF-8",unicodeerror)

				if _l.startswith("/"):
					found=_l.split(" infected with ")

					if len(found)==2:
						virusinfo=found[1][:-1]
						filename=os.path.split(found[0])[1]
						information.append(["DRWEB",filename,virusinfo])
						result=True

		except:
			self.log_traceback()

		return result,information

#######
#_FPROT
#######

class _FPROT(_basevirusscanner):

	def __init__(self,parent):
		self.cmd=shutil.which("fpscan")
		_basevirusscanner.__init__(self,parent)

	@_dbg
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
				_l=line.decode("UTF-8",unicodeerror)

				if _l.startswith("[") and ("File is encrypted" not in _l):
					found=(re.search("(?<=\<)(.*)(?=\>)",_l))

					if found:
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

	@_dbg
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
				_l=line.decode("UTF-8",unicodeerror)
				virusinfo=_l.split("'")[1]
				res=_l.split(" ")
				filename=os.path.split(res[len(res)-1][:-1])[1]
				information.append(["SOPHOS",filename,virusinfo])
				result=True

		except:
			self.log_traceback()

		return result,information

################################################################################

#####################
#get_virusscannerlist
#####################

def get_virusscannerlist():
	return 	[
				"AVAST",
				"AVG",
				"BITDEFENDER",
				"CLAMAV",
				"COMODO",
				"DRWEB",
				"FPROT",
				"SOPHOS"
			]

#################
#get_virusscanner
#################

def get_virusscanner(scanner,parent):
	scanner=scanner.upper().strip()

	try:
		if scanner=="AVAST":
			s= _AVAST(parent=parent)

			if  s.cmd and len(s.cmd)>0:
				return s

		if scanner=="AVG":
			s= _AVG(parent=parent)

			if  s.cmd and len(s.cmd)>0:
				return s

		if scanner=="CLAMAV" and _clamavscan_available:
			return _CLAMAV(parent=parent)

		if scanner=="COMODO":
			s= _COMODO(parent=parent)

			if  s.cmd and len(s.cmd)>0:
				return s

		if scanner=="BITDEFENDER":
			s= _BITDEFENDER(parent=parent)

			if  s.cmd and len(s.cmd)>0:
				return s

		if scanner=="DRWEB":
			s= _DRWEB(parent=parent)

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
	except:
		parent.log("Virusscanner %s crashed while trying to init"%scanner,
					"w")

	return None



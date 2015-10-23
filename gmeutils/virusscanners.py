#!/usr/bin/env python3
import os
import shutil
import subprocess

##################
#_basevirusscanner
##################

class _basevirusscanner:
	def __init__(self):
		pass

	def has_virus(self,directory):
		raise NotImplementedError

#################
#_bitdefenderscan
#################

class _bitdefenderscan(_basevirusscanner):
	def __init__(self):
		self.cmd=shutil.which("bdscan")

	def has_virus(self,directory):
		cmd=[self.cmd,"--no-list",directory]
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
			raise
			pass
		
		return result,information

try:
	import pyclamd
	
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
	
	clamavscan_available=True
except:
	clamavscan_available=False

################################################################################
def get_virusscannerlist():
	return ["BITDEFENDER","CLAMAV"]

def get_virusscanner(scanner):
	scanner=scanner.upper().strip()
	
	if scanner=="CLAMAV" and clamavscan_available:
		return _clamavscan()
	
	if scanner=="BITDEFENDER":
		bd= _bitdefenderscan()
		if len(bd.cmd)>0:
			return bd
			
	return None



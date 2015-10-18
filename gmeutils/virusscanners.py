#!/usr/bin/env python3
import os

##################
#_basevirusscanner
##################

class _basevirusscanner:
	def __init__(self):
		pass

	def has_virus(self,directory):
		raise NotImplementedError

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

def get_virusscannerlist():
	return ["CLAMAV"]

def get_virusscanner(scanner):
	scanner=scanner.upper().strip()
	
	if scanner=="CLAMAV" and clamavscan_available:
		return _clamavscan()
	
	return None

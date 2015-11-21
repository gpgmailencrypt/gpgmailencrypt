#!/usr/bin/env python3
#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
import sys
from gmeutils import adminconsole
host="localhost"
port=10025
cl=sys.argv[1:]

try:
	host=cl[0]
	port=int(cl[1])
except:
	pass

print("Try to connect to %s:%i ..."%(host,port))
g=adminconsole.start_adminconsole(host,port)

	

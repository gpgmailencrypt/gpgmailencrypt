#!/usr/bin/env python3
import gpgmailencrypt,sys
host="localhost"
port=10025
cl=sys.argv[1:]
try:
	host=cl[0]
	port=int(cl[1])
except:
	pass
print("Try to connect to %s:%i ..."%(host,port))
g=gpgmailencrypt.start_adminconsole(host,port)

	

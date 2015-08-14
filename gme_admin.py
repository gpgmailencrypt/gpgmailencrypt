#!/usr/bin/python3
import getpass
import smtplib, socket
import sys,binascii
#user=input("User: " )
#password=getpass.getpass("Password:")
#print(user,password)

#host = sys.argv[1]
#port = int(sys.argv[2])



class gme():
	def __init__(self):
		self.smtp= smtplib.SMTP()
		self.host="localhost"
		self.port=0

	def _sendcmd(self, cmd,arg=""):
	        self.smtp.putcmd(cmd,arg)
	        (code, msg) = self.getreply()
	        print(code,msg.decode("UTF-8"))
	        return (code, msg)

	def getreply(self):
		return self.smtp.getreply()	

	def start(self,host="localhost",port=0):
		self.host=host
		self.port=port
		try:
			self.smtp.connect(host,port)
		except:
			print("Connection not possible")
			exit(1)
		user=input("User: ")
		password=getpass.getpass("Password: ")
		auth=binascii.b2a_base64(("\x00%s\x00%s"%(user,password)).encode("UTF-8"))[:-1]
		code,msg=self._sendcmd("AUTH PLAIN",auth.decode("UTF-8"))
		if code!=235:
			print("Authentication failed")
			exit(1)
		
		while True:
			i=input("> ")
			res=i.split(" ")
			i=res[0].upper()
			args=""
			try:
				args=" ".join(res[1:])
			except:
				pass
			cmd=""
			if i in ["STATISTICS","FLUSH","RELOAD","HELP","QUIT","DELUSER","SETUSER"]:
				if i=="HELP":
					self.print_help()
				else:
					self._sendcmd(i,args)
			else:
				print("Error: command '%s' unknown"%i)
			if i=="QUIT":
				break

	def print_help(self):
		print("Allowed commands:")
		print("statistics,flush,reload,help,quit")

g=gme()
g.start("localhost",10025)
	

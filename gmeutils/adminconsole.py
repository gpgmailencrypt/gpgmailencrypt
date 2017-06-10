#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from gmeutils.child 			import _gmechild
from gmeutils.version			import *
from gmeutils._dbg 				import _dbg
from gmeutils.mytimer       	import _mytimer
from gmeutils.gpgmailserver 	import _gpgmailencryptserver
import getpass
import smtplib
import binascii

try:
	import readline
except:
	pass

###################
#start_adminconsole
###################

def start_adminconsole(host,port):
	"starts the admin console"

	#########
	#gmeadmin
	#########

	class gmeadmin(_gmechild):

		def __init__(self,parent=None):
			_gmechild.__init__(self,parent,filename=__file__)
			self.smtp= None
			self.host="localhost"
			self.port=0
			self.timer=_mytimer()

		#########
		#_sendcmd
		#########

		def _sendcmd(self, cmd,arg=""):

			if self.smtp==None:
				return (None,None)

			self.smtp.putcmd(cmd,arg)
			(code, msg) = self.getreply()
			print(msg.decode("UTF-8",unicodeerror))
			return (code, msg)

		#########
		#getreply
		#########

		def getreply(self):

			if self.smtp==None:
					return None

			return self.smtp.getreply()

		######
		#start
		######

		def start(self,host="localhost",port=0):
			self.host=host
			self.port=port

			try:
				self.smtp=smtplib.SMTP(host=host,port=port)
			except:
				print("Connection not possible")
				exit(1)

			print("gpgmailencrypt admin console")
			print("============================")

			try:
				self.smtp.starttls()
			except:
				print("WARNING. Connection is not encrypted. "
					"STARTTLS was not possible")

			user=input("User: ")
			password=getpass.getpass("Password: ")
			auth=binascii.b2a_base64(
						("\x00%s\x00%s"%(
										user,
										password)
						).encode("UTF-8"))[:-1]
			code,msg=self._sendcmd("ADMIN",auth.decode("UTF-8",unicodeerror))
			code,msg=self._sendcmd("AUTH PLAIN",auth.decode("UTF-8",
															unicodeerror))

			if code!=235:
				print("Authentication failed")
				exit(1)

			print("Welcome. Enter 'HELP' for a list of commands")
			self.timer.start(10,60)

			while True:
				i=""

				try:

					try:
						i=input("> ")
					except (KeyboardInterrupt,EOFError):
						i="QUIT"

					self.timer.set_alive()

					if not self.timer.is_running():
						print("Automatic logout due to inactivity")
						i="QUIT"

					res=i.split(" ")
					i=res[0].upper()
					args=""

					try:
						args=" ".join(res[1:])
					except:
						pass

					cmd=""

					if i in _gpgmailencryptserver.ADMINALLCOMMANDS:

						if i=="HELP":
							self.print_help()
						else:
							self._sendcmd(i,args)

					else:
						print("Error: command '%s' unknown"%i)

				except:
					print("Error sending admin command, perhaps server is down")
					#print( sys.exc_info())
					i="QUIT"

				if i=="QUIT":
					break

			self.timer.stop()

		###########
		#print_help
		###########

		def print_help(self):
			space=18
			print("\nAllowed commands:")
			print("=================")
			print("flush".ljust(space)+"tries to re-send deferred emails")
			print("debug true/false".ljust(space)+"sets the debug mode")
			print("deluser".ljust(space)+"deletes a user")
			print("".ljust(space)+"example: 'deluser john'")
			print("help".ljust(space)+"this help")
			print("messages".ljust(space)+
					"shows all systemwarnings and -errors")
			print("quit".ljust(space)+"leave the console")
			print("quarantine".ljust(space)+
			"handles the quarantine queue")
			print("".ljust(space)+"quarantine show : shows the queue ")
			print("".ljust(space)+"                        first value is"
			" the id")
			print("".ljust(space)+"quarantine delete  xxx: deletes an entry")
			print("".ljust(space)+"                        xxx is the id'")
			print("".ljust(space)+"quarantine release xxx: sends the mail")
			print("".ljust(space)+"                        xxx is the id'")
			print("".ljust(space)+"quarantine forward xxx emailadress:")
			print("".ljust(space)+"                        forwards the email"
			" to 'emailaddress'")
			print("".ljust(space)+"                        xxx is the id")
			print("reload".ljust(space)+"reloads the configuration file")
			print("resetmessages".ljust(space)+
					"deletes all old systemmessages")
			print("resetstatistics".ljust(space)+
					"sets all statistic values to 0")
			print("setuser".ljust(space)+
			"adds a new user or changes the password for an existing user")
			print("".ljust(space)+"example: 'setuser john johnspassword'")
			print("statistics".ljust(space)+"print statistic information")
			print("users".ljust(space)+"print users")
			print("createtable".ljust(space)
			+"creates a specific SQL table")
			print("".ljust(space)+"allowed values:")
			print("".ljust(space)+"all/usermap/encryptionmap/smime/pdf")

#class taken from http://stackoverflow.com/questions/20625642/\
#				 autocomplete-with-readline-in-python3

	class MyCompleter(object):  # Custom completer

		def __init__(self, options):
			self.options = sorted(options)

		#########
		#complete
		#########

		def complete(   self,
						text,
						state):

			if state == 0:  # on first trigger, build possible matches

				if not text:
					self.matches = self.options[:]
				else:
					self.matches = [s for s in self.options
									  if (s
									  and s.upper().startswith(text.upper() ))
								   ]

			try:
				return self.matches[state]
			except IndexError:
				return None

		################
		#display_matches
		################

		def display_matches(	self,
								substitution,
								matches,
								longest_match_length):
			print()
			print(matches)
			print("> %s"%substitution,end="")
			sys.stdout.flush()
			columns = environ.get("COLUMNS", 80)
			line_buffer = readline.get_line_buffer()
			tpl = "{:<" + str(int(max(map(len, matches)) * 1.2)) + "}"
			buffer = ""

			for match in matches:
				match = tpl.format(match[len(substitution):])

				if len(buffer + match) > columns:
					print(buffer)
					buffer = ""

				buffer += match

			if buffer:
				print(buffer)

			print("> ", end="")
			print(line_buffer, end="")
			sys.stdout.flush()

	try:
		completer = MyCompleter(_gpgmailencryptserver.ADMINALLCOMMANDS)
		readline.set_completer_delims(' \t\n;')
		readline.set_completer(completer.complete)
		readline.parse_and_bind('tab: complete')
		readline.set_completion_display_matches_hook(completer.display_matches)
	except:
		print("python3 module 'readline' not installed, "
				"starting without autocompletion")
	g=gmeadmin()
	g.start(host,port)


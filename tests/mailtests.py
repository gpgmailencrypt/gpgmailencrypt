#!/usr/bin/python3
import sys,os,os.path,email,smtplib,ssl,subprocess,time
sys.path.append("..")
import gpgmailencrypt

TESTTO=["horst.knorr@knorrnet.de"]
TESTFROM="test@knorrnet.de"
maildir="./emails"
mails=os.listdir(maildir)

def start_server():
	process=subprocess.Popen(["/home/horst/gpgmailencrypt3/gpgmailencrypt/g.py", "-d","-l","file"])
	return process
def stop_server(p):
	print("stop server")
	p.terminate()		
def send_singlemail(mail):
	if "Date" in mail:
		del mail["Date"]
	if "From" in mail:
		del mail["From"]
	if "To" in mail:
		del mail["To"]
	mail["From"]=TESTFROM
	mail["To"]=TESTTO[0]
	g.encrypt_mails(mail.as_string(),TESTTO)
	#i=input("beenden?")
	#if i.upper().strip()=="JA":
	#	exit()

def send_scripttestmails():
	for m in mails:
		mailname=os.path.join(maildir,m)
		f=open(mailname)
		rawmail=f.read()
		f.close()
		mail=email.message_from_string(rawmail)
		for e in ["PGPINLINE","PGPMIME","SMIME"]:
			print(m,e)
			g.set_default_preferredencryption(e)
			send_singlemail(mail)
			
def send_testmails():
	send_scripttestmails()
def m2():
	from multiprocessing import Process
	p = Process(target=g.daemonmode)
	p.start()
	p.terminate()
def moduletests():
	g.set_output2mail()
	send_testmails()
	g.set_output2stdout()
	send_testmails()
	g.set_output2file("./output.eml")
	send_testmails()
	l=g.get_locale()
	g.set_locale("DE")		
	g.set_output2stdout()
	send_testmails()
	g.set_locale("RU")		
	g.set_output2stdout()
	send_testmails()
	g.set_locale("WRONG")		
	g.set_output2stdout()
	send_testmails()
	mailname=os.path.join(maildir,"russisch.eml")
	f=open(mailname)
	rawmail=f.read()
	f.close()
	mail=email.message_from_string(rawmail)
	g.set_default_preferredencryption("pgpinline")
	send_singlemail(mail)

def servertests():
	server=start_server()
	time.sleep(10)
	stop_server(server)

#servertests()
g=gpgmailencrypt.gme()

g.set_debug(False)

#moduletests()
print("All testmails via script passed")
print(g.get_statistics())


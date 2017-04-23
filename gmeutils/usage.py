#License GPL v3
#Author Horst Knorr <gpgmailencrypt@gmx.de>
from   .version			import *

###########
#show_usage
###########

def show_usage():
	"shows the command line options to stdout"
	print ("gpgmailencrypt")
	print ("===============")
	print ("License: GPL 3")
	print ("Author:  Horst Knorr <gpgmailencrypt@gmx.de>")
	print ("Version: %s from %s"%(VERSION,DATE))
	print ("\nUsage:\n")
	print ("gme.py [options] recipient@email.address < Inputfile_from_stdin")
	print ("or")
	print ("gme.py -f inputfile.eml [options] recipient@email.address")
	print ("\nOptions:\n")
	print ("-a --addheader:     adds a gpgmailencrypt version header to "
			"the mail")
	print ("-c f --config f:    use configfile 'f'. Default is")
	print ("                    /etc/gpgmailencrypt.conf")
	print ("-d --daemon :       start gpgmailencrypt as smtpserver")
	print ("-e pgpinline :      preferred encryption method, either ")
	print ("                    'pgpinline','pgpmime' or 'smime'")
	print ("-f mail :           reads email file 'mail', otherwise from stdin")
	print ("-h --help :         print this help")
	print ("-k f --keyhome f:   sets gpg key directory to 'f'")
	print ("-l t --log t:       print information into _logfile, with valid")
	print ("                    types 't' 'none','stderr','syslog','file'")
	print ("-n domainnames:     sets the used domain names (comma separated")
	print ("                    lists, no space), which should be encrypted,")
	print ("                    empty is all")
	print ("-m mailfile :       write email file to 'mailfile', otherwise")
	print ("                    email will be sent via smtp")
	print ("-o p --output p:    valid values for p are 'mail' or 'stdout',")
	print ("                    alternatively set an outputfile with -m")
	print ("--spamcheck=true:   if true, check if the e-mail is spam")
	print ("-x --example:       print example config file")
	print ("-v --verbose:       print debugging information into _logfile")
	print ("--viruscheck=true:  if true, check if the e-mail contains a virus")
	print ("-z --zip:           zip attachments")
	print ("")

####################
#print_exampleconfig
####################

def print_exampleconfig():
	"prints an example config file to stdout"
	space=56

	print ("[default]")
	print ("preferred_encryption = pgpinline".ljust(space)+
	"#valid values are 'pgpinline','pgpmime' or 'smime'")
	print ("add_header = no".ljust(space)+
	"#adds a gpgmailencrypt version header to the mail")
	print ("domains =".ljust(space)+
	"#comma separated list of domain names,")
	print ("".ljust(space)+
	"#that should be encrypted, empty is all")
	print ("homedomains=localhost".ljust(space)+
	"#a comma separated list of domains, for which this server is working ")
	print ("".ljust(space)+"#and users might receive system mail "
	"and can use pdf encrypt")
	print ("securitylevel=may".ljust(space)+
	"#valid values are 'may','redirect' or 'bounce'")
	print ("bouncehomedomain=true".ljust(space)+
	"#when true and security level is 'bounce' unencrypted emails ")
	print ("".ljust(space)+"#to an address in 'homedomains' will bounce. ")
	print ("output=mail".ljust(space)+
	"#valid values are 'mail'or 'stdout'")
	print ("locale=en".ljust(space)+
	"#DA|DE|EN|ES|FI|FR|IT|NL|NO|PL|PT|RU|SE")
	print ("mailtemplatedir=/usr/share/gpgmailencrypt"
			"/mailtemplates".ljust(space)+
	"#directory where mail templates are stored")
	print ("systemmailfrom=gpgmailencrypt@localhost".ljust(space)+
	"#e-mail address used when sending system mails")
	print ("alwaysencrypt=False".ljust(space)+
	"#if True e-mails will be sent encrypted, even if there is no key")
	print ("".ljust(space)+
	"#Fallback encryption is encrypted pdf")
	print ("use_sentaddress=False".ljust(space)+
	"#If true a copy of the mail will be sent to the sender of the mail.")
	print ("".ljust(space)+
	"#the from address will be changed to 'sent_address'. This can be used")
	print ("".ljust(space)+
	"#to store encrypted e-mails in the sent folder of the user")
	print ("".ljust(space)+
	"#using the sent_address to filter with sieve or the e-mail client")
	print ("sent_address=SENT".ljust(space)+
	"#the used address looks like 'sent_address <original@fromaddress>'")
	print ("storagebackend=TEXT".ljust(space)+
	"#valid values are TEXT|MSSQL|MYSQL|SQLITE3|POSTGRESQL")

	print ("")
	print ("[mailserver]")
	print ("host = 127.0.0.1".ljust(space)+"#smtp host")
	print ("port = 25".ljust(space)+"#smtp port")
	print ("authenticate = False".ljust(space)+
	"#user must authenticate")
	print ("usesmtps=False".ljust(space)+
	"#if True, the connection is ssl encrypted from the beginning")
	print ("".ljust(space)+
	"#don't confuse it with STARTTLS, which will be used automatically")
	print ("smtpcredential =/etc/gpgmailencrypt.cfg".ljust(space)+
	"#file that keeps user and password information")
	print("".ljust(space)+
	"#file format 'user=password'")
	print ("cacerts=/etc/ssl/ca-certificates.crt".ljust(space)+
	"#the ca certificate storage file used for verifiying smtp connections")
	print ("#fingerprints=12345".ljust(space)+
	"#a comma separated list of certificate fingerprints used for certificate ")
	print ("".ljust(space)+
	"#pinning, if list is empty, certificate pinning is switched off")
	print ("useserver2 = False".ljust(space)+
	"#use a separate server for unencrypted emails")
	print ("host2 = 127.0.0.1".ljust(space)+"#like host, for server2")
	print ("port2 = 25".ljust(space)+"#like port, for server2")
	print ("authenticate2 = False".ljust(space)+
	"#like authenticate, for server2")
	print ("usesmtps2=False".ljust(space)+
	"#like usesmtps, for server2")
	print ("smtpcredential2 =/etc/gpgmailencrypt2.cfg".ljust(space)+
	"#like smtpcredential, for server2")
	print ("cacerts2=/etc/ssl/ca-certificates.crt".ljust(space)+
	"#like cacerts, for server2")

	print ("")
	print ("[daemon]")
	print ("host = 127.0.0.1".ljust(space)+
	"#smtp host")
	print ("port = 10025".ljust(space)+
	"#smtp port")
	print ("smtps = False".ljust(space)+
	"#use smtps encryption")
	print ("starttls = False".ljust(space)+
	"#use starttls encryption")
	print ("forcetls = False".ljust(space)+
	"#communication (e.g. authentication) will be only possible after STARTTLS")
	print ("sslkeyfile = /etc/gpgsmtp.key".ljust(space)+
	"#the x509 certificate key file")
	print ("sslcertfile = /etc/gpgsmtp.crt".ljust(space)+
	"#the x509 certificate cert file")
	print ("authenticate = False".ljust(space)+
	"#users must authenticate")
	print ("smtppasswords = /etc/gpgmailencrypt.pw".ljust(space)+
	"#file that includes users and passwords")
	print ("admins=admin1,admin2".ljust(space)+
	"#comma separated list of admins, that can use the admin console")
	print ("statistics=1".ljust(space)+
	"#how often per day should statistical data be logged (0=none) max is 24")

	print ("")
	print ("[gpg]")
	print ("keyhome = /var/lib/gpgmailencrypt/.gnupg".ljust(space)+
	"#home directory of public  gpgkeyring")
	print ("gpgcommand = /usr/bin/gpg2")
	print ("allowgpgcomment = yes".ljust(space)+
	"#allow a comment string in the GPG file")
	print ("extractkey= no".ljust(space)+
	"#automatically scan emails and extract pgp public keys to "
	"'keyextractdir'")
	print ("keyextractdir=~/.gnupg/extract")

	print ("")
	print ("[smime]")
	print ("keyhome = ~/.smime".ljust(space)+
	"#home directory of S/MIME public key files")
	print ("opensslcommand = /usr/bin/openssl")
	print ("defaultcipher = DES3".ljust(space)+
	"#DES3|AES128|AES192|AES256")
	print ("extractkey= no".ljust(space)+
	"#automatically scan emails and extract smime public keys to "
	"'keyextractdir'")
	print ("keyextractdir=~/.smime/extract")

	print ("")
	print ("[smimeuser]")
	print ("smime.user@domain.com = user.pem[,cipher]".ljust(space)+
	"#public S/MIME key file [,used cipher, see defaultcipher "
	"in the smime section]")

	print ("")
	print ("[pdf]")
	print ("useenryptpdf=False".ljust(space)+
	"#if True, emails can be encrypted as PDF")
	print ("passwordlength=10".ljust(space)+
	"#Length of the automatic created password")
	print ("passwordlifetime=172800".ljust(space)+
	"#lifetime for autocreated passwords in seconds. Default is 48 hours")
	print ("pdfpasswords=/etc/gpgpdfpasswords.pw".ljust(space)+
	"#file that includes users and passwords for permanent pdf passwords")

	print ("")
	print ("[encryptionmap]")
	print ("user@domain.com = PGPMIME".ljust(space)+
	"#PGPMIME|PGPINLINE|SMIME|PDF[:zipencryptionmethod]|NONE")

	print ("")
	print ("[usermap]")
	print (""
	"#user_nokey@domain.com = user_key@otherdomain.com")

	print ("")
	print ("[zip]")
	print ("7zipcommand=/usr/bin/7za".ljust(space)+
	"#path where to find 7za")
	print ("defaultcipher=ZipCrypto".ljust(space)+
	"#ZipCrypto|AES128||AES192|AES256")
	print ("compressionlevel=5".ljust(space)+
	"#1,3,5,7,9  with 1:lowest compression, but very fast, 9 is ")
	print ("".ljust(space)+
	"#highest compression, but very slow, default is 5")
	print ("securezipcontainer=False".ljust(space)+
	"#attachments will be stored in an encrypted zip file."
	" If this option is true,")
	print ("".ljust(space)+
	"#the directory will be also encrypted")
	print ("zipattachments=False".ljust(space)+
	"#if True all attachments will be zipped, independent "
	"from the encryption method")

	print ("")
	print ("[virus]")
	print ("checkviruses=False".ljust(space)+
	"#if true,e-mails will be checked for viruses before being encrypted")
	print ("quarantinelifetime=2419200".ljust(space)+
	"#how long an infected e-mail exists in the quarantine (in seconds)")
	print ("".ljust(space)+
	"#(default is 4 weeks). 0 deactivates automatic deletion")

	print ("")
	print ("[spam]")
	print ("spamscanner=spamassassin".ljust(space)+
	"#spamassassin|bogofilter")
	print ("checkspam=False".ljust(space)+
	"#if true, e-mails will be checked if they are spam")
	print ("sa_host=localhost".ljust(space)+
	"#server where spamassassin is running")
	print ("sa_port=783".ljust(space)+
	"#port of the spamassassin server")
	print ("sa_spamlevel=6.2".ljust(space)+
	"#spamassassin threshold for spam, "
	"values higher than that means the mail is spam")
	print ("sa_spamsuspectlevel=3.0".ljust(space)+
	"#spamassassin threshold for spam, values higher "
	"than that means the mail might be spam")
	print("".ljust(space)+"#(value must be smaller than 'spamlevel')")
	print ("maxsize=500000".ljust(space)+
	"#maximum size of e-mail,that will be checked if it is spam")
	print ("add_spamheader=False".ljust(space)+
	"#if True the e-mail gets spam headers")
	print ("change_subject=False".ljust(space)+
	"#if True, the subject of the mail will get a prefix")
	print ("spam_subject=***SPAM***".ljust(space)+
	"#subject prefix for spam")
	print ("spamsuspect_subject=***SPAMSUSPICION***".ljust(space)+
	"#subject prefix for suspected spam")

	print ("")
	print ("[dkim]")
	print ("use_dkim=False".ljust(space)+
	"#if true, the email will be signed,when the senders address is "
	"in homedomains")
	print ("dkimdomain=localhost".ljust(space)+
	"#the dkim domain name")
	print ("dkimselector=gpgdkim".ljust(space)+
	"#the dkim selector")
	print ("dkimkey=~/dkim.key".ljust(space)+
	"#the private key to be used to sign the mail")

	print ("")
	print ("[sql]")
	print ("database=gpgmailencrypt".ljust(space)+
	"#name of database")
	print ("user=gpgmailencrypt".ljust(space)+
	"#database user")
	print ("password=".ljust(space)+
	"#database password")
	print ("host=127.0.0.1".ljust(space)+
	"#sql server")
	print ("port=3306".ljust(space)+
	"#sql server port")
	print ("usermapsql=select gpguser from gpgusermap where "
			"user=? ".ljust(space)+
	"#SQL command that returns one row with the alternatve e-mail address")
	print ("encryptionmapsql=SELECT encrypt FROM encryptionmap WHERE user= ?")
	print ("".ljust(space)+
	"#SQL command that returns one row with the preferred encryption method")

	print ("smimeusersql=SELECT publickey,cipher FROM smimeuser "
							"WHERE user= ?".ljust(space)+"")
	print ("".ljust(space)+
	"#SQL command that returns one row with information about an SMIME user")

	print ("smimepublickeysql=SELECT user,publickey,cipher FROM smimeuser")
	print ("".ljust(space)+
	"#SQL command that returns a list with information about all "
	"SMIME users and their public keys")

	print ("smimeprivatekeysql=SELECT user,privatekey,cipher FROM "
	"smimeuser WHERE privatekey is not NULL")
	print("".ljust(space)+
	"#SQL command that returns a list with information about all "
	"SMIME users and their private keys")

	print ("use_sqlusermap=False".ljust(space)+
	"#if True the usermap will be taken from the sql database else it will")
	print ("".ljust(space)+
	"#be taken from the config file, section [usermap]")
	print ("use_sqlencryptionmap=False".ljust(space)+
	"#if True the encryptionmap will be taken from the sql database else it")
	print ("".ljust(space)+
	"#will be taken from the config file, section [encryptionmap]")

	print ("use_sqlsmime=False".ljust(space)+
	"#if True the SMIME user definition will be taken from the sql database")
	print ("".ljust(space)+
	"#else it will be taken from the config file, section [smimeuser]")

	print ("use_sqlpdfpasswords=False".ljust(space)+
	"#if True the PDF passwords will be stored and taken from the sql database")
	print ("sqlpdf_passwordtable=pdfpasswords".ljust(space)+
	"#table that contains the pdf passwords")
	print ("sqlpdf_userfield=user".ljust(space)+
	"#fieldname that contains the user")
	print ("sqlpdf_passwordfield=password".ljust(space)+
	"#fieldname that contains the password")
	print ("sqlpdf_starttimefield=starttime".ljust(space)+
	"#fieldname that contains the password creation time (needed for automatic"
	" password deletion)")

	print ("")
	print ("[logging]")
	print ("log=none".ljust(space)+
	"#valid values are 'none', 'syslog', 'file' or 'stderr'")
	print ("file = /tmp/gpgmailencrypt.log")
	print ("debug = no")




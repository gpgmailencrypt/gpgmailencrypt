#!/usr/bin/python3
import unittest,sys,tempfile
sys.path.append("..")
import gpgmailencrypt
class gmetests(unittest.TestCase):
	#GPGTESTS
	def test_GPG(self):
		gme = gpgmailencrypt.gme()
		gme.set_configfile("./gmetest.conf")
		gpg=gpgmailencrypt._GPG(gme)
		pk=gpg.public_keys()
		controllist=list()
		controllist.append("testaddress@gpgmailencry.pt")
		controllist.append("second.user@gpgmailencry.pt")
		gme.close()
		self.assertTrue(pk==controllist)
	def test_hasgpgkey(self):
		gme = gpgmailencrypt.gme()
		gme.set_configfile("./gmetest.conf")
		success,user=gme.check_gpgrecipient("second.user@gpgmailencry.pt")
		gme.close()
		self.assertTrue(success)
	def test_hasnotsgpgkey(self):
		gme = gpgmailencrypt.gme()
		gme.set_configfile("./gmetest.conf")
		success,user=gme.check_gpgrecipient("third.user@gpgmailencry.pt")
		gme.close()
		self.assertFalse(success)
	def test_preferredmethod(self):
		gme = gpgmailencrypt.gme()
		gme.set_configfile("./gmetest.conf")
		self.assertTrue(gme.get_preferredencryptionmethod("testaddress@gpgmailencry.pt")=="PGPMIME")
		gme.close()
	#SMIMETESTS
	#ENCRYPTIONTESTS	
if __name__ == '__main__':
    unittest.main()

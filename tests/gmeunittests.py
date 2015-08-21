#!/usr/bin/python3
import unittest,sys,tempfile
sys.path.append("..")
import gpgmailencrypt

email_unencrypted="""
Message-ID: <55D748F3.4020400@from.com>
Date: Fri, 21 Aug 2015 17:51:15 +0200
From: test@from.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Thunderbird/31.8.0
MIME-Version: 1.0
To: testaddress@gpgmailencry.pt
Subject: testmail
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 7bit

test

"""
email_gpgmimeencrypted="""
Message-ID: <55D7543F.5070908@knorrnet.de>
Date: Fri, 21 Aug 2015 18:39:27 +0200
From: test@knorrnet.de
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Thunderbird/31.8.0
To: testaddress@gpgmailencry.pt
Subject: test
MIME-Version: 1.0
Content-Type: multipart/encrypted; charset="utf-8"; boundary="===============6271318822587357114=="; protocol="application/pgp-encrypted"

This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)
--===============6271318822587357114==
Content-Type: application/pgp-encrypted
Content-Description: PGP/MIME version identification

Version: 1

--===============6271318822587357114==
Content-Type: application/octet-stream; name="encrypted.asc"
Content-Description: OpenPGP encrypted message
Content-Disposition: inline; filename="encrypted.asc"

-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.22 (GNU/Linux)
Comment: Encrypted by gpgmailencrypt version 2.0phi

hQEMA0frgA6jyJ37AQf/SV3wAjhhr+AqZKdCEs/kXCHRCySL0MCheH8ijtbtpK+E
pGmZ3fSJB+t7iHy6ZgpKLFFYy+ecPmjffdUvoZM/VhuGIPwVGqolq88LeAgj1lJ8
lP3nJp6ZFsBlIlXb11eBmrxaDt/XXMt+d0BRWw3LqjsO01n/9sCByjXLMPXka9hd
Vi249ftG7nPK4zHCfVe6X2N6cftmdInBwHmdMbLb9d4pKVqX4FS0Px+ofTqwbuG2
ilV6zw3Y7m0nd3a8HIW+zenkxR3/QnElGWQ2wJx8CFPXq/rorCax2zHw04HCWr4b
KJO5fyUhbz5GsbcezohhY8sH1/e7ffmPg7YjgWN7i9KKAbSksJJO7nbMmVWwbOHS
vExX0KisYdN842dmCDGWv5txHfgnSqLR6VFP3W4Af3Z2tzq1zveMOFqXNpC3Pmum
zMISo6KQs+FmbC7eRLA8vdx18CEyS78GAHcW40sU1J56vyfjqHq88m8uUikbh1QV
eBJxKkkjpiCCRrPSbubBX8yd3tsEh+i7oSkz
=NEIK
-----END PGP MESSAGE-----

--===============6271318822587357114==--"""

email_gpginlineencrypted="""
Message-ID: <55D74DA5.4040503@from.com>
Date: Fri, 21 Aug 2015 18:11:17 +0200
From: test@from.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Thunderbird/31.8.0
MIME-Version: 1.0
To: testaddress@gpgmailencry.pt
Subject: test
Content-Type: text/plain; charset="utf-8"
Content-Transfer-Encoding: 7bit

-----BEGIN PGP MESSAGE-----
Version: GnuPG v2.0.22 (GNU/Linux)
Comment: Encrypted by gpgmailencrypt version 2.0phi

hQEMA0frgA6jyJ37AQgAw8Cnj702WZWnIJLsNkrFVmGyW0TY/NgvyG2ABnaV+12N
ReimRZWr1CRUUDHe9YsuLxw4zIpUt1saPFNjyUb1MIZFXeqpGDLpYvUZyu4Q6U2o
eY6ue7f3tp5gvK0KWK/KnzCLzDeIsA0mF4xp1wrngIDepW4qQ5NBl+lNTTwV7wfL
IF4Oxyygx+33E3EdUw801w6WaplBvJ+ZU/gzvskIkTXBz3BGI88GOUqPEw3uCED2
VovHWpxxxIWCS7bTsm/CxN6fIbwxXxRhbtaf2MKmm+kbJi4SV9aE5zA06b759fUT
ZgIXwDVJR71GkQsMI5ZDj8coMSFfziFRA0r8OQyYndJGASixF1h+aD+eT2NbDRS9
sjwSrAHipJlzgboDaKj7aZj1qsuHInFR5b67GiKjHNdihYCRoT487HY32NXdElkA
OO3rAIhyOg==
=qggM
-----END PGP MESSAGE-----
"""
email_smimeencrypted="""
Message-ID: <55D76AE0.2010301@from.com>
Date: Fri, 21 Aug 2015 20:16:00 +0200
From: test@from.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:31.0) Gecko/20100101 Thunderbird/31.8.0
To: testaddress@gpgmailencry.pt
Subject: test
MIME-Version: 1.0
Content-Disposition: attachment; filename="smime.p7m"
content-type: application/pkcs7-mime; smime-type="enveloped-data"; name="smime.p7m"
Content-Transfer-Encoding: base64

MIIDTwYJKoZIhvcNAQcDoIIDQDCCAzwCAQAxggK4MIICtAIBADCBmzCBjTELMAkG
A1UEBhMCUFQxEzARBgNVBAgMClNvbWUtU3RhdGUxFzAVBgNVBAoMDmdwZ21haWxl
bmNyeXB0MSQwIgYDVQQDDBt0ZXN0YWRkcmVzc0BncGdtYWlsZW5jcnkucHQxKjAo
BgkqhkiG9w0BCQEWG3Rlc3RhZGRyZXNzQGdwZ21haWxlbmNyeS5wdAIJAJ82sqhr
oEI1MA0GCSqGSIb3DQEBAQUABIICAB3HuQmErwfMYrOhkZoaGChW5OfQ1aC+YZl4
1PIyRfCfYW0Uoaz9A9PC0UjlBYgCmGb22BmqXNIeaAZtgnpGStlphCF+WWlADI5G
Qndn43TGIaT2dNdx8xWsU2ttZ7jRqrbwAuhzFZMnx9HRGfwZDh1wv6lQS5sK5QO3
BrUtPpuNFU0gqF0NOgn069Z01l+o+UL+V3tGyQnc7F4C8BeeY05l4EQ7+eScET0W
Ri5YQmWEyWwsp5XxAUTmJpP3XUtO49j1SiGlQJ3ImBTt8XnFIbWL8Drk2ZD/jmMm
3NKkMhx1U+nkOah+0yAZJ2s3j//1jHoAKD3+qgsm9hT+e/O7BDHQ2a8oOsJDKOa/
Gf9Exeb+clW3H+Rdl3CkzQUtUDr0HkzDg/tQxWbxCjaDD/izSUN9vd4a75ex6ve8
fmqPTK/L7iKBPutawMHJBq0PYUKkc4jWUOzOtcOIPlXcNH6AyfCqB3Yfj0cw14MR
6WORbnqw4B1sH6ccfFfuHYexx8P8jeCh9pGuF/T0ZRZEeojocjVZgvpRtco4O51a
BjpSaG/khGTzkTTkWiJeM264VYDSSK+QA3DzQPICKD0CbPdAQcQs9gydm0vpTyRm
ok3ZAmQAxCF8KxpfM3HjxzITxu9hrWxG15XUB9WPs3l5E/NJtVV78DlWG2bLkyJa
abIAjL+VMHsGCSqGSIb3DQEHATAUBggqhkiG9w0DBwQISE4s3HFO/SmAWPMC3Of2
UoN4b6pIvQfmCF6171czNKU17Gug6nyAe4s6IAXLK2ChBSyok3fsKzE7bQ6H1FvL
XYe0R/JAbmXBKBQb2iffNL/Sru4kR3a0xjxmvKjGws3vaT8=
"""
class gmetests(unittest.TestCase):
	#General tests
	def test_configcomment(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			x=gme._SMIMECIPHER
			gme.close()
		self.assertTrue(x=="DES3")
	def test_preferredmethod(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertTrue(gme.get_preferredencryptionmethod("testaddress@gpgmailencry.pt")=="PGPMIME")
			gme.close()
	def test_preferredmethod(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			gme.adm_set_user("test","test")
			self.assertTrue(gme._smtpd_passwords["test"] == "1a5d0013be0c4a28c9c5a29973febad6275e9b144aa92d23aa1b2a413af2bcb307d239ec1d265978f6b36e4c64e45218e22e4096d438fa969e090913b099f7ae")
			gme.close()
	#GPGTESTS
	def test_GPGpublickeys(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			gpg=gpgmailencrypt._GPG(gme)
			pk=gpg.public_keys()
			controllist=list()
			controllist.append("testaddress@gpgmailencry.pt")
			controllist.append("second.user@gpgmailencry.pt")
			gme.close()
		self.assertTrue(pk==controllist)
	def test_hasgpgkey(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			success,user=gme.check_gpgrecipient("second.user@gpgmailencry.pt")
			gme.close()
		self.assertTrue(success)
	def test_hasnotsgpgkey(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			success,user=gme.check_gpgrecipient("third.user@gpgmailencry.pt")
			gme.close()
		self.assertFalse(success)
	def test_isencrypted(self):
		"test is_encrypted"
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertTrue(gme.is_encrypted(email_gpgmimeencrypted))
			gme.close()
	def test_ispgpmimeencrypted(self):
		"test is_pgpmimeencrypted"
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertTrue(gme.is_pgpmimeencrypted(email_gpgmimeencrypted))
			gme.close()
	def test_ispgpinlineencrypted(self):
		"test is_pgpinlineencrypted"
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertTrue(gme.is_pgpinlineencrypted(email_gpginlineencrypted))
			gme.close()
	def test_isunencrypted(self):
		"test is_unencrypted"
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertFalse(gme.is_encrypted(email_unencrypted))
			gme.close()
		
	#SMIMETESTS
	def test_issmimeencrypted(self):
		"test is_smimeencrypted"
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertTrue(gme.is_smimeencrypted(email_smimeencrypted))
			gme.close()
	def test_isnotsmimeencrypted(self):
		"test is_notsmimeencrypted"
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			self.assertFalse(gme.is_smimeencrypted(email_gpgmimeencrypted))
			gme.close()
	def test_hassmimekey(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			success,user=gme.check_smimerecipient("testaddress@gpgmailencry.pt")
			gme.close()
		self.assertTrue(success)
	def test_hasnotsmimekey(self):
		with gpgmailencrypt.gme() as gme:
			gme.set_configfile("./gmetest.conf")
			success,user=gme.check_smimerecipient("second.user@gpgmailencry.pt")
			gme.close()
		self.assertFalse(success)

	#ENCRYPTIONTESTS	
if __name__ == '__main__':
    unittest.main()

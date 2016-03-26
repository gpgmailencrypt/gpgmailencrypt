#!/usr/bin/env python3
import sys
sys.path.insert(1,"-")
import dkim
f=open("/home/horst/gpgtest/nurtext.eml","rb")
mail=f.read()
f=open("/home/horst/dkim.private.key","rb")
key=f.read()
x=dkim.sign(mail,b"dkimtest",b"knorrnet.de",key)
#print(x.encode("UTF-8"))
print(x)

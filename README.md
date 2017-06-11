# gpgmailencrypt
gpgmailencrypt can encrypt e-mails and check for spam and viruses.

It supports
* PGP/Inline
* PGP/Mime
* S/Mime
* PDF

For spam checking it supports
* spamassassin
* bogofilter

For virus checking it supports
* avast
* bitdefender
* clamav
* drweb
* f-prot
* sophos

It can be used normally as a script doing everything on command line, in daemon mode, where gpgmailencrypt acts as an encrypting smtp server or as a module for programmers. 

It takes e-mails and  returns the e-mail encrypted to another e-mail server if a encryption key exists for the receiver. Otherwise it returns the e-mail unencrypted.
The encryption method can be selected per user.

See gpgmailencrypt documentation.pdf for more info.(https://github.com/gpgmailencrypt/gpgmailencrypt/blob/master/documentation/gpgmailencrypt%20documentation.pdf)

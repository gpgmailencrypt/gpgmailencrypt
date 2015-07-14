# gpgmailencrypt
gpgmailencrypt can encrypt e-mails.
It supports
* PGP/Inline
* PGP/Mime
* S/Mime

It can be used normally as a script doing everything on command line, in daemon mode, where gpgmailencrypt acts as an encrypting smtp server or as a module for programmers. 
It takes e-mails and  returns the e-mail encrypted to another e-mail server if a encryption key exists for the receiver. Otherwise it returns the e-mail unencrypted.
The encryption method can be selected per user.

See gpgmailencrypt documentation.pdf for more info.

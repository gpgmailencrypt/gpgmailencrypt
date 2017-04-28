"""A setuptools based setup module.

See:
https://packaging.python.org/en/latest/distributing.html
https://github.com/pypa/sampleproject
"""

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

# To use a consistent encoding
from codecs import open
from os import path
import re

#For post-install command
import os, sys, shutil
from distutils.core import setup
from distutils.command.install import install as _install

############
#install_dir
############

def install_dir(fromdir,todir):

	d,b=os.path.split(fromdir)
	todir=os.path.join(todir,b)

	try:

		if not os.path.exists(todir):
			os.makedirs(todir)

		for root, directories, files in os.walk(fromdir):
			to=root.replace(fromdir,todir)

			for d in directories:
				pathd=os.path.join(todir,d)

				if not os.path.exists(pathd):
					os.makedirs(pathd)

			for f in files:
				fromfile=os.path.join(root,f)
				tofile=os.path.join(to,f)
				tofiledefault=tofile+".default"


				with open(tofiledefault,"wb") as to_f:
					from_f=open(fromfile,"rb")
					to_f.write(from_f.read())
					from_f.close()

				if not os.path.exists(tofile):

					with open(tofile,"wb") as to_f:
						from_f=open(fromfile,"rb")
						to_f.write(from_f.read())
						from_f.close()
	except:
		print("Error copying directory '%s'"%b)

##############
#_post_install
##############

def _post_install(dir):
	import subprocess
	import pkg_resources
	_templatepath="/usr/share/gpgmailencrypt"

	if not os.path.exists(_templatepath):
		os.makedirs(_templatepath)

	install_dir(os.path.join(dir,"mailtemplates"),_templatepath)
	initscript="/etc/init.d/gpgmailencrypt"

	try:
		shutil.copyfile(os.path.join(dir,"/misc/gpgmailencrypt.init"),initscript)
		os.chmod(initscript,0o755)
	except:
		pass

	try:
		cmd="gme.py -l none -x > /etc/gpgmailencrypt.conf.example"
		_result = subprocess.check_output(	cmd,
											shell=True)
	except:
		pass

########
#install
########

class install(_install):
	def run(self):
		_install.run(self)
		self.execute(_post_install, (self.install_lib,),
					 msg="Running post install task")

################################################################################

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file

with open(path.join(here, 'README.md'), encoding='utf-8') as f:
	long_description = f.read()

VERSIONFILE="gmeutils/version.py"
src = open(VERSIONFILE, "rt").read()
result=re.search("^VERSION=[\"]([\.0-9a-zA-Z]*)[\"]",src,re.M)

if result:
	versionstr=result.group(1)
else:
		raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE))

######
#setup
######

setup(
	name='gpgmailencrypt',
	description='an e-mail encryption, virus- and spam- checking module, gateway and daemon',
	version=versionstr,
	long_description=long_description,
	url='https://github.com/gpgmailencrypt/gpgmailencrypt',
	author='Horst Knorr',
	author_email='gpgmailencrypt@gmx.de',
	license='GPL v3',
	install_requires=["pypdf2","beautifulsoup4","python-magic","requests","lxml"],
	cmdclass={'install': install},
	# See https://pypi.python.org/pypi?%3Aaction=list_classifiers

	classifiers=[
	'Development Status :: 5 - Production/Stable',
	'Intended Audience :: Developers',
	'Intended Audience :: System Administrators',
	'Intended Audience :: Information Technology',
	"Environment :: No Input/Output (Daemon)",
	'Environment :: Console',
	'Topic :: Software Development :: Build Tools',
	'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
	'Programming Language :: Python :: 3',
	'Programming Language :: Python :: 3.4',
	'Programming Language :: Python :: 3.5',
	'Programming Language :: Python :: 3.6',
	"Topic :: Communications :: Email :: Mail Transport Agents",
	"Topic :: Communications :: Email",
	"Topic :: Database",
	"Topic :: Security :: Cryptography",
	"Topic :: Software Development :: Libraries :: Python Modules",
	"Operating System :: OS Independent",
   ],

	#zip_safe=False,
	keywords='Email encryption daemon gateway  gpg pgp smime pdf spam spamassassin bogofilter virus clamav drwatson avast f-prot fprot sophos bitdefender mysql sqlite postgres',
	scripts =[		"scripts/gme_admin.py",
					"scripts/encryptmaildir.py",
					"scripts/gme.py"],

	packages=[		"gmeutils",
					"mailtemplates",
					"documentation",
					"misc",
					"gmeutils/thirdparty",
					"gmeutils/thirdparty/dkim"],

	py_modules=[	"gpgmailencrypt"],

	package_data={	'mailtemplates': ['*/*'],
					"documentation":["*"],
					"misc":["*"],
					'gmeutils/thirdparty':["*.license"],
					},
)


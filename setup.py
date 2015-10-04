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
here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()
VERSIONFILE="gpgmailencrypt.py"
src = open(VERSIONFILE, "rt").read()
result=re.search("^VERSION=[\"]([\.0-9a-zA-Z]*)[\"]",src,re.M)
if result:
	versionstr=result.group(1)
else:
    	raise RuntimeError("Unable to find version string in %s." % (VERSIONFILE))

setup(
    name='gpgmailencrypt',
    description='an e-mail encryption module, gateway and daemon',
    version=versionstr,
    long_description=long_description,
    url='https://github.com/gpgmailencrypt/gpgmailencrypt',
    author='Horst Knorr',
    author_email='gpgmailencrypt@gmx.de',
    license='GPL v3',
    # See https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
	'Intended Audience :: System Administrators',
	'Intended Audience :: Information Technology',
        'Topic :: Software Development :: Build Tools',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
	"Topic :: Communications :: Email :: Mail Transport Agents",
	"Topic :: Communications :: Email",
	"Topic :: Security :: Cryptography",
	"Topic :: Software Development :: Libraries :: Python Modules",
	"Operating System :: OS Independent",
   ],

    keywords='Email encryption daemon gateway',
    scripts =["scripts/gme_admin.py","scripts/encryptmaildir.py"],
    packages=["","mailtemplates","documentation","misc"],
    package_data={'mailtemplates': ['*/*'],"documentation":["*"],"misc":["*"]},
    # https://packaging.python.org/en/latest/requirements.html
)


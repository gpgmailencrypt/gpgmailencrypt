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

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='gpgmailencrypt',
    version='2.0.0',

    description='an e-mail encryption module and daemon',
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
	"Topic :: Communications :: Email :: Mail Transport Agents",
	"Topic :: Communications :: Email",
	"Topic :: Security :: Cryptography",
	"Topic :: Software Development :: Libraries :: Python Modules",
	"Operating System :: OS Independent",
   ],

    keywords='Email encryption daemon',
    packages=find_packages(exclude=['contrib', 'docs', 'tests*']),
    # https://packaging.python.org/en/latest/requirements.html
)


#!/usr/bin/env python

import os
from distutils.core import setup

# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()


setup(name='ldapom',
      version='0.9.1',
      description='A simple ldap object mapper for python',
      author='Florian Richter',
      author_email='mail@f1ori.de',
      url='https://github.com/f1ori/ldapom',
      license='MIT',
      keywords = "ldap object mapper",
      long_description=read('README'),
      py_modules=['ldapom'],
     )

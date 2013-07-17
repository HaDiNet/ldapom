# -*- coding: utf-8 -*-

import os
from distutils.core import setup

import ldapom

# Utility function to read the README file.
def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(name='ldapom',
      version='0.10.0',
      description='A pythonic LDAP to Python object mapper',
      url='https://github.com/leonhandreke/ldapom',
      license='MIT',
      keywords = "ldap object mapper",
      long_description=read('README.md'),
      py_modules=['ldapom'],
      ext_modules=[ldapom.ffi.verifier.get_extension()],
     )


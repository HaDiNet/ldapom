# -*- coding: utf-8 -*-

import os
from setuptools import setup
from distutils.command.build import build

class cffi_build(build):
    """This is a shameful hack to ensure that cffi is present when
    we specify ext_modules. We can't do this eagerly because
    setup_requires hasn't run yet.

    Copied from https://github.com/xattr/xattr
    """
    def finalize_options(self):
        import ldapom
        self.distribution.ext_modules = [ldapom.connection.ffi.verifier.get_extension()]
        build.finalize_options(self)

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
      packages=['ldapom',],
      install_requires=['cffi'],
      setup_requires=['cffi'],
      zip_safe=False,
      cmdclass={'build': cffi_build},
     )


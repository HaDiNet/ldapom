# -*- coding: utf-8 -*-

from paver.easy import task, sh, needs, path
from paver.setuputils import setup

setup(name='ldapom',
      version='0.9.4',
      description='A simple ldap object mapper for python',
      author='Florian Richter',
      author_email='mail@f1ori.de',
      url='https://github.com/HaDiNet/ldapom',
      license='MIT',
      keywords = "ldap object mapper",
      long_description=path('README').text(),
      py_modules=['ldapom'],
     )

@task
def docs(options):
    sh('doxygen')

@task
def test(options):
    sh('python tests.py')

@task
def coverage(options):
    sh('coverage run --source ldapom.py ./tests.py')
    sh('coverage xml')

from paver.easy import task, sh, needs, path
from paver.setuputils import setup
import os


setup(name='ldapom',
      version='0.9.1',
      description='A simple ldap object mapper for python',
      author='Florian Richter',
      author_email='mail@f1ori.de',
      url='https://github.com/f1ori/ldapom',
      license='MIT',
      keywords = "ldap object mapper",
      long_description=path('README').text(),
      py_modules=['ldapom'],
     )

@task
def docs(options):
    sh('doxygen')

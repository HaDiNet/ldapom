# -*- coding: utf-8 -*-

import ldap
import os.path
import subprocess
from subprocess import Popen, check_call
from time import sleep


## Get absolute path of this module
def get_real_path():
    return os.path.realpath(os.path.dirname(__file__))


## make path ready for url parameter
def get_url_path(path=get_real_path()):
    return path.replace('/', '%2F')

## Get the absolute path to the default slapd.conf
def get_default_config_file():
    return os.path.join(get_real_path(), 'slapd.conf')


## Manager for OpenLDAP testing server
class LdapServer(object):
    def __init__(self, port=1381, tls_port=1382, config_file=get_default_config_file(), path=get_real_path()):
        self.server = None
        self.port = port
        self.tls_port = tls_port
        self.config_file = os.path.realpath(config_file)
        self.path = path

    ## destructor
    def __del__(self):
        self.stop()

    ## Reset ldap to ldif_file
    def load_data(self, ldif_file='testdata.ldif'):
        check_call(['rm', '-rf', '%s/ldapdata' % self.path])
        check_call(['mkdir', '-p', '%s/ldapdata' % self.path])
        check_call(['slapadd', '-l', os.path.join(self.path, ldif_file), '-f', self.config_file, '-d', '0'],
                stdout = open("/dev/null", "w"), cwd = self.path)

    ## The ldapi://-URL this LDAP server uses
    def ldapi_url(self):
        return 'ldapi://{0}%2Fldapi'.format(get_url_path(self.path))

    ## start ldap server
    def start(self, clean=True):
        if clean:
            self.load_data()
        self.server = Popen(['slapd', '-f', self.config_file, '-h', self.ldapi_url(), '-d', '0'],
             cwd = self.path,
             )
        # Busy wait until LDAP is ready
        tries = 0
        while tries < 100:
            tries += 1
            try:
                connection = ldap.initialize(self.ldapi_url())
                connection.simple_bind_s('cn=admin,dc=example,dc=com', 'admin')
                break
            except ldap.SERVER_DOWN:
                sleep(0.05)
        return

    ## stop ldap server
    def stop(self):
        if self.server:
            self.server.terminate()
        self.server = None

    ## restart ldapserver without clearing the server
    def restart(self):
        self.stop()
        self.start(clean=False)


# -*- coding: utf-8 -*-

import ldap
import os.path
import subprocess
from subprocess import Popen, check_call
from time import sleep


def get_real_path():
    """
    Get absolute path of this module
    """
    return os.path.realpath(os.path.dirname(__file__))


def get_url_path(path=get_real_path()):
    """
    make path ready for url parameter
    """
    return path.replace('/', '%2F')

def get_default_config_file():
    """
    Get the absolute path to the default slapd.conf
    """
    return os.path.join(get_real_path(), 'slapd.conf')

class LdapServer(object):
    """
    Manager for OpenLDAP testing server
    """
    def __init__(self, port=1381, tls_port=1382, config_file=get_default_config_file(), path=get_real_path()):
        self.server = None
        self.port = port
        self.tls_port = tls_port
        self.config_file = os.path.realpath(config_file)
        self.path = path

    def __del__(self):
        """
        destructor
        """
        self.stop()

    def load_data(self, ldif_file='testdata.ldif'):
        """
        Reset ldap to ldif_file
        """
        check_call(['rm', '-rf', '%s/ldapdata' % self.path])
        check_call(['mkdir', '-p', '%s/ldapdata' % self.path])
        check_call(['slapadd', '-l', os.path.join(self.path, ldif_file), '-f', self.config_file, '-d', '0'],
                stdout = open("/dev/null", "w"), cwd = self.path)

    def ldapi_url(self):
        """
        The ldapi://-URL this LDAP server uses
        """
        return 'ldapi://{0}%2Fldapi'.format(get_url_path(self.path))

    def start(self, clean=True):
        """
        start ldap server
        """
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

    def stop(self):
        """
        stop ldap server
        """
        if self.server:
            self.server.terminate()
        self.server = None

    def restart(self):
        """
        restart ldapserver without clearing the server
        """
        self.stop()
        self.start(clean=False)


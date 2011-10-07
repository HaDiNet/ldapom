# -*- coding: utf-8 -*-

import getpass
import os.path
import os

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


class LdapServer(object):
    """
    Manager for OpenLDAP testing server
    """
    def __init__(self, port=1381, tls_port=1382, config_file='slapd.conf', path=get_real_path()):
        self.server = None
        self.port = port
        self.tls_port = tls_port
        self.config_file = config_file
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
        check_call(['ldapadd', '-H', 'ldap://localhost:%d' % self.port, '-D', 'cn=admin,dc=example,dc=com', '-w', 'admin', '-x'],
             stdin = open('%s/%s' % (self.path, ldif_file), "r"),
             stdout = open("/dev/null", "w"),
            )
        
    def start(self, clean=True):
        """
        start ldap server
        """
        conn_str = 'ldapi://%s%%2Fldapi ldap://127.0.0.1:1381' % get_url_path(self.path)
        self.server = Popen(['slapd', '-f', self.config_file, '-h', conn_str],
             cwd = self.path,
             stdout = subprocess.PIPE,
             )
        self.server.stdout.read() # read until end -> slapd went to background
        if clean:
            self.load_data()

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


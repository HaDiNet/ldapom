#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import doctest
import ldapom
import openldap

def set_up(docTest):
    docTest.ldap_server = openldap.LdapServer()
    docTest.ldap_server.start()
    docTest.ldap_connection = ldapom.LdapConnection(uri='ldap://localhost:1381', base='dc=example,dc=com', login='cn=admin,dc=example,dc=com', password='admin')
    docTest.globs['ldap_server'] = docTest.ldap_server
    docTest.globs['ldap_connection'] = docTest.ldap_connection
    docTest.globs['jack_node'] = docTest.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')

def tear_down(docTest):
    docTest.ldap_server.stop()

def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite(ldapom, setUp=set_up, tearDown=tear_down))
    tests.addTests(doctest.DocFileSuite('README', setUp=set_up, tearDown=tear_down))
    return tests

if __name__ == '__main__':
    unittest.main()

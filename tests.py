#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest2 as unittest
import doctest
import ldapom
import openldap
import ldap

## general testcase class for ldap tests
##
## starts ldap and loads testdata
class LdapTest(unittest.TestCase):
    def setUp(self):
        self.ldap_server = openldap.LdapServer()
        self.ldap_server.start()
        self.ldap_connection = ldapom.LdapConnection(
                uri=self.ldap_server.ldapi_url(),
                base='dc=example,dc=com',
                login='cn=admin,dc=example,dc=com',
                password='admin'
        )

    def tearDown(self):
        self.ldap_server.stop()


## Testcases for ldapom
class LdapomTest(LdapTest):
    ## a function applied to all input strings
    def string_cleaner(self, x):
        return x

    ## test openning of connection to ldap with valid credentials
    def test_login_normal(self):
        s = lambda x: self.string_cleaner(x)
        self.ldap_connection = ldapom.LdapConnection(
                uri=s(self.ldap_server.ldapi_url()),
                base=s('dc=example,dc=com'),
                login=s('cn=Noël,dc=example,dc=com'),
                password=s('noel')
        )

    ## test login with invalid credentials
    def test_login_invalid(self):
        s = lambda x: self.string_cleaner(x)
        # test invalid credentials (end password with umlauts)
        with self.assertRaises(ldap.INVALID_CREDENTIALS):
            ldapom.LdapConnection(
                uri = s(self.ldap_server.ldapi_url()),
                base = s('dc=example,dc=com'),
                login = s('cn=ädmin,dc=example,dc=com'),
                password = s('ädmin')
            )

    ## test check_if_dn_exists
    def test_exists(self):
        s = lambda x: self.string_cleaner(x)
        self.assertTrue(self.ldap_connection.check_if_dn_exists(s('cn=jack,dc=example,dc=com')))
        self.assertFalse(self.ldap_connection.check_if_dn_exists(s('cn=nobody,dc=example,dc=com')))
        self.assertFalse(self.ldap_connection.check_if_dn_exists(s('cn=umlautä,dc=example,dc=com')))

    ## test rename method
    def test_rename(self):
        s = lambda x: self.string_cleaner(x)
        self.assertTrue(self.ldap_connection.check_if_dn_exists(s('cn=Noël,dc=example,dc=com')))
        self.assertFalse(self.ldap_connection.check_if_dn_exists(s('cn=Noël2,dc=example,dc=com')))
        self.ldap_connection.rename(s('cn=Noël,dc=example,dc=com'), s('cn=Noël2'))
        self.assertFalse(self.ldap_connection.check_if_dn_exists(s('cn=Noël,dc=example,dc=com')))
        self.assertTrue(self.ldap_connection.check_if_dn_exists(s('cn=Noël2,dc=example,dc=com')))

    ## test delete method
    def test_delete(self):
        s = lambda x: self.string_cleaner(x)
        self.assertTrue(self.ldap_connection.check_if_dn_exists(s('cn=jack,dc=example,dc=com')))
        node = self.ldap_connection.get_ldap_node(s('cn=jack,dc=example,dc=com'))
        node.delete()
        self.assertFalse(self.ldap_connection.check_if_dn_exists(s('cn=jack,dc=example,dc=com')))

    ## test check_password method
    def test_check_password(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.get_ldap_node(s('cn=Noël,dc=example,dc=com'))
        self.assertTrue(node.check_password(s('noel')))
        self.assertFalse(node.check_password(s('wrong_pw')))

    ## test set_password method
    def test_set_password(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.get_ldap_node(s('cn=Noël,dc=example,dc=com'))
        node.set_password(s('asdfä'))
        self.assertTrue(node.check_password(s('asdfä')))

    ## test new_ldap_node method
    def test_new_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.new_ldap_node('cn=newuser,dc=example,dc=com')
        node.objectClass = ['person']
        node.sn = s('Sören')
        node.cn = s('newuser')
        node.save() # the object is created not until here!
        node = self.ldap_connection.get_ldap_node('cn=newuser,dc=example,dc=com')
        self.assertEquals('Sören'.decode('utf-8'), unicode(node.sn))
        self.assertEquals('newuser'.decode('utf-8'), unicode(node.cn))

    ## test get ldap node
    def test_get_ldap_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        self.assertEquals('jack'.decode('utf-8'), node.uid.__unicode__())
        self.assertEquals(
            ['person'.decode('utf-8'), 'posixAccount'.decode('utf-8')],
            [unicode(x) for x in node.objectClass]
        )
        # make sure, it's lazy
        node = self.ldap_connection.get_ldap_node('cn=nobody,dc=example,dc=com')
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            unicode(node.cn)

    def test_retrieve_ldap_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.retrieve_ldap_node('cn=jack,dc=example,dc=com')
        self.assertEquals('jack'.decode('utf-8'), unicode(node.uid))
        # make sure, it's not lazy
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            node = self.ldap_connection.retrieve_ldap_node('cn=nobody,dc=example,dc=com')

    ## test changing node attributes
    def test_change_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        node.sn = s('Sören')
        node.save()
        self.assertEquals('Sören'.decode('utf-8'), unicode(node.sn))


## Testcase ldapom with unicode-strings
class LdapomUnicodeTest(LdapomTest):
    ## decode all input strings to unicode strings
    def string_cleaner(self, x):
        return x.decode('utf-8')


def set_up(docTest):
    docTest.ldap_server = openldap.LdapServer()
    docTest.ldap_server.start()
    docTest.ldap_connection = ldapom.LdapConnection(uri=docTest.ldap_server.ldapi_url(), base='dc=example,dc=com', login='cn=admin,dc=example,dc=com', password='admin')
    docTest.globs['ldap_server'] = docTest.ldap_server
    docTest.globs['ldap_connection'] = docTest.ldap_connection
    docTest.globs['lc'] = docTest.ldap_connection
    docTest.globs['jack_node'] = docTest.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
    # delete Noël, as doctests can't cope with non ascii characters
    docTest.ldap_connection.delete('cn=Noël,dc=example,dc=com')

def tear_down(docTest):
    docTest.ldap_server.stop()

def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite(ldapom, setUp=set_up, tearDown=tear_down))
    tests.addTests(doctest.DocFileSuite('README', setUp=set_up, tearDown=tear_down))
    return tests

if __name__ == '__main__':
    unittest.main()

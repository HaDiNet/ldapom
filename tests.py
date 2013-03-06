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

    ## test searching
    def test_search(self):
        s = lambda x: self.string_cleaner(x)
        result = self.ldap_connection.search(s('cn=*n*'))
        self.assertEqual("[<LdapNode: cn=daniel,dc=example,dc=com>, <LdapNode: cn=Noël,dc=example,dc=com>]", repr(list(result)))

    ## test __str__
    def test_to_string(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertEqual("cn=Noël,dc=example,dc=com", str(node))
        self.assertEqual("Noël", str(node.cn))
        self.assertEqual("['person', 'posixAccount']", str(node.objectClass))

    ## test __unicode__
    def test_to_unicode(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertEqual(u"cn=Noël,dc=example,dc=com", unicode(node))
        self.assertEqual(u"Noël", unicode(node.cn))
        self.assertEqual(u"[u'person', u'posixAccount']", unicode(node.objectClass))

    ## test __repr__
    def test_repr(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertEqual("<LdapNode: cn=Noël,dc=example,dc=com>", repr(node))
        self.assertEqual("<LdapAttribute: cn=Noël>", repr(node.cn))
        self.assertEqual("<LdapAttribute: objectClass=[u'person', u'posixAccount']>", repr(node.objectClass))

    ## test get_parent
    def test_get_parent(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        parent = node.get_parent()
        self.assertEqual("<LdapNode: dc=example,dc=com>", repr(parent))
        self.assertEqual(u"example", unicode(parent.o))
        self.assertEqual("<LdapNode: dc=com>", repr(parent.get_parent()))

    ## test is_object_class
    def test_is_object_class(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertTrue(node.is_posixAccount)
        self.assertFalse(node.is_windowsAccount)


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

def tear_down(docTest):
    docTest.ldap_server.stop()

def load_tests(loader, tests, ignore):
    tests.addTests(doctest.DocTestSuite(ldapom, setUp=set_up, tearDown=tear_down))
    tests.addTests(doctest.DocFileSuite('README', setUp=set_up, tearDown=tear_down))
    return tests

if __name__ == '__main__':
    unittest.main()

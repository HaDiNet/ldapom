# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import doctest
import unittest

import ldapom
import openldap

class LDAPServerMixin(object):
    """Mixin to set up an LDAPConnection connected to a testing LDAP server.
    """
    def setUp(self):
        self.ldap_server = openldap.LdapServer()
        self.ldap_server.start()
        import time; time.sleep(5)
        self.ldap_connection = ldapom.LDAPConnection(
                uri=self.ldap_server.ldapi_url(),
                base='dc=example,dc=com',
                bind_dn='cn=admin,dc=example,dc=com',
                bind_password='admin')

    def tearDown(self):
        self.ldap_server.stop()


class LDAPomTest(LDAPServerMixin, unittest.TestCase):

    def test_init_with_credentials(self):
        # Test normal instantiation with valid credentials
        ldapom.LDAPConnection(
                uri=self.ldap_server.ldapi_url(),
                base="dc=example,dc=com",
                bind_dn="cn=Noël,dc=example,dc=com",
                bind_password="noel")

        # Test with invalid credentials
        with self.assertRaises(ldapom.LDAPInvalidCredentialsError):
            ldapom.LDAPConnection(
                    uri=self.ldap_server.ldapi_url(),
                    base="dc=example,dc=com",
                    bind_dn="cn=Noël,dc=example,dc=com",
                    bind_password="invalid")

    def test_authenticate(self):
        self.assertTrue(self.ldap_connection.authenticate(
            bind_dn="cn=Noël,dc=example,dc=com",
            bind_password="noel"))
        self.assertFalse(self.ldap_connection.authenticate(
            bind_dn="cn=Noël,dc=example,dc=com",
            bind_password="invalid"))

    def test_exists(self):
        self.assertTrue(self.ldap_connection.get_entry(
            "cn=jack,dc=example,dc=com").exists())
        self.assertFalse(self.ldap_connection.get_entry(
            "cn=nobody,dc=example,dc=com").exists())
        self.assertFalse(self.ldap_connection.get_entry(
            "cn=umlautä,dc=example,dc=com").exists())

    def test_create_entry(self):
        entry = self.ldap_connection.get_entry(
                "cn=sören.pequeño,dc=example,dc=com")
        entry.objectClass = ["person", "top"]
        entry.sn = "Sören Pequeño"
        entry.cn = "sören.pequeño"
        entry.save()

        # Verify that the new entry arrived at the server
        entry = self.ldap_connection.get_entry(
                "cn=sören.pequeño,dc=example,dc=com")
        self.assertEquals(entry.sn, "Sören Pequeño")
        self.assertEquals(entry.cn, "sören.pequeño")

## Testcases for ldapom
class LdapomTest(object):
    ## a function applied to all input strings
    def string_cleaner(self, x):
        return x

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
        self.assertEquals([u'Sören'], node.sn)
        self.assertEquals([u'newuser'], node.cn)

    ## test get ldap node
    def test_get_ldap_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        self.assertEquals([u'jack'], node.uid)
        self.assertEquals(
            [u'person', u'posixAccount'],
            [unicode(x) for x in node.objectClass]
        )
        # make sure, it's lazy
        node = self.ldap_connection.get_ldap_node('cn=nobody,dc=example,dc=com')
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            unicode(node.cn)

    def test_retrieve_ldap_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.retrieve_ldap_node('cn=jack,dc=example,dc=com')
        self.assertEquals([u'jack'], node.uid)
        # make sure, it's not lazy
        with self.assertRaises(ldap.NO_SUCH_OBJECT):
            node = self.ldap_connection.retrieve_ldap_node('cn=nobody,dc=example,dc=com')

    ## test changing node attributes
    def test_change_node(self):
        s = lambda x: self.string_cleaner(x)
        node = self.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        node.sn = s('Sören')
        node.save()
        node = self.ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        self.assertEquals([u'Sören'], node.sn)

    ## test searching
    def test_search(self):
        s = lambda x: self.string_cleaner(x)
        result = self.ldap_connection.search(s('cn=*n*'))
        self.assertEqual("[<LdapNode: cn=daniel,dc=example,dc=com>, <LdapNode: cn=Noël,dc=example,dc=com>]", repr(list(result)))

    ## test __str__
    def test_to_string(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertEqual("cn=Noël,dc=example,dc=com", str(node))

    ## test __unicode__
    def test_to_unicode(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertEqual(u"cn=Noël,dc=example,dc=com", unicode(node))

    ## test __repr__
    def test_repr(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertEqual("<LdapNode: cn=Noël,dc=example,dc=com>", repr(node))

    ## test get_parent
    def test_get_parent(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        parent = node.get_parent()
        self.assertEqual("<LdapNode: dc=example,dc=com>", repr(parent))
        self.assertEqual([u"example"], parent.o)
        self.assertEqual("<LdapNode: dc=com>", repr(parent.get_parent()))

    ## test is_object_class
    def test_is_object_class(self):
        node = self.ldap_connection.get_ldap_node('cn=Noël,dc=example,dc=com')
        self.assertTrue(node.is_posixAccount)
        self.assertFalse(node.is_windowsAccount)


## Testcase ldapom with unicode-strings
class LdapomUnicodeTest(object):
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
    #tests.addTests(doctest.DocTestSuite(ldapom, setUp=set_up, tearDown=tear_down))
    #tests.addTests(doctest.DocFileSuite('README', setUp=set_up, tearDown=tear_down))
    return tests

if __name__ == '__main__':
    unittest.main()

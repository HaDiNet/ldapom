# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import unittest

import ldapom
import openldap

class LDAPServerMixin(object):
    """Mixin to set up an LDAPConnection connected to a testing LDAP server.
    """
    def setUp(self):
        self.ldap_server = openldap.LdapServer()
        self.ldap_server.start()
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

    def test_can_bind(self):
        self.assertTrue(self.ldap_connection.can_bind(
            bind_dn="cn=Noël,dc=example,dc=com",
            bind_password="noel"))
        self.assertFalse(self.ldap_connection.can_bind(
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
        self.assertEqual(entry.sn, "Sören Pequeño")
        self.assertEqual(entry.cn, "sören.pequeño")

    def test_delete_entry(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertTrue(entry.exists())
        entry.delete()
        self.assertFalse(entry.exists())

    def test_create_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        entry.description = "Test user"
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        entry.fetch()
        self.assertEqual(entry.description, "Test user")

    def test_delete_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/bash")
        del entry.loginShell
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertRaises(AttributeError, getattr, entry, "loginShell")

    def test_modify_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/bash")
        entry.loginShell = "/bin/zsh"
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/zsh")

    def test_object_class_getter(self):
        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        self.assertTrue(entry.is_person)
        self.assertFalse(entry.is_monkey)

    def test_get_parent(self):
        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        parent_entry = entry.get_parent()
        self.assertEqual(parent_entry.dn, "dc=example,dc=com")

    def test_search(self):
        result = self.ldap_connection.search("cn=*n*")
        self.assertEqual(set(["Noël", "daniel"]), set([r.cn for r in result]))


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

    ## test searching
    def test_search(self):
        s = lambda x: self.string_cleaner(x)
        result = self.ldap_connection.search(s('cn=*n*'))
        self.assertEqual("[<LdapNode: cn=daniel,dc=example,dc=com>, <LdapNode: cn=Noël,dc=example,dc=com>]", repr(list(result)))



if __name__ == '__main__':
    unittest.main()

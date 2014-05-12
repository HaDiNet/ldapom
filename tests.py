# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import sys
import unittest

import ldapom
import test_server

if sys.version_info[0] >= 3: # Python 3
    unicode = str

class LDAPServerMixin(object):
    """Mixin to set up an LDAPConnection connected to a testing LDAP server.
    """
    def setUp(self):
        self.ldap_server = test_server.LDAPServer()
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

    def test_entry_can_bind(self):
        entry = self.ldap_connection.get_entry("cn=Noël,dc=example,dc=com")
        self.assertTrue(entry.can_bind("noel"))
        self.assertFalse(entry.can_bind("invalid"))

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

    def test_create_entry_with_empty_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=sören.pequeño,dc=example,dc=com")
        entry.objectClass = ["person", "top"]
        entry.sn = "Sören Pequeño"
        entry.cn = "sören.pequeño"
        entry.givenName = []
        entry.save()

        # Verify that the new entry arrived at the server
        entry = self.ldap_connection.get_entry(
                "cn=sören.pequeño,dc=example,dc=com")
        self.assertEqual(entry.sn, {"Sören Pequeño"})
        self.assertEqual(entry.cn, {"sören.pequeño"})

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
        self.assertEqual(entry.description, {"Test user"})

    def test_create_invalid_attribute_name(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        with self.assertRaises(ldapom.LDAPAttributeNameNotFoundError):
            entry.invalidAttribute = 'invalid'

    def test_delete_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/bash")
        del entry.loginShell
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertRaises(AttributeError, getattr, entry, "loginShell")

    def test_modify_single_value_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/bash")
        entry.loginShell = "/bin/zsh"
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/zsh")
        entry.loginShell = None
        self.assertEqual(entry.loginShell, None)
        entry.save()

        entry.fetch()
        self.assertRaises(AttributeError, getattr, entry, "loginShell")

    def test_modify_multi_value_attribute(self):
        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.loginShell, "/bin/bash")
        entry.sn = "Jaqueline"
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.sn, {"Jaqueline"})
        entry.sn = {"Jaqueline", "Jacky"}
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.sn, {"Jaqueline", "Jacky"})

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        entry.sn.add("Jacko")
        entry.save()

        entry = self.ldap_connection.get_entry(
                "cn=jack,dc=example,dc=com")
        self.assertEqual(entry.sn, {"Jaqueline", "Jacky", "Jacko"})

    def test_object_class_getter(self):
        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        self.assertTrue(entry.is_person)
        self.assertFalse(entry.is_monkey)

    def test_dn_computed_properties(self):
        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        self.assertEqual(entry.dn, "cn=daniel,dc=example,dc=com")
        self.assertEqual(entry.parent_dn, "dc=example,dc=com")
        self.assertEqual(entry.rdn, "cn=daniel")

    def test_search(self):
        result = self.ldap_connection.search("cn=*n*")
        self.assertEqual(set(["Noël", "daniel"]),
                set([next(iter(r.cn)) for r in result]))

    def test_search_empty_result(self):
        result = self.ldap_connection.search("cn=nobody")
        self.assertRaises(StopIteration, next, result)

    def test_rename(self):
        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        entry.rename("cn=dieter,dc=example,dc=com")
        self.assertTrue(entry.exists())

        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        self.assertFalse(entry.exists())

        entry = self.ldap_connection.get_entry(
                "cn=dieter,dc=example,dc=com")
        self.assertTrue(entry.exists())
        self.assertEqual(entry.cn, {"dieter"})

    def test_attribute_string_representation(self):
        cn_attr = self.ldap_connection.get_attribute_type("cn")("cn")
        cn_attr.values = {"günther", }
        self.assertEqual(unicode(cn_attr), "cn: günther")

        cn_attr.values = {"günther", "gunther"}
        self.assertTrue(
                unicode(cn_attr) == "cn: günther, gunther" or
                unicode(cn_attr) == "cn: gunther, günther")

        self.assertEqual(cn_attr.__repr__(), str("<LDAPAttribute cn>"))

    def test_entry_save_without_fetch(self):
        entry = self.ldap_connection.get_entry(
                "cn=daniel,dc=example,dc=com")
        self.assertRaises(ldapom.LDAPomError, entry.save)

    def test_fetch_nonexistant_entry(self):
        entry = self.ldap_connection.get_entry(
                "cn=doesnotexist,dc=example,dc=com")
        self.assertRaises(ldapom.LDAPNoSuchObjectError, entry.fetch)

    def test_set_password(self):
        self.assertTrue(self.ldap_connection.can_bind(
            bind_dn="cn=Noël,dc=example,dc=com",
            bind_password="noel"))
        self.ldap_connection.get_entry("cn=Noël,dc=example,dc=com").set_password("new")
        self.assertTrue(self.ldap_connection.can_bind(
            bind_dn="cn=Noël,dc=example,dc=com",
            bind_password="new"))

    def test_entry_empty_multi_value_attribute(self):
        entry = self.ldap_connection.get_entry("cn=daniel,dc=example,dc=com")
        del entry.description
        self.assertEqual(set(), entry.description)

        # Ensure that saving still works
        entry.description.add('superman')
        entry.save()
        entry = self.ldap_connection.get_entry("cn=daniel,dc=example,dc=com")
        self.assertEqual({'superman'}, entry.description)

    def test_entry_nonexistant_single_value_attribute(self):
        entry = self.ldap_connection.get_entry("cn=daniel,dc=example,dc=com")
        del entry.loginShell
        with self.assertRaises(AttributeError):
            entry.loginShell

    def test_retrieve_operational_attributes(self):
        # Test for https://github.com/HaDiNet/ldapom/issues/29
        entry = self.ldap_connection.get_entry("cn=daniel,dc=example,dc=com",
                                               retrieve_operational_attributes=True)
        entry.fetch()
        entry.entryCSN

    def test_set_binary_attribute(self):
        entry = self.ldap_connection.get_entry("cn=daniel,dc=example,dc=com")
        # binary_value has a NULL byte in the middle!
        fake_jpeg = b'\xff\xd8\xff\xe0\x00\x10\xff'
        entry.jpegPhoto = fake_jpeg
        entry.save()
        entry.fetch()
        self.assertEqual(entry.jpegPhoto, {fake_jpeg})


if __name__ == '__main__':
    unittest.main()

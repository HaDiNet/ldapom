# -*- coding: utf-8 -*-
"""A CFFI/libldap-based LDAP connection."""

from __future__ import unicode_literals
from __future__ import print_function

from ldapom.cdef import libldap, ffi
from ldapom import attribute
from ldapom import compat
from ldapom.entry import LDAPEntry
from ldapom import error

LDAP_SCOPE_BASE = libldap.LDAP_SCOPE_BASE
LDAP_SCOPE_SUBTREE = libldap.LDAP_SCOPE_SUBTREE
LDAP_SCOPE_ONELEVEL = libldap.LDAP_SCOPE_ONELEVEL


def handle_ldap_error(err):
    """Given an LDAP error code, raise an error if needed.

    :param err: The error code returned by the library.
    :type err: int
    """
    if err == libldap.LDAP_SUCCESS:
        return

    error_string = compat._decode_utf8(ffi.string(libldap.ldap_err2string(err)))
    if err == libldap.LDAP_NO_SUCH_OBJECT:
        raise error.LDAPNoSuchObjectError(error_string)
    elif err == libldap.LDAP_INVALID_CREDENTIALS:
        raise error.LDAPInvalidCredentialsError(error_string)
    elif err == libldap.LDAP_SERVER_DOWN:
        raise error.LDAPServerDownError(error_string)
    else:
        raise error.LDAPError(error_string)


class LDAPConnection(object):
    """Connection to an LDAP server."""

    def __init__(self, uri, base, bind_dn, bind_password,
            cacertfile=None, timelimit=30):
        """
        :param uri: URI of the server to connect to.
        :param base: Base DN for LDAP operations.
        :param login: DN to bind with.
        :param password: Password to bind with.
        :param cacertfile: If using SSL/TLS this is certificate of the server
        :param timelimit: Defines the time limit after which a search
            operation should be terminated by the server
        """
        self._base = base
        self._uri = uri
        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._cacertfile = cacertfile

        ld_p = ffi.new("LDAP **")
        err = libldap.ldap_initialize(ld_p, compat._encode_utf8(uri))
        handle_ldap_error(err)
        self._ld = ld_p[0]

        version_p = ffi.new("int *")
        version_p[0] = libldap.LDAP_VERSION3
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_PROTOCOL_VERSION, version_p)

        if cacertfile:
            require_cert_p = ffi.new("int *")
            require_cert_p[0] = libldap.LDAP_OPT_X_TLS_NEVER
            libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_X_TLS_REQUIRE_CERT,
                    require_cert_p);

            libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_X_TLS_CACERTFILE,
                    compat._encode_utf8(cacertfile))

        # For TLS options to take effect, a context refresh seems to be needed.
        newctx_p = ffi.new("int *")
        newctx_p[0] = 0
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_X_TLS_NEWCTX, newctx_p)

        timelimit_p = ffi.new("int *")
        timelimit_p[0] = timelimit
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_TIMELIMIT, timelimit_p)

        err = libldap.ldap_simple_bind_s(self._ld,
                compat._encode_utf8(bind_dn),
                compat._encode_utf8(bind_password))
        handle_ldap_error(err)

        self._fetch_attribute_types()

    def _fetch_attribute_types(self):
        result = list(
                self._raw_search(base="cn=subschema",
                    scope=libldap.LDAP_SCOPE_BASE,
                    search_filter="(objectClass=*)",
                    retrieve_attributes=["attributeTypes"]))
        # Decode the type definitions returned to strings
        attribute_type_definitions = map(compat._decode_utf8,
                result[0][1][compat._encode_utf8("attributeTypes")])

        self._attribute_types_by_name = attribute.build_attribute_types(
                attribute_type_definitions)

    def get_attribute_type(self, name):
        """Get the Python type to represent an attribute.

        :param name: The name of the attribute to look up the type for.
        :type name: str
        :rtype: a class object, a subclass of ``LDAPAttributeBase``.
        """
        if name in self._attribute_types_by_name:
            return self._attribute_types_by_name[name]
        else:
            raise error.LDAPAttributeNameNotFoundError

    def can_bind(self, bind_dn, bind_password):
        """Try to bind with the given credentials.

        :param bind_dn: DN to bind with.
        :type bind_dn: str
        :param bind_password: Password to bind with.
        :type bind_password: str
        :rtype: boolean
        """
        try:
            self.__class__(self._uri, self._base, bind_dn, bind_password,
                    self._cacertfile)
        except error.LDAPInvalidCredentialsError:
            return False
        return True

    def _raw_search(self, search_filter=None, retrieve_attributes=None,
            base=None, scope=libldap.LDAP_SCOPE_SUBTREE):
        """
        Raw wrapper around OpenLDAP ldap_search_ext_s.

        :param search_filter: Filter expression to use. OpenLDAP default used
            if None is given.
        :type search_filter: List of str
        :param retrieve_attributes: List of attributes to retrieve. If None is
            given, all are retrieved.
        :type retrieve_attributes: List of str
        :param base: Search base for the query.
        :type base: str
        :param scope: The search scope in the LDAP tree
        """
        search_result_p = ffi.new("LDAPMessage **")

        # Keep around references to pointers to owned memory with data that is
        # still needed.
        prevent_garbage_collection = []

        if retrieve_attributes is not None:
            attrs_p = ffi.new("char*[{}]".format(len(retrieve_attributes) + 1))
            for i, a in enumerate(retrieve_attributes):
                attr_p = ffi.new("char[]", compat._encode_utf8(a))
                prevent_garbage_collection.append(attr_p)
                attrs_p[i] = attr_p
            attrs_p[len(retrieve_attributes)] = ffi.NULL
        else:
            attrs_p = ffi.NULL

        err = libldap.ldap_search_ext_s(
                self._ld,
                compat._encode_utf8(base or self._base),
                scope,
                (compat._encode_utf8(search_filter)
                    if search_filter is not None else ffi.NULL),
                attrs_p,
                0,
                ffi.NULL, ffi.NULL,
                ffi.NULL, # TODO: Implement timeouts
                0,#libldap.LDAP_NO_LIMIT,
                search_result_p)
        handle_ldap_error(err)
        search_result = search_result_p[0]

        current_entry = libldap.ldap_first_entry(self._ld, search_result)
        while current_entry != ffi.NULL:
            dn = ffi.string(libldap.ldap_get_dn(self._ld, current_entry))
            attribute_dict = {}

            ber_p = ffi.new("BerElement **")
            current_attribute = libldap.ldap_first_attribute(self._ld,
                    current_entry, ber_p)
            while current_attribute != ffi.NULL:
                current_attribute_str = ffi.string(current_attribute)
                attribute_dict[current_attribute_str] = []

                values_p = libldap.ldap_get_values(self._ld, current_entry,
                        current_attribute)
                for i in range(0, libldap.ldap_count_values(values_p)):
                    attribute_dict[current_attribute_str].append(
                            ffi.string(values_p[i]))

                current_attribute = libldap.ldap_next_attribute(self._ld,
                        current_entry, ber_p[0])
            # TODO: Call ber_free on ber_p[0]

            yield (dn, attribute_dict)
            current_entry = libldap.ldap_next_entry(self._ld, current_entry)
            # TODO: Call ldap_msgfree on search_result

    def search(self, *args, **kwargs):
        """Perform an LDAP search operation.

        :rtype: Iterable of LDAPEntry.
        """
        try:
            for dn, attributes_dict in self._raw_search(*args, **kwargs):
                entry = LDAPEntry(self, compat._decode_utf8(dn),
                        attributes=set())
                for name, value in attributes_dict.items():
                    # TODO: Create the right type of LDAPAttribute here
                    attribute_type = self.get_attribute_type(
                            compat._decode_utf8(name))
                    attribute = attribute_type(compat._decode_utf8(name))
                    attribute._set_ldap_values(value)
                    entry.attributes.add(attribute)
                yield entry
        except error.LDAPNoSuchObjectError:
            # If the search returned without results, "return" an empty generator.
            return

    def get_entry(self, *args, **kwargs):
        """Get an LDAPEntry object associated with this connection."""
        return LDAPEntry(self, *args, **kwargs)

    def delete(self, entry, recursive=False):
        """Delete an entry on the LDAP server.

        :param entry: The entry to delete.
        :type entry: ldapom.LDAPEntry
        :param recursive: If subentries should be deleted recursively.
        :type recursive: bool
        """
        if recursive:
            entries_to_delete = self._connection.search(
                    base=entry.dn,
                    scope=LDAP_SCOPE_ONELEVEL)
            for entry in entries_to_delete:
                entry.delete(recursive=True)
        err = libldap.ldap_delete_s(self._ld,
                compat._encode_utf8(entry.dn))
        handle_ldap_error(err)

    def rename(self, entry, new_dn):
        """Rename an entry on the LDAP server.

        :param entry: The entry to rename.
        :type entry: ldapom.LDAPEntry
        :param new_dn: The DN that the entry should have after the rename.
        :type new_dn: str
        """
        new_rdn, new_parent_dn = new_dn.split(",", 1)
        if new_parent_dn == entry.parent_dn:
            new_parent_dn = None

        err = libldap.ldap_rename_s(self._ld,
                compat._encode_utf8(entry.dn),
                compat._encode_utf8(new_rdn),
                (compat._encode_utf8(new_parent_dn)
                    if new_parent_dn is not None else ffi.NULL),
                1, # Delete old RDN
                ffi.NULL, ffi.NULL)
        handle_ldap_error(err)

        entry._dn = new_dn

    def exists(self, entry):
        """Checks if a the given entry exists on the LDAP server.

        :param entry: The entry to check the existence of.
        :type entry: ldapom.LDAPEntry
        """
        entry_search_result = list(self.search(
            base=entry.dn, scope=LDAP_SCOPE_BASE))
        return len(entry_search_result) == 1

    def save(self, entry):
        """Save the given entry and its attribute values to the LDAP server.

        :param entry: The entry to save.
        :type entry: ldapom.LDAPEntry
        """
        entry_exists = entry.exists()
        # Refuse to save if attributes have not been fetched or set explicitly.
        if entry.attributes is None:
            raise error.LDAPomError("Cannot save without attributes "
                    "previously fetched or set.")

        # Temporary attribute set that will contain deleted attributes as
        # LDAPAttribute objects without any values.
        save_attributes = entry.attributes.copy()
        # Don't try to save empty attributes as this fails if the entry does
        # not exist on the server yet.
        if not entry_exists:
            save_attributes = set(filter(lambda attr: len(attr._values) > 0,
                    save_attributes))

        deleted_attribute_names = entry._old_attribute_names.difference(
                [a.name for a in entry.attributes])
        for name in deleted_attribute_names:
            attribute_type = self.get_attribute_type(name)
            save_attributes.add(attribute_type(name))

        # Keep around references to pointers to owned memory with data that is
        # still needed.
        prevent_garbage_collection = []

        mods = ffi.new("LDAPMod*[{}]".format(len(save_attributes) + 1))
        for i, attribute in enumerate(save_attributes):
            mod = ffi.new("LDAPMod *")
            prevent_garbage_collection.append(mod)

            mod.mod_op = libldap.LDAP_MOD_REPLACE

            mod_type = ffi.new("char[]", compat._encode_utf8(attribute.name))
            prevent_garbage_collection.append(mod_type)
            mod.mod_type = mod_type

            modv_strvals = ffi.new("char*[{}]".format(len(attribute._values) + 1))
            prevent_garbage_collection.append(modv_strvals)
            for j, value in enumerate(attribute._get_ldap_values()):
                strval = ffi.new("char[]", value)
                prevent_garbage_collection.append(strval)
                modv_strvals[j] = strval
            modv_strvals[len(attribute._values)] = ffi.NULL
            mod.mod_vals = {"modv_strvals": modv_strvals}

            mods[i] = mod
        mods[len(save_attributes)] = ffi.NULL

        if entry_exists:
            err = libldap.ldap_modify_ext_s(self._ld,
                    compat._encode_utf8(entry.dn),
                    mods,
                    ffi.NULL, ffi.NULL)
        else:
            err = libldap.ldap_add_ext_s(self._ld,
                    compat._encode_utf8(entry.dn),
                    mods,
                    ffi.NULL, ffi.NULL)
        handle_ldap_error(err)

        entry._old_attribute_names = set([a.name for a in entry.attributes])

    def fetch(self, entry):
        """Fetch an entry's attributes from the LDAP server.

        :param entry: The entry to fetch.
        :type entry: ldapom.LDAPEntry
        """
        try:
            fetched_entry = next(self.search(base=entry.dn,
                scope=libldap.LDAP_SCOPE_BASE))
            entry.attributes = fetched_entry.attributes
            entry._old_attribute_names = set([a.name for a in entry.attributes])
        except StopIteration:
            raise error.LDAPNoSuchObjectError()

    def set_password(self, entry, password):
        """Set the bind password for an entry.

        :param entry: The entry to set the password for.
        :type entry: ldapom.LDAPEntry
        :param password: The password to set.
        :type password: str
        """
        password_p = ffi.new("char[]", compat._encode_utf8(password))
        password_berval = libldap.ber_bvstr(password_p)
        entry_dn_p = ffi.new("char[]", compat._encode_utf8(entry.dn))
        entry_dn_berval = libldap.ber_bvstr(entry_dn_p)

        err = libldap.ldap_passwd_s(self._ld,
                entry_dn_berval,
                ffi.NULL,
                password_berval, password_berval,
                ffi.NULL, ffi.NULL)
        handle_ldap_error(err)

# -*- coding: utf-8 -*-
"""A CFFI/libldap-based LDAP connection."""

from __future__ import unicode_literals
from __future__ import print_function

import copy
import sys

from ldapom.cdef import libldap, ffi
from ldapom import attribute
from ldapom import compat
from ldapom.entry import LDAPEntry
from ldapom import error

LDAP_SCOPE_BASE = libldap.LDAP_SCOPE_BASE
LDAP_SCOPE_SUBTREE = libldap.LDAP_SCOPE_SUBTREE
LDAP_SCOPE_ONELEVEL = libldap.LDAP_SCOPE_ONELEVEL

LDAP_OPT_X_TLS_NEVER = libldap.LDAP_OPT_X_TLS_NEVER
LDAP_OPT_X_TLS_HARD = libldap.LDAP_OPT_X_TLS_HARD
LDAP_OPT_X_TLS_DEMAND = libldap.LDAP_OPT_X_TLS_DEMAND
LDAP_OPT_X_TLS_ALLOW = libldap.LDAP_OPT_X_TLS_ALLOW
LDAP_OPT_X_TLS_TRY = libldap.LDAP_OPT_X_TLS_TRY


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


def _retry_reconnect(func):
    def func_wrapper(lc, *args, **kwargs):
        retry_count = 0
        while True:
            try:
                return func(lc, *args, **kwargs)
                break
            except error.LDAPServerDownError:
                if retry_count >= lc._max_retry_reconnect:
                    raise

                retry_count += 1
                try:
                    lc._connect()
                except error.LDAPServerDownError:
                    pass


    return func_wrapper

def _retry_reconnect_generator(func):
    def generator_wrapper(lc, *args, **kwargs):
        retry_count = 0
        while True:
            try:
                g = func(lc, *args, **kwargs)
                for v in g:
                    yield v
                break
            except error.LDAPServerDownError:
                if retry_count >= lc._max_retry_reconnect:
                    raise

                retry_count += 1
                try:
                    lc._connect()
                except error.LDAPServerDownError:
                    pass
    return generator_wrapper

class LDAPConnection(object):
    """Connection to an LDAP server."""

    def __init__(self, uri, base, bind_dn, bind_password,
            cacertfile=None, require_cert=LDAP_OPT_X_TLS_NEVER,
            timelimit=30, max_retry_reconnect=5,
            schema_base="cn=subschema", enable_attribute_type_mapping=True,
            retrieve_operational_attributes=False):
        """
        :param uri: URI of the server to connect to.
        :param base: Base DN for LDAP operations.
        :param login: DN to bind with.
        :param password: Password to bind with.
        :param cacertfile: If using SSL/TLS this is certificate of the server
        :param timelimit: Defines the time limit after which a search
            operation should be terminated by the server
        :param schema_base: base DN for the schema description.
        :param enable_attribute_type_mapping: Whether to enable the mapping of LDAP attribute types
            to corresponding Python types. Requires the schema to be fetched when connecting. If
            disabled, all attributes will be treated as a multi-value string attribute.
        """
        self._base = base
        self._uri = uri
        self._bind_dn = bind_dn
        self._bind_password = bind_password
        self._cacertfile = cacertfile
        self._require_cert = require_cert
        self._max_retry_reconnect = max_retry_reconnect
        self._timelimit = timelimit
        self._schema_base = schema_base
        self._enable_attribute_type_mapping = enable_attribute_type_mapping

        self._connect()

    def _connect(self):
        ld_p = ffi.new("LDAP **")
        err = libldap.ldap_initialize(ld_p, compat._encode_utf8(self._uri))
        handle_ldap_error(err)
        self._ld = ld_p[0]

        version_p = ffi.new("int *")
        version_p[0] = libldap.LDAP_VERSION3
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_PROTOCOL_VERSION, version_p)

        if self._cacertfile is not None:
            libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_X_TLS_CACERTFILE,
                    compat._encode_utf8(self._cacertfile))

        require_cert_p = ffi.new("int *")
        require_cert_p[0] = self._require_cert
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_X_TLS_REQUIRE_CERT,
                require_cert_p);

        # For TLS options to take effect, a context refresh seems to be needed.
        newctx_p = ffi.new("int *")
        newctx_p[0] = 0
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_X_TLS_NEWCTX, newctx_p)

        timelimit_p = ffi.new("int *")
        timelimit_p[0] = self._timelimit
        libldap.ldap_set_option(self._ld, libldap.LDAP_OPT_TIMELIMIT, timelimit_p)

        err = libldap.ldap_simple_bind_s(self._ld,
                compat._encode_utf8(self._bind_dn),
                compat._encode_utf8(self._bind_password))
        handle_ldap_error(err)

        if self._enable_attribute_type_mapping:
            self._fetch_attribute_types()

    def _fetch_attribute_types(self):
        attribute_type_definitions = attribute.DEFAULT_ATTRIBUTE_TYPES
        result = list(
                self._raw_search(base=self._schema_base,
                    scope=libldap.LDAP_SCOPE_BASE,
                    search_filter="(objectClass=*)",
                    retrieve_attributes=["attributeTypes"]))
        # Decode the type definitions returned to strings
        attribute_type_definitions += map(compat._decode_utf8,
                result[0][1][compat._encode_utf8("attributeTypes")])

        self._attribute_types_by_name = attribute.build_attribute_types(
                attribute_type_definitions)

    def get_attribute_type(self, name):
        """Get the Python type to represent an attribute.

        :param name: The name of the attribute to look up the type for.
        :type name: str
        :rtype: a class object, a subclass of ``LDAPAttributeBase``.
        """
        if self._enable_attribute_type_mapping:
            if name in self._attribute_types_by_name:
                return self._attribute_types_by_name[name]
            else:
                raise error.LDAPAttributeNameNotFoundError(
                        'Attribute type "{}" not found.'.format(name))
        else:
            # Use a multi-value string attribute as the default
            base_classes = [attribute.MultiValueAttributeMixin,
                            attribute.BytesAttributeMixin,
                            attribute.LDAPAttributeBase]
            if sys.version_info[0] >= 3: # Python 3
                return type("LDAPAttribute", tuple(base_classes), {})
            else:
                return type(bytes("LDAPAttribute"), tuple(base_classes), {})

    @_retry_reconnect
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
            base=None, scope=libldap.LDAP_SCOPE_SUBTREE,
            retrieve_operational_attributes=False):
        """
        Raw wrapper around OpenLDAP ldap_search_ext_s.

        :param search_filter: Filter expression to use. OpenLDAP default used
            if None is given.
        :type search_filter: List of str
        :param retrieve_attributes: List of attributes to retrieve. If None is
            given, all user attributes are retrieved.
        :type retrieve_attributes: List of str
        :param base: Search base for the query.
        :type base: str
        :param scope: The search scope in the LDAP tree
        :param retrieve_operational_attributes: Retrieve operational attributes of entries in
            addition to user attributes if retrieve_attributes is not set.
        """
        search_result_p = ffi.new("LDAPMessage **")

        # Keep around references to pointers to owned memory with data that is
        # still needed.
        prevent_garbage_collection = []

        if retrieve_attributes is None:
            retrieve_attributes = [
                compat._decode_utf8(ffi.string(libldap.LDAP_ALL_USER_ATTRIBUTES))]
            if retrieve_operational_attributes:
                retrieve_attributes.append(
                    compat._decode_utf8(ffi.string(libldap.LDAP_ALL_OPERATIONAL_ATTRIBUTES)))

        attrs_p = ffi.new("char*[{}]".format(len(retrieve_attributes) + 1))
        for i, a in enumerate(retrieve_attributes):
            attr_p = ffi.new("char[]", compat._encode_utf8(a))
            prevent_garbage_collection.append(attr_p)
            attrs_p[i] = attr_p
        attrs_p[len(retrieve_attributes)] = ffi.NULL

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

                values_p = libldap.ldap_get_values_len(self._ld, current_entry,
                        current_attribute)
                for i in range(0, libldap.ldap_count_values_len(values_p)):
                    val = ffi.buffer(values_p[i].bv_val, values_p[i].bv_len)[:]
                    attribute_dict[current_attribute_str].append(val)

                libldap.ldap_memfree(current_attribute)
                current_attribute = libldap.ldap_next_attribute(self._ld,
                        current_entry, ber_p[0])
            libldap.ber_free(ber_p[0], 0)

            yield (dn, attribute_dict)
            current_entry = libldap.ldap_next_entry(self._ld, current_entry)

        libldap.ldap_msgfree(search_result)

    @_retry_reconnect_generator
    def search(self, *args, **kwargs):
        """Perform an LDAP search operation."""
        return self._search(*args, **kwargs)

    def _search(self, search_filter=None, retrieve_attributes=None,
            base=None, scope=libldap.LDAP_SCOPE_SUBTREE,
            retrieve_operational_attributes=False):
        """Search without retry_reconnect."""
        try:
            raw_search_result = self._raw_search(search_filter=search_filter,
                                                 retrieve_attributes=retrieve_attributes,
                                                 base=base,scope=scope,
                                                 retrieve_operational_attributes=retrieve_operational_attributes)
            for dn, attributes_dict in raw_search_result:
                entry = LDAPEntry(self, compat._decode_utf8(dn),
                                  retrieve_attributes=retrieve_attributes,
                                  retrieve_operational_attributes=retrieve_operational_attributes)
                entry._attributes = set()
                for name, value in attributes_dict.items():
                    # TODO: Create the right type of LDAPAttribute here
                    attribute_type = self.get_attribute_type(
                            compat._decode_utf8(name))
                    attribute = attribute_type(compat._decode_utf8(name))
                    attribute._set_ldap_values(value)
                    entry._attributes.add(attribute)
                entry._fetched_attributes = copy.deepcopy(entry._attributes)
                yield entry
        except error.LDAPNoSuchObjectError:
            # If the search returned without results, "return" an empty generator.
            return

    def get_entry(self, *args, **kwargs):
        """Get an LDAPEntry object associated with this connection."""
        return LDAPEntry(self, *args, **kwargs)

    @_retry_reconnect
    def delete(self, entry, recursive=False):
        """Delete an entry on the LDAP server.

        :param entry: The entry to delete.
        :type entry: ldapom.LDAPEntry
        :param recursive: If subentries should be deleted recursively.
        :type recursive: bool
        """
        if recursive:
            entries_to_delete = self._connection._search(
                    base=entry.dn,
                    scope=LDAP_SCOPE_ONELEVEL)
            for entry in entries_to_delete:
                entry.delete(recursive=True)
        err = libldap.ldap_delete_s(self._ld,
                compat._encode_utf8(entry.dn))
        handle_ldap_error(err)

    @_retry_reconnect
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

    @_retry_reconnect
    def exists(self, entry):
        """Checks if a the given entry exists on the LDAP server.

        :param entry: The entry to check the existence of.
        :type entry: ldapom.LDAPEntry
        """
        entry_search_result = list(self._search(
            base=entry.dn, scope=LDAP_SCOPE_BASE))
        return len(entry_search_result) == 1

    @_retry_reconnect
    def save(self, entry):
        """Save the given entry and its attribute values to the LDAP server.

        :param entry: The entry to save.
        :type entry: ldapom.LDAPEntry
        """
        entry_exists = entry.exists()
        # Refuse to save if attributes have not been fetched or set explicitly.
        if entry._attributes is None:
            raise error.LDAPomError("Cannot save without attributes "
                    "previously fetched or set.")

        if entry_exists:
            assert entry._fetched_attributes is not None
            changed_attributes = entry._attributes - entry._fetched_attributes
            # Deleted attributes are represented as empty attributes to the LDAP server.
            deleted_attribute_names = (frozenset(a.name for a in entry._fetched_attributes)
                    - frozenset(a.name for a in entry._attributes))
            for deleted_name in deleted_attribute_names:
                deleted_attribute_type = self.get_attribute_type(deleted_name)
                changed_attributes.add(deleted_attribute_type(deleted_name))
        else:
            # Don't try to save empty attributes as this fails if the entry does
            # not exist on the server yet.
            changed_attributes = set(filter(lambda attr: len(attr._values) > 0, entry._attributes))

        # Don't try to save an empty modification set
        if not changed_attributes:
            return

        # Keep around references to pointers to owned memory with data that is
        # still needed.
        prevent_garbage_collection = []

        mods = ffi.new("LDAPMod*[{}]".format(len(changed_attributes) + 1))
        for i, attribute in enumerate(changed_attributes):
            mod = ffi.new("LDAPMod *")
            prevent_garbage_collection.append(mod)

            mod.mod_op = libldap.LDAP_MOD_REPLACE | libldap.LDAP_MOD_BVALUES

            mod_type = ffi.new("char[]", compat._encode_utf8(attribute.name))
            prevent_garbage_collection.append(mod_type)
            mod.mod_type = mod_type

            modv_bvals = ffi.new("BerValue*[{}]".format(len(attribute._values) + 1))
            prevent_garbage_collection.append(modv_bvals)
            for j, value in enumerate(attribute._get_ldap_values()):
                modv_berval = ffi.new("BerValue *")
                prevent_garbage_collection.append(modv_berval)
                modv_berval.bv_len = len(value)
                bval = ffi.new("char[]", len(value))
                prevent_garbage_collection.append(bval)
                ffi.buffer(bval)[:] = value
                modv_berval.bv_val = bval
                modv_bvals[j] = modv_berval
            modv_bvals[len(attribute._values)] = ffi.NULL
            mod.mod_vals = {"modv_bvals": modv_bvals}
            mods[i] = mod
        mods[len(changed_attributes)] = ffi.NULL

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

        entry._fetched_attributes = copy.deepcopy(entry._attributes)

    @_retry_reconnect
    def fetch(self, entry, *args, **kwargs):
        """Fetch an entry's attributes from the LDAP server.

        :param entry: The entry to fetch.
        :type entry: ldapom.LDAPEntry
        """
        try:
            fetched_entry = next(self._search(*args, base=entry.dn,
                scope=libldap.LDAP_SCOPE_BASE, **kwargs))
            entry._attributes = fetched_entry._attributes
            entry._fetched_attributes = copy.deepcopy(entry._attributes)
        except StopIteration:
            raise error.LDAPNoSuchObjectError()

    @_retry_reconnect
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

# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import sys

from cffi import FFI

ffi = FFI()

ffi.cdef("typedef ... LDAP;")
ffi.cdef("typedef ... LDAPMessage;")
ffi.cdef("typedef ... LDAPControl;")
ffi.cdef("typedef ... BerElement;")

ffi.cdef("""
typedef struct ldapmod {
    int mod_op;
    char *mod_type;
    union {
        char **modv_strvals;
    //    struct berval **modv_bvals;
    } mod_vals;
} LDAPMod;
""")

ffi.cdef("""
#define LDAP_VERSION3 ...
#define LDAP_OPT_PROTOCOL_VERSION ...
#define LDAP_OPT_X_TLS_REQUIRE_CERT ...
#define LDAP_OPT_X_TLS_CACERTFILE ...
#define LDAP_OPT_X_TLS_NEWCTX ...
#define LDAP_OPT_X_TLS_NEVER ...
#define LDAP_OPT_TIMELIMIT ...
#define LDAP_NO_LIMIT ...
#define LDAP_MOD_ADD ...
#define LDAP_MOD_DELETE ...
#define LDAP_MOD_REPLACE ...
#define LDAP_SCOPE_BASE ...
#define LDAP_SCOPE_ONELEVEL ...
#define LDAP_SCOPE_SUBTREE ...
#define LDAP_SUCCESS ...
""")

ffi.cdef("int ldap_initialize(LDAP **ldp, char *uri);")
ffi.cdef("int ldap_set_option(LDAP *ld, int option, const void *invalue);")
ffi.cdef("int ldap_simple_bind_s(LDAP *ld, const char *who, const char *passwd);")
ffi.cdef("""int ldap_search_ext_s(
       LDAP *ld,
       char *base,
       int scope,
       char *filter,
       char *attrs[],
       int attrsonly,
       LDAPControl **serverctrls,
       LDAPControl **clientctrls,
       struct timeval *timeout,
       int sizelimit,
       LDAPMessage **res);""")

# From ldap_next_entry(3)
ffi.cdef("""
int ldap_count_entries( LDAP *ld, LDAPMessage *result );
LDAPMessage *ldap_first_entry( LDAP *ld, LDAPMessage *result );
LDAPMessage *ldap_next_entry( LDAP *ld, LDAPMessage *entry );
""")

# From ldap_get_values(3)
ffi.cdef("""
char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *attr);
int ldap_count_values(char **vals);
""")

# From ldap_get_dn(3)
ffi.cdef("""
char *ldap_get_dn( LDAP *ld, LDAPMessage *entry );
""")

# From ldap_first_attribute(3)
ffi.cdef("""
char *ldap_first_attribute( LDAP *ld, LDAPMessage *entry, BerElement **berptr );
char *ldap_next_attribute( LDAP *ld, LDAPMessage *entry, BerElement *ber );
""")

# From ldap_add_ext(3)
ffi.cdef("""
int ldap_add_ext_s(
       LDAP *ld,
       const char *dn,
       LDAPMod **attrs,
       LDAPControl **sctrls,
       LDAPControl **cctrls );
""")

# From ldap_err2string(3)
ffi.cdef("""
char *ldap_err2string( int err );
""" )

ldap = ffi.verify(
"""
#define LDAP_DEPRECATED 1
#include <ldap.h>
#include <lber.h>
""", libraries=[str("ldap"), str("lber")])


def _encode_utf8(unicode_string):
  if sys.version_info[0] >= 3: # Python 3
      return bytes(unicode_string, 'utf-8')
  else:
      return unicode_string.encode('utf-8')

def _decode_utf8(bytes_obj):
  if sys.version_info[0] >= 3: # Python 3
      return str(bytes_obj, 'utf-8')
  else:
      return unicode(bytes_obj, 'utf-8')

if sys.version_info[0] >= 3: # Python 3
    unicode = str

class LDAPError(Exception):
    pass

class LDAPInvalidCredentialsError(LDAPError):
    pass

class UnicodeMixin(object):
  """Mixin class to handle defining the proper __str__/__unicode__
  methods in Python 2 or 3."""

  if sys.version_info[0] >= 3: # Python 3
      def __str__(self):
          return self.__unicode__()
  else:  # Python 2
      def __str__(self):
          return self.__unicode__().encode('utf8')


def handle_ldap_error(err):
    """Given an LDAP error code, raise an error if needed.

    :param err: The error code returned by the library.
    :type err: int
    """
    if err != ldap.LDAP_SUCCESS:
        raise LDAPError(ldap.ldap_err2string(err))


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
        err = ldap.ldap_initialize(ld_p, _encode_utf8(uri))
        handle_ldap_error(err)
        self._ld = ld_p[0]

        version_p = ffi.new("int *")
        version_p[0] = ldap.LDAP_VERSION3
        ldap.ldap_set_option(self._ld, ldap.LDAP_OPT_PROTOCOL_VERSION, version_p)

        if cacertfile:
            require_cert_p = ffi.new("int *")
            require_cert_p[0] = ldap.LDAP_OPT_X_TLS_NEVER
            ldap.ldap_set_option(self._ld, ldap.LDAP_OPT_X_TLS_REQUIRE_CERT,
                    require_cert_p);

            ldap.ldap_set_option(self._ld, ldap.LDAP_OPT_X_TLS_CACERTFILE,
                    _encode_utf8(cacertfile))

        # For TLS options to take effect, a context refresh seems to be needed.
        newctx_p = ffi.new("int *")
        newctx_p[0] = 0
        ldap.ldap_set_option(self._ld, ldap.LDAP_OPT_X_TLS_NEWCTX, newctx_p)

        timelimit_p = ffi.new("int *")
        timelimit_p[0] = timelimit
        ldap.ldap_set_option(self._ld, ldap.LDAP_OPT_TIMELIMIT, timelimit_p)

        err = ldap.ldap_simple_bind_s(self._ld,
                _encode_utf8(bind_dn),
                _encode_utf8(bind_password))
        if err != ldap.LDAP_SUCCESS:
            raise LDAPInvalidCredentialsError()

    def authenticate(self, bind_dn, bind_password):
        """Try to authenticate with the given credentials.

        :param bind_dn: DN to bind with.
        :type bind_dn: str
        :param bind_password: Password to bind with.
        :type bind_password: str
        :rtype boolean
        """
        try:
            self.__class__(self._uri, self._base, bind_dn, bind_password,
                    self._cacertfile)
        except LDAPInvalidCredentialsError:
            return False
        return True

    def _raw_search(self, search_filter=None, retrieve_attributes=None,
            base=None, scope=ldap.LDAP_SCOPE_SUBTREE):
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
        err = ldap.ldap_search_ext_s(
                self._ld,
                _encode_utf8(base or self._base),
                scope,
                search_filter or ffi.NULL,
                retrieve_attributes or ffi.NULL,
                0,
                ffi.NULL, ffi.NULL,
                ffi.NULL, # TODO: Implement timeouts
                0,#ldap.LDAP_NO_LIMIT,
                search_result_p)
        handle_ldap_error(err)
        search_result = search_result_p[0]

        current_entry = ldap.ldap_first_entry(self._ld, search_result)
        while current_entry != ffi.NULL:
            dn = ffi.string(ldap.ldap_get_dn(self._ld, current_entry))
            attribute_dict = {}

            ber_p = ffi.new("BerElement **")
            current_attribute = ldap.ldap_first_attribute(self._ld,
                    current_entry, ber_p)
            while current_attribute != ffi.NULL:
                current_attribute_str = ffi.string(current_attribute)
                attribute_dict[current_attribute_str] = []

                values_p = ldap.ldap_get_values(self._ld, current_entry,
                        current_attribute)
                for i in range(0, ldap.ldap_count_values(values_p)):
                    attribute_dict[current_attribute_str].append(
                            ffi.string(values_p[i]))

                current_attribute = ldap.ldap_next_attribute(self._ld,
                        current_entry, ber_p[0])
            # TODO: Call ber_free on ber_p[0]

            yield (dn, attribute_dict)
            current_entry = ldap.ldap_next_entry(self._ld, current_entry)
            # TODO: Call ldap_msgfree on search_result

    def search(self, *args, **kwargs):
        """Perform an LDAP search operation.

        :rtype: List of LDAPEntry.
        """
        for dn, attributes_dict in self._raw_search(*args, **kwargs):
            attributes = []
            for name, value in attributes_dict.items():
                # TODO: Create the right type of LDAPAttribute here
                attributes.append(LDAPAttribute(_decode_utf8(name), value))
            entry = LDAPEntry(self, dn, attributes=attributes)
            yield entry


class LDAPAttribute(UnicodeMixin, object):
    """Holds an LDAP attribute and its values."""

    def __init__(self, name, value=None):
        """Creates a new attribute.

        :param name: The name for the attribute.
        :param name: str
        :param value: An iterable or single value to initialize the set of
            values with.
        """
        self.name = name
        self.value = value or []
        # List of "old" values to calculate changes from later.
        self._old_values = set(self._values) or set()

    def __len__(self):
        return len(self._values)

    def __unicode__(self):
        if len(self._values) == 1:
            values = unicode(next(iter(self._values)))
        else:
            values = unicode(", ".join(map(unicode, self._values)))

        return "{name}: {values}".format(name=self.name, values=values)

    __repr__ = lambda self: self.__str__()

    def add(self, value):
        """Add an attribute value.

        :param value: The value to append.
        :type value: str
        """
        self._values.add(value)

    def remove(self, value):
        """Remove an attribute value.

        :param value: The value to be removed.
        """
        self._values.remove(value)

    def __contains__(self, value):
        """Check if a value is in the list of values.

        :rtype: bool
        """
        return value in self._values

    def __iter__(self):
        return iter(self._values)

    def _get_value(self):
        if len(self._values) == 1:
            return next(iter(self._values))
        else:
            return frozenset(self._values)

    def _set_value(self, value):
        if isinstance(value, set) or isinstance(value, list):
            self._values = set(value)
        else:
            self._values = set([value])

    values = property(_get_value, _set_value)
    value = property(_get_value, _set_value)

    def _get_has_changes(self):
        return self._old_values != self._values

    def _set_has_changes(self, value):
        if value:
            self._old_values = None
        else:
            self._old_values = self._values.copy()

    has_changes = property(_get_has_changes, _set_has_changes)


class LDAPEntry(UnicodeMixin, object):
    """Lazy-loading LDAP entry object."""

    def __init__(self, connection, dn, attributes=None):
        """Creates a lazy entry object by dn.

        :param connection: The connection to use for this node.
        :type connection: LdapConnection
        :param dn: The DN for this node.
        :type dn: str
        :param attributes: An iterable of attributes for this node.
        """
        self._connection = connection
        self._dn = dn
        self.attributes = set(attributes) if attributes is not None else None
        self._old_attribute_names = set([a.name for a in attributes]) \
                if attributes else None

    ## Expose dn as a ready-only property
    dn = property(lambda self: self._dn)

    def get_parent(self):
        """Get the parent entry in the LDAP tree."""
        parent_dn = self.dn.split(',')[1:]
        return LDAPEntry(self._connection, parent_dn)

    def fetch(self):
        """Fetch the node's attributes from the LDAP server."""
        entry = next(self._connection.search(base=self.dn,
                scope=ldap.LDAP_SCOPE_ONELEVEL))
        self.attributes = entry.attributes
        self._old_attribute_names = set([a.name for a in self.attributes])

    def save(self):
        """Save the node and its attribute values to the LDAP server."""
        # Temporary attribute set that will contain deleted attributes as
        # LDAPAttribute objects without any values.
        save_attributes = self._attributes.copy()
        deleted_attribute_names = self._old_attribute_names.difference(
                [a.name for a in self.attributes])
        for name in deleted_attribute_names:
            save_attributes.add(LDAPAttribute(name, []))

        mods_p = ffi.new("LDAPMod*[{}]".format(len(save_attributes + 1)))
        for i, attribute in enumerate(save_attributes):
            mod = mods_p[i]

            # LDAP_MOD_REPLACE creates the attribute if needed
            mod.mod_op = ldap.LDAP_MOD_REPLACE
            mod.mod_type = _encode_utf8(attribute.name)
            mod.mod_next = ffi.NULL

            mod_vals = ffi.new("char*[{}]".format(len(attribute.values) + 1))
            for j, value in enumerate(attribute.values):
                mod_vals[j] = _encode_utf8(value)
            mod_vals[len(attribute.values)] = ffi.NULL

        mods_p[len(save_attributes)] = ffi.NULL

        if self.exists():
            err = ldap.ldap_modify_ext_s(self._connection._ld,
                    self.dn,
                    mods_p,
                    ffi.NULL, ffi.NULL)
        else:
            err = ldap.ldap_add_ext_s(self._connection._ld,
                    self.dn,
                    mods_p,
                    ffi.NULL, ffi.NULL)
        handle_ldap_error(err)

        self._old_attribute_names = set([a.name for a in self.attributes])

    def exists(self):
        """Checks if a node with this DN exists on the LDAP server."""
        self_search_result = list(self._connection.search(
            base=self.dn, scope=ldap.LDAP_SCOPE_BASE))
        return len(self_search_result) == 1

    def __getattr__(self, name):
        """Get an attribute or query object class membership"""
        if self.attributes is None:
            self.fetch()
        if name.startswith("is_"):
            return name[3:] in self["objectClass"]
        if name in [attribute.name for attribute in self.attributes]:
            return [a for a in self.attributes if a.name == name]
        raise AttributeError()

    def __setattr__(self, name, value):
        """Set an attribute value"""
        try:
            super(LDAPEntry, self).__setattr__(name, value)
            return
        except AttributeError:
            pass

        if self.attributes is None:
            self.fetch()
        try:
            self[name].value = value
        except AttributeError:
            self.attributes.add = LDAPAttribute(name, value)

    def __delattr__(self, name):
        if self.attributes is None:
            self.fetch()
        attribute = self[name]
        self.attributes.remove(attribute)

    def __unicode__(self):
        return self.dn

    def __repr__(self):
        return self.__str__()

    def delete(self, recursive=False):
        """Delete this entry on the LDAP server.

        :param recursive: If subentries should be deleted recursively.
        :type recursive: bool"""
        if recursive:
            entries_to_delete = self._connection.search(
                    base=self.dn, scope=ldap.LDAP_SCOPE_ONELEVEL)
            for entry in entries_to_delete:
                entry.delete(recursive=True)
        ldap.ldap_delete_ext_s(self._connection._ld,
                _encode_utf8(self.dn))

    def set_password(self, password):
        """Change the password for this LDAP entry.

        :param password: The password to set
        :type password: str
        """
        raise NotImplementedError()

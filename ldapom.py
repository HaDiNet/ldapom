# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function

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
#define LDAP_NO_SUCH_OBJECT ...
#define LDAP_INVALID_CREDENTIALS ...
#define LDAP_SERVER_DOWN ...
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

# From ldap_modify_ext(3)
ffi.cdef("""
int ldap_modify_ext_s(
              LDAP *ld,
              char *dn,
              LDAPMod *mods[],
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


class LDAPomError(Exception):
    pass

class LDAPError(LDAPomError):
    pass

class LDAPNoSuchObjectError(LDAPError):
    pass

class LDAPInvalidCredentialsError(LDAPError):
    pass

class LDAPServerDownError(LDAPError):
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
    if err == ldap.LDAP_SUCCESS:
        return

    error_string = _decode_utf8(ffi.string(ldap.ldap_err2string(err)))
    if err == ldap.LDAP_NO_SUCH_OBJECT:
        raise LDAPNoSuchObjectError(error_string)
    elif err == ldap.LDAP_INVALID_CREDENTIALS:
        raise LDAPInvalidCredentialsError(error_string)
    elif err == ldap.LDAP_SERVER_DOWN:
        raise LDAPServerDownError(error_string)
    else:
        raise LDAPError(error_string)


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
        handle_ldap_error(err)

    def can_bind(self, bind_dn, bind_password):
        """Try to bind with the given credentials.

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
        try:
            for dn, attributes_dict in self._raw_search(*args, **kwargs):
                entry = LDAPEntry(self, dn, attributes=set())
                for name, value in attributes_dict.items():
                    # TODO: Create the right type of LDAPAttribute here
                    entry.attributes.add(LDAPAttribute(_decode_utf8(name),
                        values_from_ldap=value))
                yield entry
        except LDAPNoSuchObjectError:
            # If the search returned without results, "return" an empty list.
            return

    def get_entry(self, *args, **kwargs):
        """Get an LDAPEntry object associated with this connection."""
        return LDAPEntry(self, *args, **kwargs)



class LDAPAttribute(UnicodeMixin, object):
    """Holds an LDAP attribute and its values."""

    def __init__(self, name, values_from_ldap=None):
        """Creates a new attribute.

        :param name: The name for the attribute.
        :param name: str
        :param value: An iterable or single value to initialize the set of
            values with.
        """
        self.name = name
        self._values = (self._convert_values_from_ldap(values_from_ldap)
                if values_from_ldap else [])
        # List of "old" values to calculate changes from later.
        self._old_values = set(self._values) or set()

    @staticmethod
    def _convert_values_from_ldap(values_from_ldap):
        return [_decode_utf8(v) for v in values_from_ldap]

    def __len__(self):
        return len(self._values)

    def __unicode__(self):
        if len(self._values) == 1:
            values = unicode(next(iter(self._values)))
        else:
            values = unicode(", ".join(map(unicode, self._values)))

        return "{name}: {values}".format(name=self.name, values=values)

    def __repr__(self):
        return "<LDAPAttribute " + self.__str__() + ">"

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

    def _get_values(self):
        return frozenset(self._values)

    def _set_values(self, values):
        self._values = set(values)

    values = property(_get_values, _set_values)

    def _get_value(self):
        if len(self._values) > 1:
            raise AttributeError("Attribute has more than one value")
        elif len(self._values) == 0:
            return None
        else:
            return self._values[0]

    def _set_value(self, value):
        if value is None:
            self._values = []
        else:
            self._values = [value]

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
        # Use super() method because __setattr__ is overridden.
        super(LDAPEntry, self).__setattr__('_connection', connection)
        super(LDAPEntry, self).__setattr__('_dn', dn)
        super(LDAPEntry, self).__setattr__('attributes', set(attributes)
                if attributes is not None else None)
        super(LDAPEntry, self).__setattr__('_old_attribute_names',
                set([a.name for a in attributes]) if attributes else None)

    ## Expose dn as a ready-only property
    dn = property(lambda self: self._dn)

    def get_parent(self):
        """Get the parent entry in the LDAP tree."""
        parent_dn = self.dn.split(',')[1:]
        return LDAPEntry(self._connection, parent_dn)

    def fetch(self):
        """Fetch the node's attributes from the LDAP server."""
        try:
            entry = next(self._connection.search(base=self.dn,
                    scope=ldap.LDAP_SCOPE_BASE))
            self.attributes = entry.attributes
            self._old_attribute_names = set([a.name for a in self.attributes])
        except StopIteration:
            self.attributes = set([])
            self._old_attribute_names = set([])

    def save(self):
        """Save the node and its attribute values to the LDAP server."""
        # Refuse to save if attributes have not been fetched or set explicitly.
        if self.attributes is None:
            raise LDAPomError("Cannot save without attributes previously "
                    "fetched or set.")

        # Temporary attribute set that will contain deleted attributes as
        # LDAPAttribute objects without any values.
        save_attributes = self.attributes.copy()
        deleted_attribute_names = self._old_attribute_names.difference(
                [a.name for a in self.attributes])
        for name in deleted_attribute_names:
            save_attributes.add(LDAPAttribute(name))

        # Keep around references to pointers to owned memory with data that is
        # still needed.
        prevent_garbage_collection = []

        mods = ffi.new("LDAPMod*[{}]".format(len(save_attributes) + 1))
        for i, attribute in enumerate(save_attributes):
            mod = ffi.new("LDAPMod *")
            prevent_garbage_collection.append(mod)

            mod.mod_op = ldap.LDAP_MOD_REPLACE

            mod_type = ffi.new("char[]", _encode_utf8(attribute.name))
            prevent_garbage_collection.append(mod_type)
            mod.mod_type = mod_type

            modv_strvals = ffi.new("char*[{}]".format(len(attribute.values) + 1))
            prevent_garbage_collection.append(modv_strvals)
            for j, value in enumerate(attribute.values):
                strval = ffi.new("char[]", _encode_utf8(value))
                prevent_garbage_collection.append(strval)
                modv_strvals[j] = strval
            modv_strvals[len(attribute.values)] = ffi.NULL
            mod.mod_vals = {"modv_strvals": modv_strvals}

            mods[i] = mod
        mods[len(save_attributes)] = ffi.NULL

        if self.exists():
            err = ldap.ldap_modify_ext_s(self._connection._ld,
                    _encode_utf8(self.dn),
                    mods,
                    ffi.NULL, ffi.NULL)
        else:
            err = ldap.ldap_add_ext_s(self._connection._ld,
                    _encode_utf8(self.dn),
                    mods,
                    ffi.NULL, ffi.NULL)
        handle_ldap_error(err)

        self._old_attribute_names = set([a.name for a in self.attributes])

    def exists(self):
        """Checks if a node with this DN exists on the LDAP server."""
        self_search_result = list(self._connection.search(
            base=self.dn, scope=ldap.LDAP_SCOPE_BASE))
        return len(self_search_result) == 1

    def get_attribute(self, name):
        """Get a named attribute object from the internal set of attributes.

        :param name: The name of the attribute to get.
        :type name: str
        :rtype: LDAPAttribute object or None
        """
        try:
            return [a for a in self.attributes if a.name == name][0]
        except IndexError:
            return None

    def __getattr__(self, name):
        """Get an attribute or query object class membership"""
        if self.attributes is None:
            self.fetch()

        if name.startswith("is_"):
            return name[3:] in self.get_attribute("objectClass").values

        attribute = self.get_attribute(name)
        if attribute is not None:
            # TODO: Replace this with a check for is_single_value
            if len(attribute.values) == 1:
                return attribute.value
            else:
                return attribute.values
        raise AttributeError()

    def __setattr__(self, name, value):
        """Set an attribute value"""
        # Use normal behaviour if setting an existing instance attribute.
        if name in self.__dict__:
            super(LDAPEntry, self).__setattr__(name, value)
            return

        if self.attributes is None:
            self.fetch()

        # Try to get existing attribute from list, if not found
        # create a new once.
        attribute = self.get_attribute(name)
        if attribute is None:
            attribute = LDAPAttribute(name)
            self.attributes.add(attribute)

        if isinstance(value, list) or isinstance(value, set):
            attribute.values = value
        else:
            attribute.value = value

    def __delattr__(self, name):
        if self.attributes is None:
            self.fetch()
        attribute = self.get_attribute(name)
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

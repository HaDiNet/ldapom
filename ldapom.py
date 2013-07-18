# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function

import sys
import re

from cffi import FFI

ffi = FFI()

# Type definitions
ffi.cdef("""
typedef ... LDAP;
typedef ... LDAPMessage;
typedef ... LDAPControl;
typedef ... BerElement;

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

# Function declarations
ffi.cdef("""
int ldap_initialize(LDAP **ldp, char *uri);
int ldap_set_option(LDAP *ld, int option, const void *invalue);
int ldap_simple_bind_s(LDAP *ld, const char *who, const char *passwd);
int ldap_search_ext_s(
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
       LDAPMessage **res);

// From ldap_next_entry(3)
int ldap_count_entries( LDAP *ld, LDAPMessage *result );
LDAPMessage *ldap_first_entry( LDAP *ld, LDAPMessage *result );
LDAPMessage *ldap_next_entry( LDAP *ld, LDAPMessage *entry );

// From ldap_get_values(3)
char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *attr);
int ldap_count_values(char **vals);

// From ldap_get_dn(3)
char *ldap_get_dn( LDAP *ld, LDAPMessage *entry );

// From ldap_first_attribute(3)
char *ldap_first_attribute( LDAP *ld, LDAPMessage *entry, BerElement **berptr );
char *ldap_next_attribute( LDAP *ld, LDAPMessage *entry, BerElement *ber );

// From ldap_add_ext(3)
int ldap_add_ext_s(
       LDAP *ld,
       const char *dn,
       LDAPMod **attrs,
       LDAPControl **sctrls,
       LDAPControl **cctrls );

// From ldap_modify_ext(3)
int ldap_modify_ext_s(
              LDAP *ld,
              char *dn,
              LDAPMod *mods[],
              LDAPControl **sctrls,
              LDAPControl **cctrls );

// From ldap_delete_s(3)
int ldap_delete_s(LDAP *ld, char *dn);

// From ldap_err2string(3)
char *ldap_err2string( int err );

// From ldap_msgfree(3)
int ldap_msgfree( LDAPMessage *msg );
""")

ldap = ffi.verify(
"""
// Required for ldap_bind_simple
#define LDAP_DEPRECATED 1

#include <ldap.h>
#include <lber.h>
""", libraries=[str("ldap"), str("lber")])


OID_REGEX = re.compile(r"\( ([0-9\.]+) .* \)")
SINGLE_VALUE_REGEX = re.compile(r"\(.* SINGLE-VALUE .*\)")
ONE_NAME_REGEX = re.compile(r"\(.* NAME \'([^']+)\' .*\)")
MULTIPLE_NAMES_REGEX = re.compile(r"\(.* NAME \( ([^)]+) \) .*\)")
SYNTAX_REGEX = re.compile(r"\(.* SYNTAX ([0-9\.]+)({\d+})? .*\)")
DESC_REGEX = re.compile(r"\(.* DESC \'([^']+)\' .*\)")
SUP_REGEX = re.compile(r"\(.* SUP (\w+) .*\)")



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


class SingleValueAttributeMixin(object):
    single_value = True

    def _get_value(self):
        if len(self._values) == 0:
            return None
        else:
            return next(iter(self._values))

    def _set_value(self, value):
        if value is None:
            self._values = set()
        else:
            self._values = set([value])

    value = property(_get_value, _set_value)


class MultiValueAttributeMixin(object):
    single_value = False

    def _get_values(self):
        return self._values

    def _set_values(self, values):
        self._values = set(values)

    values = property(_get_values, _set_values)


class LDAPAttributeBase(UnicodeMixin, object):
    """Holds an LDAP attribute and its values."""

    def __init__(self, name):
        """Creates a new attribute.

        :param name: The name for the attribute.
        :param name: str
        """
        self.name = name
        self._values = set()

    def __unicode__(self):
        if len(self._values) == 1:
            values_string = unicode(next(iter(self._values)))
        else:
            values_string = unicode(", ".join(map(unicode, self._values)))
        return "{name}: {values}".format(name=self.name, values=values_string)

    def __repr__(self):
        return "<LDAPAttribute " + self.__str__() + ">"


class UnicodeAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set([_decode_utf8(v) for v in values])

    def _get_ldap_values(self):
        return set([_encode_utf8(v) for v in self._values])


class BooleanAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set([(_decode_utf8(v) == "TRUE") for v in values])

    def _get_ldap_values(self):
        string_values = ["TRUE" if v else "FALSE" for v in self._values]
        return set([_encode_utf8(v) for v in string_values])


class IntegerAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set([int(_decode_utf8(v)) for v in values])

    def _get_ldap_values(self):
        return set([_encode_utf8(unicode(v)) for v in self._values])


class BytesAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set(values)

    def _get_ldap_values(self):
        return set(self._values)

ATTRIBUTE_SYNTAX_TO_TYPE_MIXIN = {
        '1.3.6.1.1.1.0.0':               BytesAttributeMixin,     # RFC2307 NIS Netgroup Triple
        '1.3.6.1.1.1.0.1':               UnicodeAttributeMixin, # RFC2307 Boot Parameter
        '1.3.6.1.1.16.1':                UnicodeAttributeMixin, # UUID
        '1.3.6.1.4.1.1466.115.121.1.3':  UnicodeAttributeMixin, # Attribute Type Description
        '1.3.6.1.4.1.1466.115.121.1.4':  BytesAttributeMixin,     # Audio
        '1.3.6.1.4.1.1466.115.121.1.5':  BytesAttributeMixin,     # Binary
        '1.3.6.1.4.1.1466.115.121.1.6':  BytesAttributeMixin,     # Bit String
        '1.3.6.1.4.1.1466.115.121.1.7':  BooleanAttributeMixin,    # Boolean
        '1.3.6.1.4.1.1466.115.121.1.8':  BytesAttributeMixin,     # Certificate
        '1.3.6.1.4.1.1466.115.121.1.9':  BytesAttributeMixin,     # Certificate List
        '1.3.6.1.4.1.1466.115.121.1.10': BytesAttributeMixin,     # Certificate Pair
        '1.3.6.1.4.1.1466.115.121.1.11': UnicodeAttributeMixin, # CountryString
        '1.3.6.1.4.1.1466.115.121.1.12': UnicodeAttributeMixin, # Distinguished Name
        '1.3.6.1.4.1.1466.115.121.1.13': UnicodeAttributeMixin, # Data Quality Syntax
        '1.3.6.1.4.1.1466.115.121.1.14': UnicodeAttributeMixin, # Delivery Method
        '1.3.6.1.4.1.1466.115.121.1.15': UnicodeAttributeMixin, # DirectoryString
        '1.3.6.1.4.1.1466.115.121.1.19': UnicodeAttributeMixin, # DSA Quality Syntax
        '1.3.6.1.4.1.1466.115.121.1.21': UnicodeAttributeMixin, # Enhanced Guide
        '1.3.6.1.4.1.1466.115.121.1.22': UnicodeAttributeMixin, # Facsimile Telephone Number
        '1.3.6.1.4.1.1466.115.121.1.23': BytesAttributeMixin,     # Fax Image Syntax
        '1.3.6.1.4.1.1466.115.121.1.24': UnicodeAttributeMixin, # GeneralizedTime
        '1.3.6.1.4.1.1466.115.121.1.25': UnicodeAttributeMixin, # Guide (Obsolete)
        '1.3.6.1.4.1.1466.115.121.1.26': UnicodeAttributeMixin, # IA5String
        '1.3.6.1.4.1.1466.115.121.1.27': IntegerAttributeMixin,     # Integer
        '1.3.6.1.4.1.1466.115.121.1.28': BytesAttributeMixin,     # JPEG
        '1.3.6.1.4.1.1466.115.121.1.30': UnicodeAttributeMixin, # Matching Rule Description syntax
        '1.3.6.1.4.1.1466.115.121.1.31': UnicodeAttributeMixin, # Matching Rule Use Description syntax
        '1.3.6.1.4.1.1466.115.121.1.34': UnicodeAttributeMixin, # Name And Optional UID
        '1.3.6.1.4.1.1466.115.121.1.36': UnicodeAttributeMixin, # NumericString
        '1.3.6.1.4.1.1466.115.121.1.37': UnicodeAttributeMixin, # Object Class Description syntax
        '1.3.6.1.4.1.1466.115.121.1.38': UnicodeAttributeMixin, # OID
        '1.3.6.1.4.1.1466.115.121.1.39': UnicodeAttributeMixin, # Other Mailbox
        '1.3.6.1.4.1.1466.115.121.1.40': BytesAttributeMixin,     # OctetString
        '1.3.6.1.4.1.1466.115.121.1.41': UnicodeAttributeMixin, # PostalAddress
        '1.3.6.1.4.1.1466.115.121.1.42': UnicodeAttributeMixin, # protocolInformation
        '1.3.6.1.4.1.1466.115.121.1.43': UnicodeAttributeMixin, # Presentation Address syntax
        '1.3.6.1.4.1.1466.115.121.1.44': UnicodeAttributeMixin, # PrintableString
        '1.3.6.1.4.1.1466.115.121.1.49': BytesAttributeMixin,     # Supported Algorithm
        '1.3.6.1.4.1.1466.115.121.1.50': UnicodeAttributeMixin, # TelephoneNumber
        '1.3.6.1.4.1.1466.115.121.1.51': UnicodeAttributeMixin, # Teletex Terminal Identifier
        '1.3.6.1.4.1.1466.115.121.1.52': UnicodeAttributeMixin, # Telex Number
        '1.3.6.1.4.1.1466.115.121.1.54': UnicodeAttributeMixin, # LDAP Syntax Description
        '1.3.6.1.4.1.4203.666.2.7':      BytesAttributeMixin,     # OpenLDAP authz
        }


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

        self._fetch_attribute_types()

    def _fetch_attribute_types(self):
        result = list(
                self._raw_search(base="cn=subschema",
                    scope=ldap.LDAP_SCOPE_BASE,
                    search_filter="(objectClass=*)",
                    retrieve_attributes=["attributeTypes"]))
        # Decode the type definitions returned to strings
        attribute_type_definitions = map(_decode_utf8,
                result[0][1][_encode_utf8("attributeTypes")])

        attribute_type_dicts = []
        for type_definition in attribute_type_definitions:
            type_dict = {}

            sup_match = SUP_REGEX.match(type_definition)
            if sup_match:
                type_dict["sup"] = sup_match.group(1)

            desc_match = DESC_REGEX.match(type_definition)
            if desc_match:
                type_dict["desc"] = desc_match.group(1)

            oid_match = OID_REGEX.match(type_definition)
            if oid_match:
                type_dict["oid"] = oid_match.group(1)

            single_value_match = SINGLE_VALUE_REGEX.match(type_definition)
            if single_value_match:
                type_dict["single_value"] = bool(single_value_match)

            one_name_match = ONE_NAME_REGEX.match(type_definition)
            if one_name_match:
                names = [one_name_match.group(1)]
            else:
                names_string = MULTIPLE_NAMES_REGEX.match(type_definition).group(1)
                names = [n.strip("'") for n in names_string.split(" ")]
            type_dict["names"] = names

            syntax_match = SYNTAX_REGEX.match(type_definition)
            if syntax_match:
                type_dict["syntax"] = syntax_match.group(1)

            attribute_type_dicts.append(type_dict)

        type_dicts_by_name = {}
        for type_dict in attribute_type_dicts:
            for name in type_dict["names"]:
                type_dicts_by_name[name] = type_dict

        # Resolve inheritance for attribute types
        resolved_type_dicts = []
        for type_dict in attribute_type_dicts:
            # Build a list of ancestors, starting with the leaf
            ancestors = []
            current_ancestor = type_dict
            while current_ancestor is not None:
                ancestors.append(current_ancestor)
                current_ancestor = type_dicts_by_name.get(
                        current_ancestor.get("sup", None), None)
            # Reverse ancestors, so the root comes first
            ancestors.reverse()
            resolved_type_dict = {}
            for ancestor in ancestors:
                resolved_type_dict.update(ancestor)

            resolved_type_dicts.append(resolved_type_dict)

        # Build the types for each of the type definitions
        self._attribute_type_by_name = {}
        for type_dict in resolved_type_dicts:
            base_classes = []
            if type_dict.get("single_value", False):
                base_classes.append(SingleValueAttributeMixin)
            else:
                base_classes.append(MultiValueAttributeMixin)

            type_mixin = ATTRIBUTE_SYNTAX_TO_TYPE_MIXIN[type_dict["syntax"]]
            base_classes.append(type_mixin)

            base_classes.append(LDAPAttributeBase)
            if sys.version_info[0] >= 3: # Python 3
                attribute_type = type("LDAPAttribute", tuple(base_classes), {})
            else:
                attribute_type = type(bytes("LDAPAttribute"),
                        tuple(base_classes), {})
            for name in type_dict["names"]:
                self._attribute_type_by_name[name] = attribute_type

    def get_attribute_type(self, name):
        return self._attribute_type_by_name[name]

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

        # Keep around references to pointers to owned memory with data that is
        # still needed.
        prevent_garbage_collection = []

        if retrieve_attributes is not None:
            attrs_p = ffi.new("char*[{}]".format(len(retrieve_attributes) + 1))
            for i, a in enumerate(retrieve_attributes):
                attr_p = ffi.new("char[]", _encode_utf8(a))
                prevent_garbage_collection.append(attr_p)
                attrs_p[i] = attr_p
            attrs_p[len(retrieve_attributes)] = ffi.NULL
        else:
            attrs_p = ffi.NULL

        err = ldap.ldap_search_ext_s(
                self._ld,
                _encode_utf8(base or self._base),
                scope,
                (_encode_utf8(search_filter)
                    if search_filter is not None else ffi.NULL),
                attrs_p,
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
                entry = LDAPEntry(self, _decode_utf8(dn), attributes=set())
                for name, value in attributes_dict.items():
                    # TODO: Create the right type of LDAPAttribute here
                    attribute_type = self.get_attribute_type(_decode_utf8(name))
                    attribute = attribute_type(_decode_utf8(name))
                    attribute._set_ldap_values(value)
                    entry.attributes.add(attribute)
                yield entry
        except LDAPNoSuchObjectError:
            # If the search returned without results, "return" an empty list.
            return

    def get_entry(self, *args, **kwargs):
        """Get an LDAPEntry object associated with this connection."""
        return LDAPEntry(self, *args, **kwargs)


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
        parent_dn = ",".join(self.dn.split(',')[1:])
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
            attribute_type = self._connection.get_attribute_type(name)
            save_attributes.add(attribute_type(name))

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
            if attribute.single_value:
                return attribute.value
            else:
                return attribute.values
        raise AttributeError()

    def __setattr__(self, name, value):
        """Set an attribute value.

        If the attribute is multi-value but the passed value is not a list
        or set, the value is set as the first and only value of the set of
        values for this attribute.
        """
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
            attribute_type = self._connection.get_attribute_type(name)
            attribute = attribute_type(name)
            self.attributes.add(attribute)

        if attribute.single_value:
            attribute.value = value
        else:
            if isinstance(value, (list, set)):
                attribute.values = value
            else:
                attribute.values = {value}

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
        ldap.ldap_delete_s(self._connection._ld, _encode_utf8(self.dn))

    def set_password(self, password):
        """Change the password for this LDAP entry.

        :param password: The password to set
        :type password: str
        """
        raise NotImplementedError()

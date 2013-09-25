# -*- coding: utf-8 -*-
"""Types for dealing with different LDAP attributes."""

from __future__ import unicode_literals
from __future__ import print_function

import re
import sys

from ldapom import compat

if sys.version_info[0] >= 3: # Python 3
    unicode = str

OID_REGEX = re.compile(r"\( ([0-9\.]+) .* \)")
SINGLE_VALUE_REGEX = re.compile(r"\(.* SINGLE-VALUE .*\)")
ONE_NAME_REGEX = re.compile(r"\(.* NAME \'([^']+)\' .*\)")
MULTIPLE_NAMES_REGEX = re.compile(r"\(.* NAME \( ([^)]+) \) .*\)")
SYNTAX_REGEX = re.compile(r"\(.* SYNTAX ([0-9\.]+)({\d+})? .*\)")
DESC_REGEX = re.compile(r"\(.* DESC \'([^']+)\' .*\)")
SUP_REGEX = re.compile(r"\(.* SUP (\w+) .*\)")


class LDAPAttributeBase(compat.UnicodeMixin, object):
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
        return "<LDAPAttribute " + self.name + ">"


class SingleValueAttributeMixin(object):
    single_value = True
    multi_value = False

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
    multi_value = True

    def _get_values(self):
        return self._values

    def _set_values(self, values):
        self._values = set(values)

    values = property(_get_values, _set_values)


class UnicodeAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set([compat._decode_utf8(v) for v in values])

    def _get_ldap_values(self):
        return set([compat._encode_utf8(v) for v in self._values])


class BooleanAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set([(compat._decode_utf8(v) == "TRUE") for v in values])

    def _get_ldap_values(self):
        string_values = ["TRUE" if v else "FALSE" for v in self._values]
        return set([compat._encode_utf8(v) for v in string_values])


class IntegerAttributeMixin(object):
    def _set_ldap_values(self, values):
        self._values = set([int(compat._decode_utf8(v)) for v in values])

    def _get_ldap_values(self):
        return set([compat._encode_utf8(unicode(v)) for v in self._values])


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

def build_attribute_types(type_definitions):
    """Build attribute types from type definitions.

    :param type_definitions: A list of LDAP attribute type definitions.
    :type type_definition: list of str
    :rtype: Name-keyed dict of attribute types.
    """
    attribute_type_dicts = []
    for type_definition in type_definitions:
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
    attribute_types_by_name = {}
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
            attribute_types_by_name[name] = attribute_type

    return attribute_types_by_name

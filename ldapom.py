#! /usr/bin/python
# -*- coding: utf-8 -*-
"An LDAP object-mapper"

# Copyright (c) 2010 Florian Richter <mail@f1ori.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## @mainpage
#
# The @e ldapom python module provides a simple LDAP object mapper.
#
# @author Florian Richter
#

import ldap
import re
from copy import deepcopy

LDAPOM_VERBOSE = False

## Force a string to be encoded as UTF-8
def _encode_utf8(string):
    if string is None:
        return None
    elif isinstance(string, unicode):
        return string.encode('utf-8')
    else:
        return str(string)

## Force a string to be unicode, convert from  UTF-8
def _decode_utf8(s):
    if s is None:
        return None
    elif isinstance(s, str):
        return s.decode('utf-8')
    else:
        return s

## decorator to handle disconnection of ldap server
def _retry_on_disconnect(func):
    ## wrapper function, catching the exception
    def new(self, *args, **kws):
        try:
            return func.__call__(self, *args, **kws)
        except ldap.SERVER_DOWN:
            # try to reconnect
            self._connect()
        return func(self, *args, **kws)
    return new


## decorator for generator functions to handle disconnection
## of ldap server
def _retry_on_disconnect_gen(func):

    ## wrapper function, catching the exception
    ## (acting as generator function)
    def new(self, *args, **kws):
        try:
            gen = func(self, *args, **kws)
            yield gen.next()
        except ldap.SERVER_DOWN:
            # try to reconnect
            self._connect()
            gen = func(self, *args, **kws)
        while True:
            yield gen.next()
        # return via StopIteration-exception

    return new

class LdapType(object):
    @property
    def single_value(self):
        return self._single_value

    def __init__(self, type, single_value):
        self._type = type
        self._single_value = single_value

    def single_decode_from_ldap(self, var):
        if self._type == unicode:
            return var.decode('utf-8')
        if self._type == str:
            return var
        if self._type == int:
            return int(var)
        if self._type == bool:
            return var == 'TRUE'

    def decode_from_ldap(self, var):
        if self.single_value:
            return self.single_decode_from_ldap(var[0])
        else:
            return map(self.single_decode_from_ldap, var)

    def single_encode_for_ldap(self, var):
        if self._type == unicode:
            return var.encode('utf-8') if isinstance(var, unicode) else str(var)
        if self._type == str:
            return str(var)
        if self._type == int:
            return str(var)
        if self._type == bool:
            return 'TRUE' if bool(var) else 'FALSE'

    def encode_for_ldap(self, var):
        if self.single_value:
            return [self.single_encode_for_ldap(var)]
        else:
            # for convienance, accept single values for multiple value fields
            if not isinstance(var, list):
                return [self.single_encode_for_ldap(var)]
            else:
                return map(self.single_encode_for_ldap, var)

    def get_changes(self, name, old_attrs, new_attrs):
        old_attr = self.encode_for_ldap(old_attrs[name]) if name in old_attrs else []
        new_attr = self.encode_for_ldap(new_attrs[name]) if name in new_attrs else []
        change_list = []
        # deleted values
        for value in old_attr:
            if value not in new_attr:
                change_list.append( (ldap.MOD_DELETE, name, value) )
        # new values
        for value in new_attr:
            if value not in old_attr:
                change_list.append( (ldap.MOD_ADD, name, value) )
        return change_list


class LdapAttributeType(object):
    _oid_regex = re.compile(ur'\( ([0-9\.]+) .* \)')
    _single_value_regex = re.compile(ur'\(.* SINGLE-VALUE .*\)')
    _one_name_regex = re.compile(ur"\(.* NAME \'([^']+)\' .*\)")
    _multiple_names_regex = re.compile(ur"\(.* NAME \( ([^)]+) \) .*\)")
    _syntax_regex = re.compile(ur"\(.* SYNTAX ([0-9\.]+)({\d+})? .*\)")
    _desc_regex = re.compile(ur"\(.* DESC \'([^']+)\' .*\)")
    _sup_regex = re.compile(ur"\(.* SUP (\w+) .*\)")

    @property
    def oid(self):
        return self._oid

    @property
    def names(self):
        return self._names

    @property
    def single_value(self):
        return self._single_value

    @property
    def sup(self):
        return self._sup

    @property
    def description(self):
        return self._description

    def __init__(self, type_str):
        # parse attribute type definition
        sup_match = self._sup_regex.match(type_str)
        self._sup = sup_match.group(1) if sup_match else None
        oid_match = self._oid_regex.match(type_str)
        self._oid = oid_match.group(1) if oid_match else None
        self._single_value = bool(self._single_value_regex.match(type_str))
        syntax_match = self._syntax_regex.match(type_str)
        self._syntax = syntax_match.group(1) if syntax_match else None
        desc_match = self._desc_regex.match(type_str)
        self._description = desc_match.group(1) if desc_match else None
        one_name_match = self._one_name_regex.match(type_str)
        if one_name_match:
            self._names = [ one_name_match.group(1) ]
        else:
            name_list = self._multiple_names_regex.match(type_str).group(1)
            self._names = [ x.strip(u"'") for x in name_list.split(u" ") ]

    def get_type(self):
        return {
            '1.3.6.1.1.1.0.0':               str,     # RFC2307 NIS Netgroup Triple
            '1.3.6.1.1.1.0.1':               unicode, # RFC2307 Boot Parameter
            '1.3.6.1.1.16.1':                unicode, # UUID
            '1.3.6.1.4.1.1466.115.121.1.3':  unicode, # Attribute Type Description
            '1.3.6.1.4.1.1466.115.121.1.4':  str,     # Audio
            '1.3.6.1.4.1.1466.115.121.1.5':  str,     # Binary
            '1.3.6.1.4.1.1466.115.121.1.6':  str,     # Bit String
            '1.3.6.1.4.1.1466.115.121.1.7':  bool,    # Boolean
            '1.3.6.1.4.1.1466.115.121.1.8':  str,     # Certificate
            '1.3.6.1.4.1.1466.115.121.1.9':  str,     # Certificate List
            '1.3.6.1.4.1.1466.115.121.1.10': str,     # Certificate Pair
            '1.3.6.1.4.1.1466.115.121.1.11': unicode, # CountryString
            '1.3.6.1.4.1.1466.115.121.1.12': unicode, # Distinguished Name
            '1.3.6.1.4.1.1466.115.121.1.13': unicode, # Data Quality Syntax
            '1.3.6.1.4.1.1466.115.121.1.14': unicode, # Delivery Method
            '1.3.6.1.4.1.1466.115.121.1.15': unicode, # DirectoryString
            '1.3.6.1.4.1.1466.115.121.1.19': unicode, # DSA Quality Syntax
            '1.3.6.1.4.1.1466.115.121.1.21': unicode, # Enhanced Guide
            '1.3.6.1.4.1.1466.115.121.1.22': unicode, # Facsimile Telephone Number
            '1.3.6.1.4.1.1466.115.121.1.23': str,     # Fax Image Syntax
            '1.3.6.1.4.1.1466.115.121.1.24': unicode, # GeneralizedTime
            '1.3.6.1.4.1.1466.115.121.1.25': unicode, # Guide (Obsolete)
            '1.3.6.1.4.1.1466.115.121.1.26': unicode, # IA5String
            '1.3.6.1.4.1.1466.115.121.1.27': int,     # Integer
            '1.3.6.1.4.1.1466.115.121.1.28': str,     # JPEG
            '1.3.6.1.4.1.1466.115.121.1.30': unicode, # Matching Rule Description syntax
            '1.3.6.1.4.1.1466.115.121.1.31': unicode, # Matching Rule Use Description syntax
            '1.3.6.1.4.1.1466.115.121.1.34': unicode, # Name And Optional UID
            '1.3.6.1.4.1.1466.115.121.1.36': unicode, # NumericString
            '1.3.6.1.4.1.1466.115.121.1.37': unicode, # Object Class Description syntax
            '1.3.6.1.4.1.1466.115.121.1.38': unicode, # OID
            '1.3.6.1.4.1.1466.115.121.1.39': unicode, # Other Mailbox
            '1.3.6.1.4.1.1466.115.121.1.40': str,     # OctetString
            '1.3.6.1.4.1.1466.115.121.1.41': unicode, # PostalAddress
            '1.3.6.1.4.1.1466.115.121.1.42': unicode, # protocolInformation
            '1.3.6.1.4.1.1466.115.121.1.43': unicode, # Presentation Address syntax
            '1.3.6.1.4.1.1466.115.121.1.44': unicode, # PrintableString
            '1.3.6.1.4.1.1466.115.121.1.49': str,     # Supported Algorithm
            '1.3.6.1.4.1.1466.115.121.1.50': unicode, # TelephoneNumber
            '1.3.6.1.4.1.1466.115.121.1.51': unicode, # Teletex Terminal Identifier
            '1.3.6.1.4.1.1466.115.121.1.52': unicode, # Telex Number
            '1.3.6.1.4.1.1466.115.121.1.54': unicode, # LDAP Syntax Description
            '1.3.6.1.4.1.4203.666.2.7':      str,     # OpenLDAP authz
        }[self._syntax]


## This Object holds all parameters to connect to an ldapserver
## and provide a minimal convenience.
## Methods marked as internal in the docstring should only be used
## by this module.
##
## Methods for external relevance so far:
## * __init__
## * get_ldap_node
## * retrieve_ldap_node
class LdapConnection(object):

    ## Create a new LdapConnection.
    ##
    ## This already connects to the LDAP server. There is no lazy loading.
    ##
    ## @param uri URI indicating the LDAP instance we should connect to
    ## @param base The Base of the LDAP we are working in
    ## @param login The dn we are authenticating with
    ## @param password The password for the login dn
    ## @param certfile If using SSL/TLS, this is the server's certificate
    ## @param timelimit Set a limit to the time a search request may take
    def __init__(self, uri, base, login, password, certfile=None, timelimit=30):
        ## native python-ldap connection instance
        self._lo = None
        ## URI indicating the LDAP instance we should connect to
        self._uri = uri
        ## The Base of the LDAP we are working in
        self._base = base
        ## The dn we are authenticating with
        self._login = login
        ## The password for the login dn
        self._password = password
        ## If using SSL/TLS, this is the server's certificate
        self._certfile = certfile
        ## Defines how long we will wait for result answers from the LDAP server
        self._timeout = 0
        ## Set timelimit, python-ldap defaults to 30
        ldap.set_option(ldap.OPT_TIMELIMIT, timelimit)
        # After storing all information, we connect to the server
        self._connect()

    ## Connect to LDAP server
    ##
    ## @return None
    def _connect(self):
        if self._certfile:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self._certfile)
        self._lo = ldap.initialize(self._uri)
        #self._lo.set_option(ldap.OPT_X_TLS_DEMAND, False)
        _login = _encode_utf8(self._login)
        _password = _encode_utf8(self._password)
        self._lo.simple_bind_s(_login, _password)
        self._fetch_attribute_types()

    def _fetch_attribute_types(self):
        # to avoid the hen and egg problem, do it the hard way
        result = self._lo.search_s("cn=subschema", ldap.SCOPE_BASE, "(objectClass=*)", ["attributeTypes"])
        if result == None:
            raise Exception("Could not fetch attribute types")
        attribute_types = result[0][1]['attributeTypes']
        attribute_types_for_name = {}
        for attribute_type in attribute_types:
            t = LdapAttributeType(attribute_type.decode('utf-8'))
            for name in t.names:
                attribute_types_for_name[name] = t
        self._type_for_name = {}
        for name, attribute_type in attribute_types_for_name.items():
            # get parent type
            while attribute_type.sup:
                attribute_type = attribute_types_for_name[attribute_type.sup]
            self._type_for_name[name] = LdapType(attribute_type.get_type(), attribute_type.single_value)

    @_retry_on_disconnect
    ## Try to authenticate on a seperate connection to check the (dn, password)
    ## combination.
    ##
    ## @param dn The dn to authenticate with
    ## @param password The password for the login dn
    ## @return boolean
    def authenticate(self, dn, password):
        lo = ldap.initialize(self._uri)
        # TODO:tls
        try:
            lo.simple_bind_s(_encode_utf8(dn), _encode_utf8(password))
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    @_retry_on_disconnect
    ## raw LDAP add function
    ##
    ## @param dn The new/modified dn
    ## @param attrs The added attributes
    ## @return None
    def add(self, dn, attrs):
        self._lo.add_s(dn, attrs)

    @_retry_on_disconnect
    ## raw LDAP modify function
    ##
    ## @param dn The modified dn
    ## @param change The changed attributes
    ## @return None
    def modify(self, dn, change):
        self._lo.modify_s(dn, change)


    @_retry_on_disconnect
    ## raw ldap rename function
    ##
    ## @param dn The old DN
    ## @param newrdn The new DN
    ## @return None
    def rename(self, dn, newrdn):
        _dn = _encode_utf8(dn)
        _newrdn = _encode_utf8(newrdn)
        self._lo.rename_s(_dn, _newrdn, delold=1)


    @_retry_on_disconnect
    ## raw LDAP delete function
    ##
    ## @param dn The DN of the LDAP node that should be deleted
    ## @return None
    def delete(self, dn):
        _dn = _encode_utf8(dn)
        self._lo.delete_s(_dn)

    @_retry_on_disconnect
    ## recursive delete function
    ##
    ## @param dn The DN of the LDAP node that should be deleted
    ## @return None
    def delete_r(self, dn):
        toDelete = list(self.query(base=dn,scope=ldap.SCOPE_ONELEVEL))
        for sub in toDelete:
            self.delete_r(sub[0])
        self.delete(dn)

    @_retry_on_disconnect_gen
    ## Convencience wrapper arround python-ldap internal search
    ##
    ## @param filter The LDAP query send to the server
    ## @param retrieve_attributes The list of attributes that should be fetched. If None, all are fetched.
    ## @param base The base dn from where the search starts in the LDAP tree
    ## @param scope The search scope in the LDAP tree
    ## @return string[]
    def query(self, filter="(objectClass=*)", retrieve_attributes=None, base=None,
                scope=ldap.SCOPE_SUBTREE):
        if base is None:
            base = self._base
        base = _encode_utf8(base)
        if retrieve_attributes:
            retrieve_attributes = map(_encode_utf8, retrieve_attributes)
        filter = _encode_utf8(filter)
        result_id = self._lo.search(base, scope, filter, retrieve_attributes)
        while True:
            result_type, result_data = self._lo.result(result_id, self._timeout)
            if (result_data == []):
                break
            elif result_type == ldap.RES_SEARCH_ENTRY:
                yield result_data[0]

    @_retry_on_disconnect
    ## Change the password of a user.
    ##
    ## This issues an LDAP Password Modify Extended Operation.
    ##
    ## @param dn The DN of which the password should be changed
    ## @param password The new password
    ## @return None
    def set_password(self, dn, password):
        _dn = _encode_utf8(dn)
        _password = _encode_utf8(password)
        # Issue an LDAP Password Modify Extended Operation
        self._lo.passwd_s(_dn, None, _password)

    ## Like query(), but wraps each object as an LdapNode.
    ##
    ## @param args The arguments supplied which will be passed through to query()
    ## @param kwargs The keyword arguments supplied which will be passed through to query()
    ## @return LdapNode[]
    def search(self, *args, **kwargs):
        for dn, attributes_dict in self.query(*args, **kwargs):
            node = LdapNode(self, dn)
            node._load_attributes(attributes_dict)
            yield node

    ## Search LDAP server for dn and return a boolean
    ##
    ## @param dn The DN for which existence should be checked
    ## @return boolean
    def check_if_dn_exists(self, dn):
        try:
            res = self.query(base=dn, scope=ldap.SCOPE_BASE)
            if len(list(res)) != 0:
                return True
        except ldap.NO_SUCH_OBJECT:
            return False
        return False

    ## Create lazy LdapNode-Object linked to this connection
    ##
    ## @param dn The DN of the LDAP node which we would like to have mapped into an LdapNode
    ## @return LdapNode
    def get_ldap_node(self, dn):
        return LdapNode(self, dn)

    ## Retrieves the object from that database and wraps it as an LdapNode.
    ##
    ## This is the same as get_ldap_node, except that all attributes
    ## for this node will be obtained from that database immediately
    ## instead of lazily.
    ##
    ## It will raise ldap.NO_SUCH_OBJECT if the entry cannot be found.
    ##
    ## @param dn The DN of the LDAP node which we would like to have mapped into an LdapNode
    ## @return LdapNode
    def retrieve_ldap_node(self, dn):
        node = LdapNode(self, dn)
        node.retrieve_attributes()
        return node

    ## Create new LdapNode-Object linked to this connection
    #
    #  @param dn The DN of the newly created LdapNode
    #  @return LdapNode
    def new_ldap_node(self, dn):
        return LdapNode(self, dn, new=True)


## Holds an LDAP object represented by the dn (distinguishable name).
#  attributes are fetched from the LDAP server lazily, so you can
#  create objects without causing network traffic.
class LdapNode(object):

    ## Creates the lazy node object using the given connection and dn.
    # @param conn The connection string
    # @param dn The DN to use
    # @param new default: @e False
    def __init__(self, conn, dn, new=False):
        self._conn = conn
        self._dn = _decode_utf8(dn)
        self._valid = True
        self._to_delete = []
        self._new = new
        if new:
            self._attr = {}
            self._old_attr = {}
        else:
            self._attr = None
            self._old_attr = None

    ## Expose dn as a ready-only property
    dn = property(lambda self: self._dn)


    ## Get the parent node in the LDAP tree
    def get_parent(self):
        dn_parts = map(_decode_utf8, ldap.explode_dn(_encode_utf8(self._dn)))
        parent_dn = u','.join(dn_parts[1:])
        return LdapNode(self._conn, parent_dn)


    ## Retrieves the node's attributes from the database.
    #
    #  Attributes are usually loaded lazily (the first time they're accessed),
    #  but you can use this method to force this to happen now.
    #
    #  @return None
    def retrieve_attributes(self):
        _dn, attributes_dict = self._conn.query(base=self._dn, scope=ldap.SCOPE_BASE).next()
        self._load_attributes(attributes_dict)

    ## Fill node object with attribute values
    #
    #  @return None
    def _load_attributes(self, attributes_dict):
        self._attr = dict([
                (name, self._conn._type_for_name[name].decode_from_ldap(values))
                for name, values in attributes_dict.items()
                ])
        self._old_attr = deepcopy(self._attr)

    ## get an LDAP attribute
    #
    #  @returns the value of the attribute identified by its @p name.
    #  Attributes starting with <em>is_*</em> are mapped to a check, if the
    #  objectClass is present.
    def __getattr__(self, name):
        if self._attr is None:
            self.retrieve_attributes()
        if name.startswith("is_"):
            return name[3:] in self._attr[u'objectClass']
        if name in self._attr:
            return self._attr[name]
        raise AttributeError('Cannot find attribute %s' % name)

    ## Sets the @p value of the attribute identified by its @p name.
    # @return None
    def __setattr__(self, name, value):
        # handle private attributes the default way
        if name.startswith("_"):
            return object.__setattr__(self, name, value)
        if self._attr is None:
            self.retrieve_attributes()
        self._attr[name] = value

    ## Deletes the attribute identified by its @p name.
    # @return None
    def __delattr__(self, name):
        if self._attr is None:
            self.retrieve_attributes()
        del self._attr[name]

    ## @returns the unicode DN of the node.
    def __unicode__(self):
        return self._dn

    ## @returns the string DN of the node.
    def __str__(self):
        return self._dn.encode("utf-8")

    ## @returns the String representation of the object.
    def __repr__(self):
        r = u"<LdapNode: %s>" % self._dn
        return r.encode('utf-8')

    ## Saves any changes made to the object.
    ## @return None
    def save(self):
        if self._attr is None:
            # No changes yet
            return
        # infer differences
        change_list = []
        # TODO: delete attribute
        for name in self._attr.keys():
            change_list.extend(self._conn._type_for_name[name].get_changes(name, self._old_attr, self._attr))

        if self._new:
            change_list = [ (c[1], c[2]) for c in change_list ]
            if LDAPOM_VERBOSE:  # pragma: no cover
                print("ldap_add: {0}".format(change_list))
            self._conn.add(self._dn.encode('utf-8'), change_list)
        else:
            if change_list == []:
                return
            if LDAPOM_VERBOSE:  # pragma: no cover
                print("ldap_modify: {0}".format(change_list))
            self._conn.modify(self._dn.encode('utf-8'), change_list)
        self._new = False
        self._old_attr = self._attr

    ## delete this object in LDAP
    #
    #  @return None
    def delete(self):
        self._conn.delete(self._dn.encode('utf-8'))
        self._valid = False

    ## check password for this LDAP object
    #
    #  @return Boolean
    #  @param password String Password which will be used for authentication
    def check_password(self, password):
        return self._conn.authenticate(self._dn.encode('utf-8'), _encode_utf8(password))

    ## set password for this LDAP object immediately
    #
    # Issues an LDAP Password Modify Extended Operation
    #
    #  @return None
    #  @param password String new password (plain text as hashes are done by the LDAP server)
    def set_password(self, password):
        self._conn.set_password(self._dn.encode('utf-8'), _encode_utf8(password))

# vim: ai sw=4 expandtab

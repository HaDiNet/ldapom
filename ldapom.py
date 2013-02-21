#! /usr/bin/python
# -*- coding: utf-8 -*-

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

LDAPOM_VERBOSE = False

## Force a string to be encoded as UTF-8
def _encode_utf8(str):
    if str == None:
        return None
    elif type(str) == unicode:
        return str.encode('utf-8')
    else:
        return unicode(str)

## Force a string to be unicode, convert from  UTF-8
def _decode_utf8(s):
    if s == None:
        return None
    elif type(s) == str:
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
        while 1:
            yield gen.next()
        # return via StopIteration-exception

    return new


## This Object holds all parameters to connect to an ldapserver
## and provide a minimal convenience.
## Methods marked as internal in the docstring should be used only
## by this modul.
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
    ## @param certfile If using SSL/TLS this is certificate of the server
    ## @param timelimit Set the timelimit a search request may take
    def __init__(self, uri, base, login, password, certfile=None, timelimit=30):
        """
        """

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
        ## If using SSL/TLS this is certificate of the server
        self._certfile = certfile
        # After storing all information, we connect to the server
        self._connect()
        ## Defines how long we will wait for result answers from the LDAP server
        self._timeout = 0
        ## Set timelimit, python-ldap defaults to 30
        ldap.set_option(ldap.OPT_TIMELIMIT, timelimit)

    ## Connect to ldap-server
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
    ## raw ldap add function
    ##
    ## @param dn The new/modified dn
    ## @param attrs The added attributes
    ## @return None
    def add(self, dn, attrs):
        self._lo.add_s(dn, attrs)

    @_retry_on_disconnect
    ## raw ldap modify function
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
    ## raw ldap delete function
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
        if base == None:
            base = self._base
        base = _encode_utf8(base)
        scope = _encode_utf8(scope)
        if retrieve_attributes:
            retrieve_attributes = map(_encode_utf8, retrieve_attributes)
        filter = _encode_utf8(filter)
        result_id = self._lo.search(base, scope, filter, retrieve_attributes)
        while 1:
            result_type, result_data = self._lo.result(result_id, self._timeout)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    yield result_data[0]

    @_retry_on_disconnect
    ## Change the password of a user.
    ##
    ## This issues a LDAP Password Modify Extended Operation.
    ##
    ## @param dn The DN of which the password should be changed
    ## @param password The new password
    ## @return None
    def set_password(self, dn, password):
        _dn = _encode_utf8(dn)
        _password = _encode_utf8(password)
        # Issue a LDAP Password Modify Extended Operation
        self._lo.passwd_s(_dn, None, _password)

    ## Like query(), but wraps each object as an LdapNode.
    ##
    ## @param args The arguments supplied which will be passed thru to query()
    ## @param kwargs The keyword arguments supplied which will be passed thru to query()
    ## @return LdapNode[]
    def search(self, *args, **kwargs):
        for dn, attributes_dict in self.query(*args, **kwargs):
            node = LdapNode(self, dn)
            node._load_attributes(attributes_dict)
            yield node

    ## Search ldap-server for dn and return a boolean
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
    ## @param dn The DN of the LDAP node which we would like to have mapped into a LdapNode
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
    ## @param dn The DN of the LDAP node which we would like to have mapped into a LdapNode
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


## Holds a set of LDAP-Attributes with the same name.
#
#  All changes are recorded, so they can be pushed to ldap_modify directly.
class LdapAttribute(object):

    ## Creates a new attribute with the given @p name and @p value. If @p add is @e False (default), the current value
    # is overwritten, else appended.
    def __init__(self, name, value, add=False):
        self._name = _decode_utf8(name)
        self._replace_all = False
        self._changes = []
        if add:
            self._values = []
            if type(value) == list:
                for v in value:
                    self.append(_decode_utf8(v))
            else:
                self.append(_decode_utf8(value))
        else:
            if type(value) == list:
                self._values = map(_decode_utf8, value)
            else:
                self._values = [_decode_utf8(value)]

    ## The number of values set for this attribute
    #
    #  @return Integer
    def __len__(self):
        return len(self._values)

    ## @returns String
    def __str__(self):
        # if there's only one item, return it directly
        if len(self._values) == 1:
            return self._values[0].encode("utf-8")
        return [val.encode("utf-8") for val in self._values]

    ## unicode value of this attribute
    #
    #  @return String
    def __unicode__(self):
        # if there's only one item, return it directly
        if len(self._values) == 1:
            return self._values[0]
        return self._values

    ## literal representation
    #
    #  @returns the String representation of the object.
    def __repr__(self):
        return u"<LdapAttribute: %s=%s>" % (self._name, self.__unicode__())

    ## add an attribute
    #
    #  @param value String the additional value
    #  @return None
    def append(self, value):
        value = _decode_utf8(value)
        if not value in self._values:
            self._values.append(value)
            self._changes.append((ldap.MOD_ADD, self._name, value))

    ## remove an attribute
    #
    #  @param value String the to-be-removed value
    #  @return None
    def remove(self, value):
        value = _decode_utf8(value)
        if value in self._values:
            self._values.remove(value)
            self._changes.append((ldap.MOD_DELETE, self._name, value))

    ## Membership test operator (<em>in</em> and <em>not in</em>), tests if the attribute contains the @p item.
    #  @return Boolean
    def __contains__(self, item):
        item = _decode_utf8(item)
        return self._values.__contains__(item)

    ## @returns the item identified by @p key
    def __getitem__(self, key):
        key = _decode_utf8(key)
        return self._values[key]

    ## Sets the value of @p key to @p value.
    # @return None
    def __setitem__(self, key, value):
        key = _decode_utf8(key)
        self._replace_all = True
        self._values[key] = _decode_utf8(value)

    ## Deletes the value identified by its @p key
    # @return None
    def __delitem__(self, key):
        key = _decode_utf8(key)
        self._replace_all = True
        self._values.remove(key)

    ## @return Iterator
    def __iter__(self):
        return self._values.__iter__()

    ## Sets single @p value, discards all existing ones.
    ## @return None
    def set_value(self, value):
        if type(value) == list:
            self._values = [_decode_utf8(x) for x in value]
        else:
            self._values = [_decode_utf8(value)]
        self._replace_all = True

    ## get all changes to this attribute in ldap_modify-syntax
    #
    #  @return Array
    def get_change_list(self):
        if self._replace_all:
            if len(self) == 0:
                return [(ldap.MOD_DELETE, self._name, None)]
            change_list = [ (ldap.MOD_REPLACE, self._name, x) for x in self._values[0:1]]
            change_list += [ (ldap.MOD_ADD, self._name, x) for x in self._values[1:] ]
            return change_list
        return self._changes

    ## called when attribute-changes were successfully saved
    #
    #  @return None
    def discard_change_list(self):
        self._changes = []
        self._replace_all = False


## Holds an ldap-object represented by the dn (distinguishable name).
#  attributes are fetched from ldapserver lazily, so you can create objects
#  without network traffic.
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
        else:
            self._attr = None

    ## Expose dn as a ready-only property
    dn = property(lambda self: self._dn)

    ## Retrieves the node's attributes from the database.
    #
    #  Attributes are usually loaded lazily (the first time they're accessed),
    #  but you can use this method to force this to happen now.
    #
    #  @return None
    def retrieve_attributes(self):
        _dn, attributes_dict = list(self._conn.query(base=self._dn, scope=ldap.SCOPE_BASE))[0]
        self._load_attributes(attributes_dict)

    ## Fill node object with attribute values
    #
    #  @return None
    def _load_attributes(self, attributes_dict):
        self._attr = dict([
            (attr_name, LdapAttribute(attr_name, attr_values))
                for attr_name, attr_values in attributes_dict.items()
        ])

    ## get an ldap-attribute
    #
    #  @returns the value of the attribute identified by its @p name.
    #  Attributes starting with <em>is_*</em> are mapped to a check, if the
    #  objectClass is present.
    def __getattr__(self, name):
        if self._attr == None:
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
        if self._attr == None:
            self.retrieve_attributes()
        if name in self._attr:
            self._attr[name].set_value(value)
        else:
            self._attr[name] = LdapAttribute(name, value, add=True)

    ## Deletes the attribute identified by its @p name.
    # @return None
    def __delattr__(self, name):
        if self._attr == None:
            self.retrieve_attributes()
        del self._attr[name]
        self._to_delete.append(name)

    ## @returns the unicode DN of the node.
    def __unicode__(self):
        return self._dn

    ## @returns the string DN of the node.
    def __str__(self):
        return self._dn.encode("utf-8")

    ## @returns the String representation of the object.
    def __repr__(self):
        return u"<LdapNode: %s>" % self._dn

    ## Saves any changes made to the object.
    ## @return None
    def save(self):
        if self._attr == None:
            # No changes yet
            return
        if self._new:
            change_list = [ (_encode_utf8(x._name), [_encode_utf8(y) for y in x]) for x in self._attr.values() ]
            if LDAPOM_VERBOSE:  # pragma: no cover
                print("ldap_add: {0}".format(change_list))
            self._conn.add(_encode_utf8(self._dn), change_list)
        else:
            change_list = [ (ldap.MOD_DELETE, _encode_utf8(x), None) for x in self._to_delete ]
            for attr in self._attr.values():
                change_list.extend([(x, _encode_utf8(y), _encode_utf8(z)) for (x,y,z) in attr.get_change_list()])
            if len(change_list) == 0:
                return
            if LDAPOM_VERBOSE:  # pragma: no cover
                print("ldap_modify: {0}".format(change_list))
            self._conn.modify(_encode_utf8(self._dn), change_list)
        self._new = False
        self._to_delete = []
        for attr in self._attr.values():
            attr.discard_change_list()

    ## delete this object in ldap
    #
    #  @return None
    def delete(self):
        self._conn.delete(_encode_utf8(self._dn))
        self._valid = False

    ## check password for this ldap-object
    #
    #  @return Boolean
    #  @param password String Password which will be used for authentication
    def check_password(self, password):
        return self._conn.authenticate( _encode_utf8(self._dn), _encode_utf8(password) )

    ## set password for this ldap-object immediately
    #
    # Issues a LDAP Password Modify Extended Operation
    #
    #  @return None
    #  @param password String new password (plain text as hashes are done by the LDAP server)
    def set_password(self, password):
        self._conn.set_password(_encode_utf8(self._dn), _encode_utf8(password))

# vim: ai sw=4 expandtab

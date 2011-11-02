#! /usr/bin/python
# -*- coding: utf-8 -*-
"A LDAP object-mapper"

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

import ldap

LDAPOM_VERBOSE = False

def _encode_utf8(str):
    """
    Force a string to be encoded as UTF-8
    """
    if str == None:
        return None
    elif type(str) == unicode:
        return str.encode('utf-8')
    else:
        return str

# decorators
def _retry_on_disconnect(func):
    "decorator to handle disconnection"
    def new(self, *args, **kws):
        "wrapper function, catching the exception"
        try:
            return func.__call__(self, *args, **kws)
        except ldap.SERVER_DOWN:
            # try to reconnect
            self._connect()
        return func(self, *args, **kws)
    return new


def _retry_on_disconnect_gen(func):
    "decorator for generator functions to handle disconnection"

    def new(self, *args, **kws):
        """
                wrapper function, catching the exception
                (acting as generator function)
        """
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


class LdapConnection(object):
    """
        This Object holds all parameters to connect to an ldapserver
        and provide a minimal convenience.
        Methods marked as internal in the docstring should be used only
        by this modul.

        Methods for external relevance so far:
        * __init__
        * getLdapNode
    """

    ## @param uri URI indicating the LDAP instance we should connect to
    ## @param base The Base of the LDAP we are working in
    ## @param login The dn we are authenticating with
    ## @param password The password for the login dn
    ## @param certfile If using SSL/TLS this is certificate of the server
    def __init__(self, uri, base, login, password, certfile=None):
        """
        Create a new LdapConnection.

        This already connects to the LDAP server. There is no lazy loading.
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

    ## @return None
    def _connect(self):
        """
        Connect to ldap-server
        """
        if self._certfile:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
            ldap.set_option(ldap.OPT_X_TLS_CACERTFILE, self._certfile)
        self._lo = ldap.initialize(self._uri)
        #self._lo.set_option(ldap.OPT_X_TLS_DEMAND, False)
        self._lo.simple_bind_s(self._login, self._password)

    @_retry_on_disconnect
    ## @param dn The dn to authenticate with
    ## @param password The password for the login dn
    ## @return boolean
    def authenticate(self, dn, password):
        """
        Try to authenticate on a seperate connection to check the (dn, password)
        combination.
        """
        lo = ldap.initialize(self._uri)
        # TODO:tls
        try:
            _dn = _encode_utf8(dn)
            _password = _encode_utf8(password)
            lo.simple_bind_s(dn, password)
            return True
        except ldap.INVALID_CREDENTIALS:
            return False

    @_retry_on_disconnect
    ## @param dn The new/modified dn
    ## @param attrs The added attributes
    ## @return None
    def add(self, dn, attrs):
        """
        raw ldap add function
        """
        self._lo.add_s(dn, attrs)

    @_retry_on_disconnect
    ## @param dn The modified dn
    ## @param change The changed attributes
    ## @return None
    def modify(self, dn, change):
        """
        raw ldap modify function
        """
        self._lo.modify_s(dn, change)


    @_retry_on_disconnect
    ## @param dn The old DN
    ## @param newrdn The new DN
    ## @return None
    def rename(self, dn, newrdn):
        """
        raw ldap rename function
        """
        self._lo.rename_s(dn, newrdn, delold=1)


    @_retry_on_disconnect
    ## @param dn The DN of the LDAP node that should be deleted
    ## @return None
    def delete(self, dn):
        """
        raw ldap delete function
        """
        self._lo.delete_s(dn)

    @_retry_on_disconnect
    ## @param dn The DN of the LDAP node that should be deleted
    ## @return None
    def delete_r(self, dn):
        """
        recursive delete function
        """
        toDelete = list(self.query(base=dn,scope=ldap.SCOPE_ONELEVEL))
        for sub in toDelete:
            self.delete_r(sub[0])
        self.delete(dn)

    @_retry_on_disconnect_gen
    ## @param filter The LDAP query send to the server
    ## @param retrieve_attributes The list of attributes that should be fetched. If None, all are fetched.
    ## @param base The base dn from where the search starts in the LDAP tree
    ## @param scope The search scope in the LDAP tree
    ## @return string[]
    def query(self, filter="(objectClass=*)", retrieve_attributes=None, base=None,
                scope=ldap.SCOPE_SUBTREE):
        """
        Convencience wrapper arround python-ldap internal search
        """
        if base == None:
            base = self._base
        _filter = _encode_utf8(filter)
        result_id = self._lo.search(base, scope, _filter, retrieve_attributes)
        while 1:
            result_type, result_data = self._lo.result(result_id, self._timeout)
            if (result_data == []):
                break
            else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                    yield result_data[0]

    @_retry_on_disconnect
    ## @param dn The DN of which the password should be changed
    ## @param password The new password
    ## @return None
    def set_password(self, dn, password):
        """
        Change the password of a user.

        This issues a LDAP Password Modify Extended Operation.
        """
        _dn = _encode_utf8(dn)
        _password = _encode_utf8(password)
        # Issue a LDAP Password Modify Extended Operation
        self._lo.passwd_s(_dn, None, _password)

    ## @param args The arguments supplied which will be passed thru to query()
    ## @param kwargs The keyword arguments supplied which will be passed thru to query()
    ## @return LdapNode[]
    def search(self, *args, **kwargs):
        """
        Like query(), but wraps each object as an LdapNode.
        """
        for dn, attributes_dict in self.query(*args, **kwargs):
            node = LdapNode(self, dn)
            node._load_attributes(attributes_dict)
            yield node

    ## @param dn The DN for which existence should be checked
    ## @return boolean
    def check_if_dn_exists(self, dn):
        """
        Search ldap-server for dn and return a boolean

        >>> ldap_connection.check_if_dn_exists('cn=jack,dc=example,dc=com')
        True
        >>> ldap_connection.check_if_dn_exists('cn=foobar,dc=example,dc=com')
        False
        """
        try:
            res = self.query(base=dn, scope=ldap.SCOPE_BASE)
            if len(list(res)) != 0:
                return True
        except ldap.NO_SUCH_OBJECT:
            return False
        return False

    ## @param dn The DN of the LDAP node which we would like to have mapped into a LdapNode
    ## @return LdapNode
    def get_ldap_node(self, dn):
        """
        Create lazy LdapNode-Object linked to this connection

        >>> ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        <LdapNode: cn=jack,dc=example,dc=com>
        >>> ldap_connection.get_ldap_node('cn=nobody,dc=example,dc=com') # this won't check, if node exists
        <LdapNode: cn=nobody,dc=example,dc=com>
        >>> _.cn
        Traceback (most recent call last):
        NO_SUCH_OBJECT: {'desc': 'No such object'}
        """
        return LdapNode(self, dn)

    ## @param dn The DN of the LDAP node which we would like to have mapped into a LdapNode
    ## @return LdapNode
    def retrieve_ldap_node(self, dn):
        """
        Retrieves the object from that database and wraps it as an LdapNode.

        This is the same as get_ldap_node, except that all attributes
        for this node will be obtained from that database immediately
        instead of lazily.

        It will raise ldap.NO_SUCH_OBJECT if the entry cannot be found.

        >>> ldap_connection.retrieve_ldap_node('cn=jack,dc=example,dc=com')
        <LdapNode: cn=jack,dc=example,dc=com>
        >>> ldap_connection.retrieve_ldap_node('cn=nobody,dc=example,dc=com')
        Traceback (most recent call last):
        NO_SUCH_OBJECT: {'desc': 'No such object'}
        """
        node = LdapNode(self, dn)
        node.retrieve_attributes()
        return node

    ## @param dn The DN of the newly created LdapNode
    ## @return LdapNode
    def new_ldap_node(self, dn):
        """
        Create new LdapNode-Object linked to this connection

        >>> node = ldap_connection.new_ldap_node('cn=newuser,dc=example,dc=com')
        >>> node.objectClass = ['person']
        >>> node.sn = 'Daniel'
        >>> node.cn = 'newuser'
        >>> node.save() # the object is created not until here!
        >>> node = ldap_connection.get_ldap_node('cn=newuser,dc=example,dc=com')
        >>> unicode(node.sn)
        u'Daniel'
        >>> unicode(node.cn)
        u'newuser'
        """
        return LdapNode(self, dn, new=True)


class LdapAttribute(object):
    """
        Holds an set of LDAP-Attributes with the same name.
        All changes are recorded, so they can be push to ldap_modify
        directly
    """

    def __init__(self, name, value, add=False):
        self._name = unicode(name)
        self._replace_all = False
        self._changes = []
        if add:
            self._values = []
            if type(value) == list:
                for v in value:
                    self.append(v)
            else:
                self.append(value)
        else:
            if type(value) == list:
                self._values = value
            else:
                self._values = [unicode(value)]

    def __len__(self):
        return len(self._values)

    def __unicode__(self):
        "if there's only one item, return it directly"
        if len(self._values) == 1:
            return self._values[0]
        return unicode(self._values)

    def __repr__(self):
        return "<LdapAttribute: %s=%s>" % (self._name, self.__unicode__())

    def append(self, value):
        "add an attribute"
        if not value in self._values:
            self._values.append(unicode(value))
            self._changes.append((ldap.MOD_ADD, self._name, unicode(value)))

    def remove(self, value):
        "remove an attribute"
        if unicode(value) in self._values:
            self._values.remove(unicode(value))
            self._changes.append((ldap.MOD_DELETE, self._name, unicode(value)))

    def __contains__(self, item):
        return self._values.__contains__(item)

    def __getitem__(self, key):
        return self._values[key]

    def __setitem__(self, key, value):
        self._replace_all = True
        self._values[key] = unicode(value)

    def __delitem__(self, key):
        self._replace_all = True
        self._values.remove(key)

    def __iter__(self):
        return self._values.__iter__()

    def set_value(self, value):
        "set single value, discard all existing ones"
        if type(value) == list:
            self._values = [unicode(x) for x in value]
        else:
            self._values = [unicode(value)]
        self._replace_all = True

    def get_change_list(self):
        "get all changes to this attribute in ldap_modify-syntax"
        if self._replace_all:
            if len(self) == 0:
                return [(ldap.MOD_DELETE, self._name, None)]
            change_list = [ (ldap.MOD_REPLACE, self._name, x) for x in self._values[0:1]]
            change_list += [ (ldap.MOD_ADD, self._name, x) for x in self._values[1:] ]
            return change_list
        return self._changes

    def discard_change_list(self):
        "called when attribute-changes were successfully saved"
        self._changes = []
        self._replace_all = False


class LdapNode(object):
    """
        Holds an ldap-object represented by the dn (distinguishable name).
        attributes are fetched from ldapserver lazily, so you can create objects
        without network traffic.
    """

    def __init__(self, conn, dn, new=False):
        "Create lazy Node Object from dn"
        self._conn = conn
        self._dn = unicode(dn)
        self._valid = True
        self._to_delete = []
        self._new = new
        if new:
            self._attr = {}
        else:
            self._attr = None

    def retrieve_attributes(self):
        """Retrieves the node's attributes from the database.

        Attributes are usually loaded lazily (the first time they're accessed),
        but you can use this method to force this to happen now.
        """
        _dn, attributes_dict = list(self._conn.query(base=self._dn, scope=ldap.SCOPE_BASE))[0]
        self._load_attributes(attributes_dict)

    def _load_attributes(self, attributes_dict):
        self._attr = dict([
            (attr_name, LdapAttribute(attr_name, attr_values))
                for attr_name, attr_values in attributes_dict.items()
        ])

    def __getattr__(self, name):
        """
            get an ldap-attribute
            * attributes starting with is_* are mapped to a check, if the objectClass is present
        """
        if self._attr == None:
            self.retrieve_attributes()
        if name.startswith("is_"):
            return name[3:] in self._attr[u"objectClass"]
        if name in self._attr:
            return self._attr[name]
        raise AttributeError('Cannot find attribute %s' % name)

    def __setattr__(self, name, value):
        "set ldap attribute"
        # handle private attributes the default way
        if name.startswith("_"):
            return object.__setattr__(self, name, value)
        if self._attr == None:
            self.retrieve_attributes()
        if name in self._attr:
            self._attr[name].set_value(value)
        else:
            self._attr[name] = LdapAttribute(name, value, add=True)

    def __delattr__(self, name):
        if self._attr == None:
            self.retrieve_attributes()
        del self._attr[name]
        self._to_delete.append(name)

    def __unicode__(self):
        return self._dn

    def __str__(self):
        return self._dn.encode("utf-8")

    def __repr__(self):
        return "<LdapNode: %s>" % self._dn

    def save(self):
        """Save any changes to the object"""
        if self._attr == None:
            # No changes yet
            return
        if self._new:
            change_list = [ (_encode_utf8(x._name), [_encode_utf8(y) for y in x]) for x in self._attr.values() ]
            if LDAPOM_VERBOSE:  # pragma: no cover
                print "ldap_add: %s" % change_list
            self._conn.add(_encode_utf8(self._dn), change_list)
        else:
            change_list = [ (ldap.MOD_DELETE, _encode_utf8(x), None) for x in self._to_delete ]
            for attr in self._attr.values():
                change_list.extend([(x, _encode_utf8(y), _encode_utf8(z)) for (x,y,z) in attr.get_change_list()])
            if len(change_list) == 0:
                return
            if LDAPOM_VERBOSE:  # pragma: no cover
                print "ldap_modify: %s" % change_list
            self._conn.modify(_encode_utf8(self._dn), change_list)
        self._new = False
        self._to_delete = []
        for attr in self._attr.values():
            attr.discard_change_list()

    def delete(self):
        """
        delete this object in ldap

        >>> ldap_connection.check_if_dn_exists('cn=jack,dc=example,dc=com')
        True
        >>> node = ldap_connection.get_ldap_node('cn=jack,dc=example,dc=com')
        >>> node.delete()
        >>> ldap_connection.check_if_dn_exists('cn=jack,dc=example,dc=com')
        False
        """
        self._conn.delete(_encode_utf8(self._dn))
        self._valid = False

    def check_password(self, password):
        """
        check password for this ldap-object

        >>> jack_node.check_password('jack')
        True
        >>> jack_node.check_password('wrong_pw')
        False
        """
        return self._conn.authenticate( _encode_utf8(self._dn), _encode_utf8(password) )

    def set_password(self, password):
        """
        set password for this ldap-object immediately

        >>> jack_node.set_password('asdfä')
        >>> jack_node.check_password('asdfä')
        True
        """
        # Issue a LDAP Password Modify Extended Operation
        self._conn.set_password(_encode_utf8(self._dn), _encode_utf8(password))

# vim: ai sw=4 expandtab

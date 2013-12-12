# -*- coding: utf-8 -*-
"""Types for LDAP attributes."""

from __future__ import unicode_literals
from __future__ import print_function

from ldapom import compat


class LDAPEntry(compat.UnicodeMixin, object):
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
                set([a.name for a in attributes]) if attributes else set())

    ## Expose dn as a ready-only property
    dn = property(lambda self: self._dn)
    rdn = property(lambda self: self.dn.split(",")[0])
    parent_dn = property(lambda self: ",".join(self.dn.split(",")[1:]))

    def fetch(self):
        """Fetch this entry's attributes from the LDAP server."""
        return self._connection.fetch(self)

    def _fetch_attributes_if_exists(self):
        """Fetch this entry's attributes from the LDAP server if it exists.

        If it doesn't exist, simply use an empty set as attributes.
        """
        if self.attributes is not None:
            return

        if self.exists():
            self.fetch()
        else:
            self.attributes = set()

    def exists(self):
        """Checks if this entry exists on the LDAP server."""
        return self._connection.exists(self)

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
        self._fetch_attributes_if_exists()

        if name.startswith("is_"):
            return name[3:] in self.get_attribute("objectClass").values

        attribute_type = self._connection.get_attribute_type(name)
        attribute = self.get_attribute(name)
        if attribute is not None:
            if attribute.single_value:
                return attribute.value
            else:
                return attribute.values
        else:
            if attribute_type.multi_value:
                setattr(self, name, set())
                return self.get_attribute(name).values
            else:
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

        self._fetch_attributes_if_exists()

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
                attribute.values = set(value)
            else:
                attribute.values = {value}

    def __delattr__(self, name):
        self._fetch_attributes_if_exists()
        attribute = self.get_attribute(name)
        if attribute is not None:
            self.attributes.remove(attribute)

    def __unicode__(self):
        return self.dn

    def __repr__(self):
        return self.__str__()

    def delete(self, *args, **kwargs):
        """Delete this entry on the LDAP server."""
        return self._connection.delete(self, *args, **kwargs)

    def rename(self, *args, **kwargs):
        """Rename this entry on the LDAP server."""
        return self._connection.rename(self, *args, **kwargs)

    def save(self, *args, **kwargs):
        """Save this entry and its attribute values to the LDAP server."""
        return self._connection.save(self, *args, **kwargs)

    def set_password(self, password):
        """Change the password for this LDAP entry.

        :param password: The password to set
        :type password: str
        """
        return self._connection.set_password(self, password)

    def can_bind(self, bind_password):
        """Try to bind with the given credentials.

        :param bind_password: Password to bind with.
        :type bind_password: str
        :rtype: boolean
        """
        return self._connection.can_bind(self.dn, bind_password)

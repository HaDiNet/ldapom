# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import print_function


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


class LDAPAttributeNameNotFoundError(LDAPomError):
    pass

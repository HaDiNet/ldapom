"""Utility functions to abstract Python version differences."""

import sys


class UnicodeMixin(object):
  """Mixin class to handle defining the proper __str__/__unicode__
  methods in Python 2 or 3."""

  if sys.version_info[0] >= 3: # Python 3
      def __str__(self):
          return self.__unicode__()
  else:  # Python 2
      def __str__(self):
          return self.__unicode__().encode('utf8')


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


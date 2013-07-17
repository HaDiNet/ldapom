# LDAPom

LDAPom is a pythonic LDAP to Python object mapper. It should work with Python 2.7 and all versions of Python 3.

## Testing

Because LDAPom uses a real LDAP server for testing, OpenLDAP is required to be
installed (i.e. `slapd` and `slapadd` have to be in `$PATH`).

	# Install development dependencies
	pip install -r dev-requirements.txt
	# Run the tests
	python tests.py

## A note about Unicode strings in Python 2

LDAPom is source-code compatible with both Python 2 and Python 3. However,
LDAPom expects unicode strings to be passed to it whenever a string is
required.

For Python 2, this means that you should use the `unicode` type for `str`-type
arguments and the `str`/`bytes` type for `bytes`-type arguments.

In Python 3, everything is exactly as you would expect. `str` for strings,
`bytes` for binary data. Simple, really.

## License

LDAPom is licensed under the MIT license. For more information, see the `COPYING` file.


# `mk-jwks` and `mk-jwks.py`
Both of these commands create the JSON to use in a JWKs.

`mk-jwks cert.pem` is the golang implementation. It is the more tested of the two

`mk-jwks.py cert.pem` is in Python3 and is less tested but relys in a proper library

They create different `kid` values and the python one doesn't produce an `x5c`

# *These tools are completely unsupported, use at your own risk*

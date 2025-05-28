# `mk-jwks` and `mk-jwks.py`
Both of these commands create the JSON to use in a JWKs.

`mk-jwks cert1.pem cert2.pem ...` is the golang implementation. It is the more tested of the two

`mk-jwks.py cert1.pem cert2.pem ...` is in Python3 and is less tested but relys on a library which will be very well tested

They create different `kid` values and the python one doesn't produce an `x5c`

# *These tools are completely unsupported, use at your own risk*

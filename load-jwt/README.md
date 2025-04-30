# load-jwt
`load-jwt` is a simple load testing tool to load a JWT authenticated API

Flags are:

`--cert` file containing a PEM format RSA certificate

`--key` file containing the PEM format private key for the certificate

`--claims` JSON file containing the claims to put into the body of the JWT

`--url` the URL of the API

## Notes:
These are added to the claims JSON

`iat`, the current unix epoch second

`sub`, the current unix epoch nanosecond (To keep the value close to unique)

# *These tools are completely unsupported, use at your own risk*

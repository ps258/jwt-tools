# jwt-tools
Home made tools for various JWT related tasks

+ `check-jwt` Checks the given JWT against the given JWKs
+ `jwt-decode` a simple shell script to decode JWTs from the command line
+ `load-jwt` generates JWTs on the fly and loads a JWT authenticated API
+ `mk-jwt` generates JWTs but is more flexible in their creation. Can be combined with another tools to load an API

Several of these will only work with RSA certificates. `mk-jwt` will also work with EC certs but that is not fully tested

# *These tools are completely unsupported, use at your own risk*

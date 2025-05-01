# `mk-jwt`

`mk-jwt` will create a jwt based on the options given

````
Usage of mk-jwt:
  -cert string
        The x509 RSA public certificate (default "cert.pem")
  -claims string
        A file of claims in json format (default "claims.json")
  -exp string
        Duration for JWT expiration (e.g., '1h', '30m', '24h')
  -iat-offset int
        Offset for IssuedAt time in seconds (can be positive or negative)
  -key string
        The RSA private key (default "key.pem")
  -policy string
        The policy to put in the 'pol' claim
  -random
        Set a random 'sub' claim
  -subject string
        The subject to put in the 'sub' claim
  -verbose
        Print more messages
````

It has more options that `load-jwt` so is more flexible in the JWTs it can make

# *These tools are completely unsupported, use at your own risk*

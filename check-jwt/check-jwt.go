package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt"
	//"github.com/lestrrat-go/jwx/v2/jws"

	//"github.com/lestrrat/go-jwx/jwk"
	"github.com/lestrrat-go/jwx/v2/jwk"
	ljwt "github.com/lestrrat-go/jwx/v2/jwt"
)

var tokenString, jwksURL *string

func getKey(token *jwt.Token) (interface{}, error) {

	// TODO: cache response so we don't have to make a request every time
	// we want to verify a JWT
	set, err := jwk.Fetch(context.Background(), *jwksURL)
	if err != nil {
		return nil, err
	}

	// msg, err := jws.Parse([]byte(token.Raw))
	keyID, err := ljwt.ParseString(token.Raw, ljwt.WithKeySet(set))
	if err != nil {
		return nil, errors.New("expecting JWT header to have string kid")
	} else {
		return keyID, nil
	}

	/* keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}

	if key := set.LookupKeyID(keyID); len(key) == 1 {
		return key[0].Materialize()
	}

	return nil, errors.New("unable to find key") */
}

func main() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	tokenString = flag.String("token", "", "JWT token to verify")
	jwksURL = flag.String("jwksURL", "", "URL of the JWKS service to retrive the key from")
	flag.Parse()
	if *tokenString == "" || *jwksURL == "" {
		log.Fatal("Must speficy both --jwksURL and --token")
		os.Exit(1)
	}

	token, err := jwt.Parse(*tokenString, getKey)
	if err != nil {
		panic(err)
	}
	claims := token.Claims.(jwt.MapClaims)
	for key, value := range claims {
		fmt.Printf("%s\t%v\n", key, value)
	}
}

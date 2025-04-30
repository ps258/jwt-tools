package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

var (
	errKeyMustBePEMEncoded = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	errNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
	errNotRSAPublicKey     = errors.New("Key is not a valid RSA public key")
)

func parseRSAPrivateKeyFromPEM(key []byte) (*rsa.PrivateKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		fmt.Println("ErrKeyMustBePEMEncoded", errKeyMustBePEMEncoded)
		return nil, errKeyMustBePEMEncoded
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	var pkey *rsa.PrivateKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errNotRSAPrivateKey
	}

	return pkey, nil
}

func parseRSAPrivateKeyFromFile(rsaPrivateKeyLocation string) (*rsa.PrivateKey, error) {
	priv, err := ioutil.ReadFile(rsaPrivateKeyLocation)
	if err != nil {
		fmt.Println("No RSA private key found: ", err)
		return nil, err
	}
	return parseRSAPrivateKeyFromPEM(priv)
}

func parseRSAPublicKeyFromPEM(key []byte) (*rsa.PublicKey, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errKeyMustBePEMEncoded
	}

	// Parse the key
	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			parsedKey = cert.PublicKey
		} else {
			return nil, err
		}
	}

	var pkey *rsa.PublicKey
	var ok bool
	if pkey, ok = parsedKey.(*rsa.PublicKey); !ok {
		return nil, errNotRSAPublicKey
	}

	return pkey, nil
}

func parseRSAPublicKeyFromFile(rsaPublicKeyLocation string) (*rsa.PublicKey, error) {
	pub, err := ioutil.ReadFile(rsaPublicKeyLocation)
	if err != nil {
		fmt.Println("No RSA public key found: ", err)
		os.Exit(1)
	}
	return parseRSAPublicKeyFromPEM(pub)
}

func parseRSACertFromPEM(key []byte) (*x509.Certificate, error) {
	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, errKeyMustBePEMEncoded
	}

	// Parse the cert from the PEM block
	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		return cert, nil
	} else {
		return nil, err
	}
}

func parseRSACertFromFile(rsaCertKeyLocation string) (*x509.Certificate, error) {
	cert, err := ioutil.ReadFile(rsaCertKeyLocation)
	if err != nil {
		fmt.Println("No RSA private key found: ", err)
		return nil, err
	}
	return parseRSACertFromPEM(cert)
}

func parseJSONFromFIle(claimsFile string) (map[string]interface{}, error) {
	jsonClaimsFile, err := os.Open(claimsFile)
	if err != nil {
		return nil, err
	}
	defer jsonClaimsFile.Close()
	jsonByteValue, _ := ioutil.ReadAll(jsonClaimsFile)
	var jsonClaims map[string]interface{}
	json.Unmarshal([]byte(jsonByteValue), &jsonClaims)
	return jsonClaims, nil
}

func createJwt(certFile, keyFile, claimsFile string) string {
	cert, _ := parseRSACertFromFile(certFile)
	json, _ := parseJSONFromFIle(claimsFile)

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.KeyIDKey, cert.SerialNumber.String())

	s := jwt.New()
	s.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
	s.Set(jwt.AudienceKey, `Golang Users`)
	s.Set(jwt.IssuedAtKey, time.Now().Unix)
	s.Set("sub", strconv.FormatInt(time.Now().UnixNano(), 10))
	for jsonKey, jsonValue := range json {
		s.Set(jsonKey, jsonValue)
	}

	privkey, err := parseRSAPrivateKeyFromFile(keyFile)
	if err != nil {
		log.Printf("Failed to load private key from %s: %s", keyFile, err)
		return ""
	}

	signed, err := jwt.Sign(s, jwa.RS256, privkey, jwt.WithHeaders(hdrs))
	if err != nil {
		log.Printf("Failed to created JWS message: %s", err)
		return ""
	}
	return string(signed)
}

func main() {
	cert := flag.String("cert", "cert.pem", "The x509 RSA public certificate")
	key := flag.String("key", "key.pem", "The RSA private key")
	claims := flag.String("claims", "claims.json", "A file of claims in json format")
	url := flag.String("url", "https://httpbin.org/anything/fred", "The URL to call")
	//jwks := flag.String("jwks", "http://localhost:8080/jwks.json", "The matching JWKS to the cert and key")
	flag.Parse()
	fmt.Println("Here")
	if *cert == "" || *key == "" {
		fmt.Println("Must provide --cert, --key, --claims")
		os.Exit(1)
	}
	client := &http.Client{}
	req, _ := http.NewRequest("GET", *url, nil)

	for i := 1; i < 25000; i++ {
		jwt := createJwt(*cert, *key, *claims)
		//fmt.Println(jwt)
		req.Header.Set("Authorization", jwt)
		//req, _ := http.NewRequest("GET", url, nil)
		res, err := client.Do(req)
		if err != nil {
			fmt.Printf("%s\n", res.Status)
			log.Fatalln(err)
		} else {
			defer res.Body.Close()
			body, _ := io.ReadAll(res.Body)
			fmt.Print(strconv.Itoa(i) + " " + string(body))
		}
	}
}

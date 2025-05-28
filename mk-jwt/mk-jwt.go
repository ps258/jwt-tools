package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
)

//const aLongLongTimeAgo = 233431200

var (
	errKeyMustBePEMEncoded = errors.New("Invalid Key: Key must be PEM encoded PKCS1 or PKCS8 private key")
	errNotRSAPrivateKey    = errors.New("Key is not a valid RSA private key")
	errNotRSAPublicKey     = errors.New("Key is not a valid RSA public key")
	verbose                = false
	randomSub              = false
	policy                 *string
	subject                *string
	expiry                 *string
	iatOffset              *int
)

// checkFileExists verifies that a file exists and is readable
func checkFileExists(filename string) error {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %s", filename)
	} else if err != nil {
		return fmt.Errorf("cannot access file %s: %v", filename, err)
	}
	return nil
}

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
		fmt.Println("No RSA certificate found: ", err)
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

func createJwt(certFile, keyFile, claimsFile string) {
	cert, err := parseRSACertFromFile(certFile)
	json, err := parseJSONFromFIle(claimsFile)

	hdrs := jws.NewHeaders()
	hdrs.Set(jws.KeyIDKey, cert.SerialNumber.String())
	if verbose {
		log.Printf("Serial number: %s, %v", cert.SerialNumber.String(), err)
	}

	s := jwt.New()
	s.Set(jwt.SubjectKey, `https://github.com/lestrrat-go/jwx/jwt`)
	s.Set(jwt.AudienceKey, `Golang Users`)
	now := time.Now()
	s.Set(jwt.IssuedAtKey, now.Add(time.Duration(*iatOffset)*time.Second).Unix())
	s.Set(jwt.JwtIDKey, uuid.New().String())

	// Set expiration time if provided
	if *expiry != "" {
		duration, err := time.ParseDuration(*expiry)
		if err != nil {
			log.Printf("Failed to parse expiry duration: %s", err)
			return
		}
		expiryTime := now.Add(duration)
		if verbose {
			log.Printf("Setting expiry time to: %s", expiryTime)
		}
		s.Set(jwt.ExpirationKey, expiryTime.Unix())
	}
	for jsonKey, jsonValue := range json {
		s.Set(jsonKey, jsonValue)
	}
	// commandline options overrid the contents of the claims file
	if randomSub {
		s.Set("sub", uuid.New().String())
	}
	if *policy != "" {
		s.Set("pol", *policy)
	}
	// --subject commandline overrides both the claims file and the --random
	if *subject != "" {
		s.Set("sub", *subject)
	}

	privkey, err := parseRSAPrivateKeyFromFile(keyFile)
	if err != nil {
		log.Printf("Failed to load private key from %s: %s", keyFile, err)
		return
	}

	signed, err := jwt.Sign(s, jwa.RS256, privkey, jwt.WithHeaders(hdrs))
	if err != nil {
		log.Printf("Failed to created JWS message: %s", err)
		return
	}
	pubkey := cert.PublicKey.(*rsa.PublicKey)

	if verbose {
		fmt.Println("Signed jws with certificate in ", certFile)
	}
	fmt.Println(string(signed))
	if verbose {
		fmt.Println("")
	}

	token, err := jwt.Parse(signed, jwt.WithVerify(jwa.RS256, pubkey))
	if err != nil {
		panic(err)
	}
	if verbose {
		fmt.Println("Private claims:")
		for key, value := range token.PrivateClaims() {
			fmt.Printf("%s\t->\t%v\n", key, value)
		}
		fmt.Println("All claims:")
		// seriously??? This is what you have to do to get a list of claims?
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		for iter := token.Iterate(ctx); iter.Next(ctx); {
			pair := iter.Pair()
			fmt.Printf("%s -> %v\n", pair.Key, pair.Value)
		}
	}

	// When you received a JWS message, you can verify the signature
	// and grab the payload sent in the message in one go:
	verified, err := jws.Verify(signed, jwa.RS256, *pubkey)
	if err != nil {
		log.Printf("Failed to verify message: %s", err)
		return
	}
	if verbose {
		fmt.Printf("\nSigned message verified! -> %s\n", verified)
	}
}

func main() {
	cert := flag.String("cert", "", "The x509 RSA public certificate")
	key := flag.String("key", "", "The RSA private key")
	claims := flag.String("claims", "", "A file of claims in json format")
	policy = flag.String("policy", "", "The policy to put in the 'pol' claim")
	subject = flag.String("subject", "", "The subject to put in the 'sub' claim")
	expiry = flag.String("exp", "", "Duration for JWT expiration (e.g., '1h', '30m', '24h')")
	iatOffset = flag.Int("iat-offset", 0, "Offset for IssuedAt time in seconds (can be positive or negative)")
	flag.BoolVar(&randomSub, "random", false, "Set a random 'sub' claim")
	flag.BoolVar(&verbose, "verbose", false, "Print more messages")
	flag.Parse()
	if *cert == "" || *key == "" {
		fmt.Println("Must provide --cert, --key, --claims")
		os.Exit(1)
	}

	// Check that all required files exist before proceeding
	if err := checkFileExists(*cert); err != nil {
		fmt.Printf("Certificate file error: %v\n", err)
		os.Exit(1)
	}

	if err := checkFileExists(*key); err != nil {
		fmt.Printf("Private key file error: %v\n", err)
		os.Exit(1)
	}

	if err := checkFileExists(*claims); err != nil {
		fmt.Printf("Claims file error: %v\n", err)
		os.Exit(1)
	}

	createJwt(*cert, *key, *claims)
}

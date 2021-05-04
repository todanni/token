package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/stretchr/testify/assert"
)

func Test_TokenGeneration(t *testing.T) {
	// Generate RSA keys for JWT signing
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	publickey := &privatekey.PublicKey
	//issuer := "todanni-account-service"

	token := jwt.New()
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour*24).Unix())
	token.Set(jwt.IssuerKey, Issuer)
	token.Set("uid", 1234)
	token.Set("email", "test@mail.com")

	signed, err := jwt.Sign(token, jwa.RS256, privatekey)
	assert.NoError(t, err)

	parsed, err := jwt.Parse(signed, jwt.WithValidate(true), jwt.WithVerify(jwa.RS256, publickey))
	assert.NoError(t, err)
	assert.Equal(t, parsed.Issuer(), Issuer)

	buf, err := json.MarshalIndent(parsed, "", "  ")
	assert.NoError(t, err)
	fmt.Printf("%s\n", string(buf))
}

func Test_JWKGeneration(t *testing.T) {
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	jwkKey, err := jwk.New(privatekey)
	assert.NoError(t, err)
	jwkKey.Set(jwk.KeyIDKey, "mykey")

	buf, err := json.MarshalIndent(jwkKey, "", "  ")
	assert.NoError(t, err)
	fmt.Printf("%s\n", buf)
}

func Test_JWKVerification(t *testing.T) {
	// Generate RSA key
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Generate JWK
	jwkKey, err := jwk.New(privatekey)
	assert.NoError(t, err)
	jwkKey.Set(jwk.KeyIDKey, "mykey")

	// Generate JWT and sign with JWK
	token := jwt.New()
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour*24).Unix())
	token.Set(jwt.IssuerKey, Issuer)
	token.Set("uid", 1234)
	token.Set("email", "test@mail.com")

	// Sign with JWK
	signed, err := jwt.Sign(token, jwa.RS256, jwkKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, signed)

	// Validate JWT with JWK
	pubKey, err := jwk.New(privatekey.PublicKey)
	assert.NoError(t, err)
	pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	pubKey.Set(jwk.KeyIDKey, "mykey")

	var keyset jwk.Set
	keyset = jwk.NewSet()
	keyset.Add(pubKey)

	// Parse
	parsed, err := jwt.Parse(signed, jwt.WithKeySet(keyset), jwt.WithValidate(true))
	assert.NoError(t, err)
	assert.Equal(t, parsed.Issuer(), Issuer)
}

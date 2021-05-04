package token

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/thanhpk/randstr"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/todanni/authentication/pkg/account"
)

const (
	Issuer = "todanni-account-service"
)

func Generate(key jwk.Key, acc account.AuthDetails) ([]byte, error) {
	token := jwt.New()
	token.Set(jwt.ExpirationKey, time.Now().Add(time.Hour*24).Unix())
	token.Set(jwt.IssuerKey, Issuer)
	token.Set("account_id", acc.AccountID)
	token.Set("email", acc.Email)
	token.Set("verified", acc.Verified)

	signed, err := jwt.Sign(token, jwa.RS256, key)
	if err != nil {
		return []byte{}, err
	}

	return signed, err
}

func Validate(token jwt.Token, set jwk.Set) (bool, error) {

	return false, errors.New("")
}

func GeneratePrivateJWK(key rsa.PrivateKey) error {
	jwkKey, err := jwk.New(key)
	jwkKey.Set(jwk.KeyIDKey, randstr.Hex(10))
	return err
}

func GeneratePublicJWK(key rsa.PrivateKey) error {
	pubKey, err := jwk.New(key.PublicKey)
	if err != nil {
		return err
	}
	pubKey.Set(jwk.AlgorithmKey, jwa.RS256)
	pubKey.Set(jwk.KeyIDKey, "mykey")
	return err
}

func GenerateJWK() (privateJWK, publicJWK jwk.Key, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	privateJWK, err = jwk.New(privateKey)
	if err != nil {
		return nil, nil, err
	}

	publicJWK, err = jwk.New(privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	return privateJWK, publicJWK, nil
}

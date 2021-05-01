package token

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

const (
	Issuer = "todanni"
	KeyURL = "http://todanni/jwt/public-key"
)

type ToDanniClaims struct {
	UserID     int    `json:"user_id"`
	Email      string `json:"email"`
	ProfilePic string `json:"profile_pic"`

	jwt.StandardClaims
}

func Generate(userID int, email, profilePic, signingKey string) (string, error) {
	claims := ToDanniClaims{
		UserID:     userID,
		Email:      email,
		ProfilePic: profilePic,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "todanni-account-service",
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	ss, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", err
	}

	return ss, nil
}

func Validate(tokenString, signingKey string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenString, &ToDanniClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signingKey), nil
	})
	if err != nil {
		return false, err
	}
	return token.Valid, err
}

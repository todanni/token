package token

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

const (
	Issuer = "todanni-account-service"

	//TODO: figure out how to store these for local testing
	JWKURL   = "http://token-issuer/api/token/public-key"
	TokenURL = "http://token-issuer/api/token?uid=%d"
)

func Generate(uid int, client http.Client, url string) ([]byte, error) {
	resp, err := client.Get(fmt.Sprintf("%/?uid=%d", url, uid))
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, err
	}
	tokenBytes, err := io.ReadAll(resp.Body)

	return tokenBytes, err
}

func Validate(tokenBytes []byte, ctx context.Context) (uid int, err error) {
	autoRefresh := jwk.NewAutoRefresh(ctx)
	autoRefresh.Configure(JWKURL, jwk.WithMinRefreshInterval(time.Second*30))

	keySet, err := autoRefresh.Fetch(ctx, JWKURL)
	if err != nil {
		return 0, err
	}

	buf, err := json.Marshal(keySet)
	log.Printf("%s", buf)

	parsed, err := jwt.Parse(tokenBytes, jwt.WithKeySet(keySet), jwt.WithValidate(true))
	if err != nil {
		return 0, err
	}

	userID, ok := parsed.Get("uid")
	// Some dank hacks to make this not a float
	// https://tanaikech.github.io/2017/06/02/changing-from-float64-to-int-for-values-did-unmarshal-using-mapstringinterface/
	uid = int(userID.(float64))
	if ok != true {
		return 0, err
	}

	return uid, nil
}

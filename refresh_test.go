package token

import (
	"context"
	"encoding/json"
	"log"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
)

func Test_JWKRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const jwkURL = "http://localhost:8080/api/token/public-key"
	autoRefresh := jwk.NewAutoRefresh(ctx)
	autoRefresh.Configure(jwkURL, jwk.WithMinRefreshInterval(time.Second*30))

	s, err := autoRefresh.Refresh(ctx, jwkURL)
	assert.NoError(t, err)

	jsonbuf, err := json.Marshal(s)
	assert.NoError(t, err)
	log.Printf("%s", jsonbuf)

	for {
		select {
		case <-ctx.Done():
			log.Println("Done")
			break
		default:
		}
		// Fetch from cache if it hasn't expired
		keySet, err := autoRefresh.Fetch(ctx, jwkURL)
		assert.NoError(t, err)

		buf, err := json.Marshal(keySet)
		assert.NoError(t, err)
		log.Printf("%s", buf)
		time.Sleep(time.Second)
	}
}

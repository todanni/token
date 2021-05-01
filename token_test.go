package token

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_GenerateAndValidate(t *testing.T) {
	// Setup
	key := "PGQpL7zNgYrCFUPfHkvG"

	// Execute
	token, err := Generate(1, "test@email.com", "http://imgur.com", key)
	assert.NoError(t, err)

	isValid, err := Validate(token, key)
	assert.NoError(t, err)
	assert.Equal(t, true, isValid)
}

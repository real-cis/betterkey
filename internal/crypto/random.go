package crypto

import (
	"crypto/rand"
	"io"

	"github.com/hashicorp/go-uuid"
)

func GenerateNonce(len int) []byte {
	randomBytes := make([]byte, len)
	_, err := io.ReadFull(rand.Reader, randomBytes)
	if err != nil {
		panic(err)
	}
	return randomBytes
}

func GenerateUUID() string {
	id, err := uuid.GenerateUUID()
	if err != nil {
		panic(err)
	}
	return id
}

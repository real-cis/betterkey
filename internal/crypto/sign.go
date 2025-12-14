package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"
)

type ECDSASignature struct {
	R, S *big.Int
}

func ECDSASign(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// DER encode the signature
	signature := ECDSASignature{R: r, S: s}
	derBytes, err := asn1.Marshal(signature)
	if err != nil {
		return nil, fmt.Errorf("DER encoding failed: %w", err)
	}

	return derBytes, nil
}

func ECDSAVerify(publicKey *ecdsa.PublicKey, data []byte, signatureDER []byte) (bool, error) {
	hash := sha256.Sum256(data)
	var sig ECDSASignature
	_, err := asn1.Unmarshal(signatureDER, &sig)
	if err != nil {
		return false, fmt.Errorf("DER decoding failed: %w", err)
	}

	valid := ecdsa.Verify(publicKey, hash[:], sig.R, sig.S)
	return valid, nil
}

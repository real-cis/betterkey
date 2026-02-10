package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
	"gitlab.com/real-cis/cc/betterkey/pkg/aes"
	"gitlab.com/real-cis/cc/betterkey/pkg/api"
)

type KeyGenService interface {
	DeriveHKDF(id string, data []byte, context api.Context) (string, error)
	DeriveX25519(id string, data []byte, context api.Context) (*crypto.KeyPair, error)
	DeriveECDSA(id string, data []byte, context api.Context, curve elliptic.Curve, length int) (*crypto.KeyPair, error)
	SignWithECDSA(req api.SigningRequest) (*api.SigningResponse, error)
	CreateRSA(id string) (*crypto.KeyPair, error)
	RemoveRSA(id string) error
	TDXSeal(req api.TdxSealRequest) (*api.TdxSealResponse, error)
}

type VaultKeyService struct {
	vault         common.Vault
	keyStore      common.BaseKeyStore
	contextPrefix string
}

func NewKeyGenService(vault common.Vault, keyStore common.BaseKeyStore, devMode bool) KeyGenService {
	contextPrefix := ""
	if devMode {
		contextPrefix = "dev-"
	}
	return &VaultKeyService{
		vault:         vault,
		keyStore:      keyStore,
		contextPrefix: contextPrefix,
	}
}

func (v *VaultKeyService) DeriveHKDF(id string, data []byte, context api.Context) (string, error) {
	hkdf, err := v.vault.HKDF(data, fmt.Sprintf("%s-%s-%s", v.contextPrefix, string(context), id), 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(hkdf), nil
}

func (v *VaultKeyService) DeriveX25519(id string, data []byte, context api.Context) (*crypto.KeyPair, error) {
	key, err := v.vault.HKDF(data, fmt.Sprintf("%s-%s-%s", v.contextPrefix, string(context), id), 32)
	if err != nil {
		return nil, err
	}
	return crypto.X25519(key)
}

func (v *VaultKeyService) DeriveECDSA(id string, data []byte, context api.Context, curve elliptic.Curve, length int) (*crypto.KeyPair, error) {
	key, err := v.vault.HKDF(data, fmt.Sprintf("%s-%s-%s", v.contextPrefix, string(context), id), length)
	if err != nil {
		return nil, err
	}
	privateKey, err := crypto.ECDSA(key, curve)
	if err != nil {
		return nil, err
	}
	return pemencodeECKeyPair(privateKey)
}

func (v *VaultKeyService) SignWithECDSA(req api.SigningRequest) (*api.SigningResponse, error) {
	mrtd, err := base64.StdEncoding.DecodeString(req.Mrtd)
	if err != nil {
		return nil, err
	}
	key, err := v.vault.HKDF(mrtd, fmt.Sprintf("%s-%s-%s", v.contextPrefix, string(req.Ctx), req.Id), 32)
	if err != nil {
		return nil, err
	}
	privateKey, err := crypto.ECDSA(key, elliptic.P256())
	if err != nil {
		return nil, err
	}
	signatures := make(map[string]string)
	for msgId, msgBase64 := range req.Messages {
		message, err := base64.StdEncoding.DecodeString(msgBase64)
		if err != nil {
			return nil, err
		}

		signed, err := crypto.ECDSASign(privateKey, message)
		if err != nil {
			return nil, err
		}
		signatures[msgId] = base64.StdEncoding.EncodeToString(signed)
	}

	keyPair, err := pemencodeECKeyPair(privateKey)
	if err != nil {
		return nil, err
	}
	return &api.SigningResponse{Signatures: signatures, PublicKey: keyPair.Public}, nil
}

func (v *VaultKeyService) CreateRSA(id string) (*crypto.KeyPair, error) {
	var key *crypto.KeyPair
	keyId := common.STORE_PREFIX_RSA_KEY + id
	keyBytes, err := v.keyStore.Read(keyId)
	if v.keyStore.HasNil(err) {
		// generate new key, persist to keystore
		key, err = crypto.RSA()
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		v.keyStore.Write(keyId, data)
	} else if err != nil {
		return nil, err
	} else {
		// key exists, parse key
		err = json.Unmarshal(keyBytes, &key)
		if err != nil {
			return nil, err
		}
	}

	return key, nil
}

func (v *VaultKeyService) RemoveRSA(id string) error {
	keyId := common.STORE_PREFIX_RSA_KEY + id
	exists, err := v.keyStore.Exists(keyId)
	if err != nil {
		return err
	} else if exists > 0 {
		return v.keyStore.Delete(keyId)
	}
	return nil
}

func pemencodeECKeyPair(privateKey *ecdsa.PrivateKey) (*crypto.KeyPair, error) {
	privBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	return &crypto.KeyPair{Private: base64.StdEncoding.EncodeToString(privPEM),
		Public: base64.StdEncoding.EncodeToString(pubPEM)}, nil
}

// derives a hash from TDX measurements and boot configuration,
// to be used as a seed for HKDF
func DeriveSeedFromMeasurements(mrtd, cfv []byte) []byte {
	h := sha256.New()
	h.Write(mrtd)
	h.Write(cfv)

	return h.Sum(nil)
}

func (v *VaultKeyService) TDXSeal(req api.TdxSealRequest) (*api.TdxSealResponse, error) {
	// Decode all eventlog parameters from base64
	mrtd, err := base64.StdEncoding.DecodeString(req.Mrtd)
	if err != nil {
		return nil, fmt.Errorf("failed to decode mrtd: %w", err)
	}
	cfv, err := base64.StdEncoding.DecodeString(req.Cfv)
	if err != nil {
		return nil, fmt.Errorf("failed to decode cfv: %w", err)
	}
	payload, err := base64.StdEncoding.DecodeString(req.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	// Derive symmetric key from TDX measurements and boot configuration
	seed := DeriveSeedFromMeasurements(mrtd, cfv)
	key, err := v.vault.HKDF(seed, fmt.Sprintf("%s-%s-%s", v.contextPrefix, string(api.ContextVMBoot), req.Id), 32)
	if err != nil {
		return nil, err
	}

	// Encrypt the payload
	encryptedPayload, err := aes.EncryptAESGCM(key, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt payload: %w", err)
	}

	return &api.TdxSealResponse{
		Id:            req.Id,
		SealedPayload: encryptedPayload,
	}, nil
}

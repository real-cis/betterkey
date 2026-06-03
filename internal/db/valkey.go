package db

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type ValKeyKeyService struct {
	uris        []string
	client      valkey.Client
	transformer func() common.Vault
	namespace   string
}

func NewValKeyKeyService(uris []string, username string, password string, namesapce string, hasTLS bool,
	transformer func() common.Vault) (common.KeyStore, error) {
	var tlsConfig *tls.Config
	if hasTLS {
		tlsConfig = &tls.Config{}
	}
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: uris,
		Username:    username,
		Password:    password,
		TLSConfig:   tlsConfig,
	})
	if err != nil {
		return nil, err
	}
	var kts common.KeyStore = &ValKeyKeyService{
		uris:        uris,
		client:      client,
		transformer: transformer,
		namespace:   namesapce + ":",
	}
	return kts, nil
}

func unseal(s *ValKeyKeyService, res []byte) ([]byte, error) {
	vault := s.transformer()
	if vault == nil {
		return make([]byte, 0), common.ErrNoEncryptionService
	}
	return vault.Unseal(res)
}

func (s *ValKeyKeyService) Read(id string) ([]byte, error) {
	ctx := context.Background()
	compl := s.client.Do(ctx, s.client.B().Hget().Key(s.namespace+id).Field("data").Build())
	resp, err := compl.ToMessage()

	if err != nil {
		return make([]byte, 0), err
	}
	if resp.Error() != nil {
		return make([]byte, 0), resp.Error()
	}

	if resp.IsNil() {
		return make([]byte, 0), nil
	}

	b, err := resp.AsBytes()
	if err != nil {
		return make([]byte, 0), err
	}
	return unseal(s, b)
}

func (s *ValKeyKeyService) Write(id string, value []byte) error {
	return s.WriteWithTTL(id, value, -1)
}

func (s *ValKeyKeyService) WriteWithTTL(id string, value []byte, ttl int) error {
	vault := s.transformer()
	if vault == nil {
		return common.ErrNoEncryptionService
	}
	data, err := vault.Seal(value)
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = s.client.Do(ctx,
		s.client.B().Hset().
			Key(s.namespace+id).FieldValue().
			FieldValue("data", valkey.BinaryString(data)).
			FieldValue("size", strconv.Itoa(len(data))).
			FieldValue("modtime", strconv.FormatInt(time.Now().Unix(), 10)).
			Build()).Error()
	if err != nil {
		return err
	}
	if ttl < 0 {
		return nil
	}
	return s.client.Do(ctx, s.client.B().Expire().Key(s.namespace+id).Seconds(int64(ttl)).Build()).Error()
}

func (s *ValKeyKeyService) WriteNX(id string, value []byte, ttlSeconds int) (bool, error) {
	vault := s.transformer()
	if vault == nil {
		return false, common.ErrNoEncryptionService
	}
	data, err := vault.Seal(value)
	if err != nil {
		return false, err
	}
	ctx := context.Background()
	// HSETNX is atomic: only the first caller creates the "data" field. A lock
	// previously left behind by a crashed node is reclaimed automatically once
	// its TTL lapses and the whole key disappears.
	acquired, err := s.client.Do(ctx,
		s.client.B().Hsetnx().
			Key(s.namespace+id).Field("data").Value(valkey.BinaryString(data)).
			Build()).AsBool()
	if err != nil {
		return false, err
	}
	if !acquired {
		return false, nil
	}
	if err := s.client.Do(ctx,
		s.client.B().Hset().
			Key(s.namespace+id).FieldValue().
			FieldValue("size", strconv.Itoa(len(data))).
			FieldValue("modtime", strconv.FormatInt(time.Now().Unix(), 10)).
			Build()).Error(); err != nil {
		return true, err
	}
	if ttlSeconds > 0 {
		if err := s.client.Do(ctx, s.client.B().Expire().Key(s.namespace+id).Seconds(int64(ttlSeconds)).Build()).Error(); err != nil {
			return true, err
		}
	}
	return true, nil
}

func (s *ValKeyKeyService) Delete(id string) error {
	ctx := context.Background()
	err := s.client.Do(ctx, s.client.B().Del().Key(s.namespace+id).Build()).Error()
	return err
}

func (s *ValKeyKeyService) Exists(id string) (int64, error) {
	ctx := context.Background()
	return s.client.Do(ctx, s.client.B().Exists().Key(s.namespace+id).Build()).AsInt64()
}

func (s *ValKeyKeyService) List(prefix string, recursive bool) ([]string, error) {
	ctx := context.Background()
	pattern := prefix + "*"
	return s.client.Do(ctx, s.client.B().Keys().Pattern(pattern).Build()).AsStrSlice()
}

func (s *ValKeyKeyService) Stat(id string) (*common.StorageStat, error) {
	ctx := context.Background()
	res, err := s.client.Do(ctx,
		s.client.B().Hmget().Key(s.namespace+id).Field("size").Field("modtime").Build(),
	).AsStrSlice()
	if err != nil {
		return nil, err
	}

	if len(res) != 2 {
		return nil, fmt.Errorf("expected 2 fields but got %d", len(res))
	}

	size, err := strconv.Atoi(res[0])
	if err != nil {
		return nil, fmt.Errorf("size field missing or invalid")
	}

	modUnix, err := strconv.ParseInt(res[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("modtime field missing or invalid")
	}

	return &common.StorageStat{
		Size:    int64(size),
		ModTime: time.Unix(modUnix, 0),
	}, nil
}

func (s *ValKeyKeyService) HasNil(err error) bool {
	return err == valkey.Nil
}

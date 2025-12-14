package web

import (
	"log/slog"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type NamespacedKeyStore struct {
	store     common.BaseKeyStore
	namespace string
}

func NewSessionKeyStore(store common.KeyStore, dev bool) common.BaseKeyStore {
	prefix := ""
	slog.Info("session store dev mode:", "dev", dev)
	if dev {
		prefix = common.STORE_PREFIX_DEV
	}
	return &NamespacedKeyStore{
		store:     store,
		namespace: prefix,
	}
}

func NewPolicyStore(store common.KeyStore, dev bool) common.BaseKeyStore {
	prefix := common.STORE_PREFIX_POLICY
	slog.Info("policy store dev mode:", "dev", dev)
	if dev {
		prefix = common.STORE_PREFIX_DEV + common.STORE_PREFIX_POLICY
	}
	return &NamespacedKeyStore{
		store:     store,
		namespace: prefix,
	}
}

func (s *NamespacedKeyStore) Read(id string) ([]byte, error) {
	return s.store.Read(s.namespace + id)
}

func (s *NamespacedKeyStore) Write(id string, value []byte) error {
	return s.store.Write(s.namespace+id, value)
}

func (s *NamespacedKeyStore) WriteWithTTL(id string, value []byte, ttlSeconds int) error {
	return s.store.WriteWithTTL(s.namespace+id, value, ttlSeconds)
}

func (s *NamespacedKeyStore) HasNil(err error) bool {
	return s.store.HasNil(err)
}

func (s *NamespacedKeyStore) Delete(id string) error {
	return s.store.Delete(s.namespace + id)
}

func (s *NamespacedKeyStore) Exists(id string) (int64, error) {
	return s.store.Exists(s.namespace + id)
}

package cert

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"time"

	"github.com/caddyserver/certmagic"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

const (
	// lockTTLSeconds bounds how long a lock survives if its owner crashes
	// without unlocking; after this the store expires the key so other nodes
	// can take over instead of deadlocking forever.
	lockTTLSeconds = 300
	// lockPollInterval is how often Lock retries while the lock is held.
	lockPollInterval = 2 * time.Second
)

// implements certmagic.Storage interface
type CertStorage struct {
	client common.KeyStore
	ctx    context.Context
	nodeId string
}

func NewCertStorage(kvStore common.KeyStore, nodeId string) *CertStorage {
	ctx := context.Background()
	return &CertStorage{
		client: kvStore,
		ctx:    ctx,
		nodeId: nodeId,
	}
}

func (c *CertStorage) Store(ctx context.Context, key string, value []byte) error {
	slog.Debug(fmt.Sprintf("Store key %s with content length %d", key, len(value)))
	err := c.client.Write(key, value)
	slog.Debug(fmt.Sprintf("Store key %s done, err: %v", key, err))
	if c.client.HasNil(err) {
		err = nil
	}
	return err
}

func (c *CertStorage) Load(ctx context.Context, key string) ([]byte, error) {
	data, err := c.client.Read(key)
	if c.client.HasNil(err) {
		return nil, fs.ErrNotExist
	} else if err != nil {
		return nil, err
	}
	return data, nil
}

func (c *CertStorage) Exists(ctx context.Context, key string) bool {
	exists, err := c.client.Exists(key)
	return err == nil && exists > 0
}

func (c *CertStorage) Delete(ctx context.Context, key string) error {
	return c.client.Delete(key)
}

func (c *CertStorage) List(ctx context.Context, prefix string, recursive bool) ([]string, error) {
	keys, err := c.client.List(prefix, recursive)
	if err != nil {
		return nil, err
	}
	return keys, nil
}

func (c *CertStorage) Stat(ctx context.Context, key string) (certmagic.KeyInfo, error) {
	stat, err := c.client.Stat(key)
	if err != nil {
		return certmagic.KeyInfo{}, err
	}

	return certmagic.KeyInfo{
		Key:        key,
		Modified:   stat.ModTime,
		Size:       stat.Size,
		IsTerminal: true,
	}, nil
}

// Lock implements certmagic.Locker. Per the contract it blocks until the lock
// is acquired or ctx is cancelled, rather than failing fast when the lock is
// held. Acquisition is atomic (WriteNX) and the lock carries a TTL so a crashed
// owner cannot deadlock the cluster.
func (c *CertStorage) Lock(ctx context.Context, key string) error {
	slog.Info(fmt.Sprintf("Acquire lock for key %s", key))
	for {
		acquired, err := c.client.WriteNX(key, []byte(c.nodeId), lockTTLSeconds)
		if c.client.HasNil(err) {
			err = nil
		}
		if err != nil {
			return err
		}
		if acquired {
			return nil
		}
		// Held by another node: wait and retry, honoring cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(lockPollInterval):
		}
	}
}

func (c *CertStorage) Unlock(ctx context.Context, key string) error {
	slog.Info(fmt.Sprintf("Unlock for key %s", key))
	val, err := c.Load(ctx, key)
	switch err {
	case nil:
		if string(val) == c.nodeId {
			c.Delete(ctx, key)
		}
	case fs.ErrNotExist:
		// already deleted
	default:
		slog.Info(fmt.Sprintf("** Unlock error %s", err))
		return err
	}
	return nil
}

//go:build ionos

package dns

import "github.com/libdns/ionos"

func NewProvider(token string) *ionos.Provider {
	return &ionos.Provider{AuthAPIToken: token}
}

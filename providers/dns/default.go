//go:build !ionos

package dns

import "github.com/libdns/libdns"

type DNSProvider interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

// no-op placeholder for tooling without tags.
func NewProvider(token string) DNSProvider {
	panic("no DNS provider selected (build with -tags=<provider>)")
}

// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package common

import (
	"errors"
	"net"
)

func ResolveIP(host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.LookupIP(host)
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if !addr.IsLoopback() {
			return addr.String(), nil
		}
	}
	return "", errors.New("no non-loopback address found")
}

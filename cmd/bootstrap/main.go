// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package main

import (
	"gitlab.com/real-cis/cc/betterkey/internal/cluster"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

func main() {
	enclaveConfig, clusterConfig := common.ParseConfig()

	bootstrap := &cluster.Bootstrap{Cluster: clusterConfig, Enclave: enclaveConfig}
	go bootstrap.Start()

	select {}
}

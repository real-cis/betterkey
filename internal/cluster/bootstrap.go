// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/web"
)

type Bootstrap struct {
	Cluster *common.ClusterConfig
	Enclave *common.EnclaveConfig
}

type NodeStateListener struct {
	lock      sync.Mutex
	done      bool
	countdown *sync.WaitGroup
}

// OnHeartBeatWindow implements StateListener.
func (n *NodeStateListener) OnHeartBeatWindow(w *common.HeartBeatWindow) {}

// OnStateChanged implements StateListener.
func (n *NodeStateListener) OnStateChanged(state int) {
	n.lock.Lock()
	defer n.lock.Unlock()
	if !n.done && state == NODE_STATE_READY {
		n.done = true
		n.countdown.Done()
	}
}

func (bootstrap *Bootstrap) Start() {
	slog.Info("start node")
	if bootstrap.Cluster.DevMode {
		slog.Info("## DEV mode enabled ##")
		slog.Info("### running in development mode: 1) services mock tdx attestation verification 2) keystore uses dev namespace")
	}
	listener := &NodeStateListener{
		lock:      sync.Mutex{},
		done:      false,
		countdown: common.NewCountDown(1),
	}
	node := NewNode(bootstrap.Cluster, bootstrap.Enclave, listener)
	go node.Start()
	listener.countdown.Wait()
	server := web.NewKeyServer(bootstrap.Cluster, node.KVDatabase(), node.NodeStatus(),
		node.(*Node).masterKs.Read(), node.(*Node).NodeTls().ClientTlsConfig())
	server.Start()

	// Graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	<-signalCh
	node.Shutdown()
}

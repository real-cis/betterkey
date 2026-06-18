// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type noopVault struct {
	countdown *sync.WaitGroup
	window    *common.HeartBeatWindow
}

// Handle implements WindowHandler.
func (n *noopVault) OnHeartBeatWindow(w *common.HeartBeatWindow) {
	n.countdown.Done()
	n.window = w
}

// Seal implements common.Vault.
func (n *noopVault) Seal(data []byte) ([]byte, error) {
	return data, nil
}

// Unseal implements common.Vault.
func (n *noopVault) Unseal(data []byte) ([]byte, error) {
	return data, nil
}

// HKDF implements common.Vault.
func (n *noopVault) HKDF(data []byte, info string, length int) ([]byte, error) {
	return data, nil
}

func tohex(s string) string {
	return hex.EncodeToString([]byte(s))
}
func TestProcess(t *testing.T) {
	cd := common.NewCountDown(1)
	hbw := &common.HeartBeatWindow{
		Stats: &map[string]*common.HeartBeatStat{},
	}
	noOp := noopVault{
		countdown: cd,
		window:    hbw,
	}
	nid := &common.NodeInfo{
		Id:        "node-id",
		ClusterId: "cluster-id",
	}
	nodeState := &NodeState{
		nodeInfo: nid,
		state:    NODE_STATE_READY,
		seed:     nil,
	}
	hbm := NewHeartBeatManager(func() common.Vault {
		return &noOp
	}, 20*time.Second, 5*time.Second, &noOp, nodeState)

	now := hbm.lastRunTs

	n1 := tohex("1")
	n2 := tohex("2")
	n3 := tohex("3")
	n4 := tohex("4")
	badN := tohex("bad")

	hbs := []*peerHeartBeat{
		{id: "1", nonce: n1, encryptedNonce: n1, ts: now + 2},
		{id: "2", nonce: n2, encryptedNonce: n2, ts: now + 3},
		{id: "3", nonce: n3, encryptedNonce: n3, ts: now + 4},
		{id: "1", nonce: n1, encryptedNonce: n1, ts: now + 5},
		{id: "2", nonce: n2, encryptedNonce: n2, ts: now + 10},
		{id: "3", nonce: n3, encryptedNonce: badN, ts: now + 17},
		{id: "4", nonce: n4, encryptedNonce: n4, ts: now + 22},
	}

	hbm.samples = hbs
	hbm.windowHandler = &noOp
	go hbm.Start()
	defer hbm.Stop()
	cd.Wait()
	assert.Equal(t, 1, len(hbm.samples))
	assert.Equal(t, 3, len(*noOp.window.Stats))
	bad := (*noOp.window.Stats)["3"]
	assert.Equal(t, 1, bad.Errors)
	assert.Equal(t, 2, bad.Total)
	ok := (*noOp.window.Stats)["1"]
	assert.Equal(t, 0, ok.Errors)
	assert.Equal(t, 2, ok.Total)

	no := (*noOp.window.Stats)["4"]
	assert.Nil(t, no)

	cd.Add(1)
	cd.Wait()

	assert.Equal(t, 0, len(hbm.samples))
	assert.Equal(t, 1, len(*noOp.window.Stats))
	hb4 := (*noOp.window.Stats)["4"]
	assert.Equal(t, 0, hb4.Errors)

}

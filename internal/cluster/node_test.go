// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
)

var clusterId = "testCluster"

type TestNode struct {
	name string
	ip   string
	port uint32
}

var testNodes = []TestNode{
	{name: "127.0.0.1", ip: "127.0.0.1", port: 6001},
	{name: "127.0.0.2", ip: "127.0.0.2", port: 6002},
	{name: "127.0.0.3", ip: "127.0.0.3", port: 6003},
}
var seeds = []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
var testNode4 = TestNode{name: "127.0.0.4", ip: "127.0.0.4", port: 6004}
var testNode5 = TestNode{name: "127.0.0.5", ip: "127.0.0.5", port: 6005}

type nodeStateListener struct {
	name     string
	callback *func(name string, state int)
}

// OnHeartBeatWindow implements StateListener.
func (n *nodeStateListener) OnHeartBeatWindow(w *common.HeartBeatWindow) {
}

type valKey struct {
	container testcontainers.Container
	uris      []string
}

// OnStateChanged implements StateListener.
func (n *nodeStateListener) OnStateChanged(state int) {
	(*n.callback)(n.name, state)
}

func (vk *valKey) cleanup(t *testing.T) {
	testcontainers.CleanupContainer(t, vk.container)
}

func newValkey(t *testing.T) *valKey {
	ctx := context.Background()
	req := testcontainers.ContainerRequest{
		Image:        "valkey/valkey:8.0.2-alpine",
		ExposedPorts: []string{"6379/tcp"},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	valkeyContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	valkeyEp, _ := valkeyContainer.Endpoint(ctx, "")
	valkeyUri := []string{valkeyEp}
	return &valKey{
		container: valkeyContainer,
		uris:      valkeyUri,
	}
}

func TestSeedNodeRestartInReadyState(t *testing.T) {

	folder, _ := os.MkdirTemp("/tmp", "seal")
	valKey := newValkey(t)

	// node1 contains key before start up
	node1 := testNodes[0]
	node1CountDown := common.NewCountDown(1)
	var n1Ready = false

	n5callback := func(name string, state int) {
		if name == node1.name && state == NODE_STATE_READY {
			t.Logf("node %v READY", name)
			n1Ready = true
			node1CountDown.Done()
		}
	}

	k := make([]byte, 32)
	rand.Read(k)
	secret := hex.EncodeToString(k)
	mk := &common.MasterSecret{
		Secret:    secret,
		CreatorId: node1.name,
		Created:   0,
	}

	node1Info := &NodeInfo{
		Id:        node1.name,
		ClusterId: clusterId,
	}

	// to feed storage
	sgx.NewMasterkeyStore((*common.NodeInfo)(node1Info), folder, nil).Write(mk)

	n1 := newNode(clusterId, &node1, folder, valKey.uris, []string{fmt.Sprintf("%s:%v", node1.name, 6001)}, seeds, &n5callback)
	n1.state.nodeInfo = (*common.NodeInfo)(node1Info)

	go n1.Start()

	node1CountDown.Wait()
	require.True(t, n1Ready)

	t.Cleanup(func() {
		valKey.cleanup(t)
		n1.Shutdown()
		os.RemoveAll(folder)
	})
}

func TestSeedingClusterWithJoiningNode(t *testing.T) {

	folder, _ := os.MkdirTemp("/tmp", "seal")
	valKey := newValkey(t)

	nodes := []*Node{}
	count := len(seeds)

	seedsSet := common.NewSet()
	seedsSet.AddAll(seeds)
	seedsCountdown := *common.NewCountDown(3)

	callback := func(name string, state int) {
		if seedsSet.Size() > 0 && seedsSet.Contains(name) && state == NODE_STATE_READY {
			t.Logf("node %v READY", name)
			seedsSet.Remove(name)
			seedsCountdown.Done()
		}
	}
	for ind := range seeds {
		testNode := &testNodes[ind]
		peer1 := testNodes[(ind+1)%count]
		peer2 := testNodes[(ind+2)%count]
		node := newNode(clusterId, testNode, folder, valKey.uris, []string{fmt.Sprintf("%s:%v", peer1.name, peer1.port), fmt.Sprintf("%s:%v", peer2.name, peer2.port)}, seeds, &callback)
		go node.Start()
		nodes = append(nodes, node)
	}
	// converged
	seedsCountdown.Wait()
	t.Log("member list converged")
	for _, s := range seeds {
		_, err := os.ReadFile(filepath.Join(folder, s))
		require.NoError(t, err)
	}
	t.Log("all seed nodes saved key")

	// new node join cluster

	n4Countdow := *common.NewCountDown(1)

	n4callback := func(name string, state int) {
		if name == testNode4.name && state == NODE_STATE_READY {
			t.Logf("node %v READY", testNode4.name)
			n4Countdow.Done()
		}
	}

	n4 := newNode(clusterId, &testNode4,
		folder, valKey.uris, []string{fmt.Sprintf("%s:%v", testNodes[0].name, testNodes[0].port)}, seeds, &n4callback)
	go n4.Start()
	n4Countdow.Wait()
	_, err := os.ReadFile(filepath.Join(folder, testNode4.name))
	require.NoError(t, err)
	t.Logf("%v joined, received key", testNode4.name)

	// node5 contains key before start up
	node5CountDown := common.NewCountDown(1)
	var n5Ready = false

	n5callback := func(name string, state int) {
		if name == testNode5.name && state == NODE_STATE_READY {
			t.Logf("node %v READY", name)
			n5Ready = true
			node5CountDown.Done()
		}
	}
	// copy key from old node4
	mk := n4.masterKs.Read().MasterSecret
	n5 := newNode(clusterId, &testNode5, folder, valKey.uris, []string{fmt.Sprintf("%s:%v", testNodes[0].name, testNodes[0].port)}, seeds, &n5callback)
	node5Info := &NodeInfo{
		Id:        testNode5.name,
		ClusterId: clusterId,
	}
	// to feed storage
	n5.state.nodeInfo = (*common.NodeInfo)(node5Info)
	sgx.NewMasterkeyStore((*common.NodeInfo)(node5Info), folder, nil).Write(mk)

	nodes = append(nodes, n5)
	go n5.Start()

	node5CountDown.Wait()

	require.True(t, n5Ready, "node 5 must have been ready")

	t.Cleanup(func() {
		valKey.cleanup(t)
		for _, n := range nodes {
			n.Shutdown()
		}
		os.RemoveAll(folder)
	})
}

func newNode(clusterId string, node *TestNode, folder string, valkey, peerAddresses, seeds []string, lst *func(name string, state int)) *Node {
	cf := &common.ClusterConfig{
		Id:              clusterId,
		EncryptionKey:   "test",
		Port:            node.port,
		BindAddress:     node.ip,
		PeerAddresses:   peerAddresses,
		SeedNodes:       seeds,
		NodeHost:        node.name,
		ValkeyUris:      valkey,
		ServerPort:      8080,
		MasterKeyFolder: folder,
	}
	stLsn := &nodeStateListener{
		callback: lst,
		name:     node.name,
	}
	cn := NewNode(cf, nil, stLsn)
	n := cn.(*Node)
	return n
}

func badClusterFromPeerMessage(t *testing.T) {

	n := &Node{
		id:      seeds[0],
		cluster: clusterId,
		state: &NodeState{
			state: 0,
			nodeInfo: &common.NodeInfo{
				Id:        seeds[0],
				ClusterId: clusterId,
			},
		},
	}
	n.inMessages = make(chan PeerMessage, 10)
	go func() {
		m := <-n.inMessages
		t.Logf("peer received from cluster:%v", m.Sender.ClusterId)
	}()
	imMsg := &PeerMessage{
		Type: 1,
		Sender: &common.NodeInfo{
			Id:        seeds[1],
			ClusterId: "othercluster",
		},
		Data: make([]byte, 0),
	}
	b, _ := json.Marshal(imMsg)
	n.NotifyMsg(b)
}

func badClusterFromPeerStatus(t *testing.T) {
	n := &Node{
		id:      seeds[0],
		cluster: clusterId,
		state: &NodeState{
			state: 0,
			nodeInfo: &common.NodeInfo{
				Id: seeds[0],

				ClusterId: clusterId,
			},
		},
	}

	nm := &common.NodeMeta{
		Id:        seeds[1],
		ClusterId: "othercluster",
		State:     1,
	}
	b, _ := json.Marshal(nm)
	t.Logf("Merging state from remote cluster %v", nm.ClusterId)
	n.MergeRemoteState(b, true)
}

func TestPanicOnBadClusterFromPeerMessage(t *testing.T) {
	defer func() { recover() }()
	badClusterFromPeerMessage(t)
	t.Errorf("should have panicked")
}

func TestPanicOnBadClusterJoinMessage(t *testing.T) {
	defer func() { recover() }()
	badClusterFromPeerStatus(t)
	t.Errorf("should have panicked")
}

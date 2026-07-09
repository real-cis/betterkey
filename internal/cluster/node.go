// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"gitlab.com/real-cis/cc/betterkey/internal/cluster/transport"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/db"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
)

type Node struct {
	id                      string
	hostname                string
	cluster                 string
	configuredPeerAddresses []string
	seedNodes               []string
	list                    *memberlist.Memberlist
	masterKs                common.MasterKeyStore
	keyDb                   common.KeyStore
	state                   *NodeState
	inMessages              chan PeerMessage
	stateChangeMessages     chan int
	lock                    sync.Mutex
	memberlistConfig        *memberlist.Config
	stateListener           StateListener
	heartbeatManager        *HeartBeatManager
	nodeTls                 common.NodeTLSConfig
}

func (c *Node) ConfiguredPeerAddresses() []string {
	return c.configuredPeerAddresses[:]
}

func (n *Node) SetStateListener(listener StateListener) {
	n.stateListener = listener
}

// NodeStatus implements common.ClusterNode
func (n *Node) NodeStatus() *common.NodeMeta {
	n.lock.Lock()
	defer n.lock.Unlock()
	nm := &common.NodeMeta{
		Id:        n.state.nodeInfo.Id,
		ClusterId: n.state.nodeInfo.ClusterId,
		State:     n.state.state,
	}
	if nm.State == NODE_STATE_READY {
		hb := n.heartbeatManager.LocalHeartBeat()
		if hb != nil {
			slog.Debug("Providing heartbeat in NodeStatus")
			nm.HeartBeat = hb
		}
	}
	return nm
}

// common.ClusterNode
func (n *Node) ActiveMemberNodes() []*common.NodeMeta {
	list := []*common.NodeMeta{}
	peers := n.copyClusterPeers()
	for _, peer := range peers {
		if peer.Name != n.id {
			m, err := NodeMetaFromBytes(peer.Meta)
			if err != nil {
				slog.Error("Bad memberlist.Node.Meta", "error", err)
			} else {
				list = append(list, m)
			}
		}
	}
	return list
}

// common.ClusterNode
func (c *Node) Start() {
	list, err := memberlist.Create(c.memberlistConfig)
	if err != nil {
		log.Fatalf("Failed to create memberlist: %v", err)
	}

	c.list = list
	c.state.seed.msgSender = list
	slog.Info("starting node", "id", c.id)
	localId := c.masterKs.Read()

	go c.loop()
	go c.notifyStateChange()
	go c.heartbeatManager.Start()

	if localId != nil {
		slog.Info("Key found locally")
		if localId.NodeInfo.ClusterId != c.cluster {
			panic(fmt.Errorf("auto shutdown, clusterId mismatch, own:%v, localMasterKey:%v", c.cluster, localId.NodeInfo.ClusterId))
		}
		if slices.Contains(c.seedNodes, c.id) {
			slog.Info("Seed Node, using local MK", "nodeId", c.id)
			for {
				pc, err := c.list.Join(c.configuredPeerAddresses)
				if pc == 0 {
					slog.Error("no peers on join(), wait loop", "error", err)
					time.Sleep(5 * time.Second)
				} else {
					slog.Info("joined", "error", err, "peers", pc)
					break
				}
			}
			c.setStatus(NODE_STATE_READY)
		} else {
			c.validatingExistingKey()
		}
	} else {
		slog.Info("No key locally")
		c.onNoKey()
	}
}

// common.ClusterNode
func (n *Node) Shutdown() {
	log.Println("Shutting down...")

	// shutdown memberlist first to release the TCP port
	if n.list != nil {
		err := n.list.Shutdown()
		if err != nil {
			log.Printf("Error shutting down memberlist: %v", err)
		}
	}

	close(n.inMessages)
	close(n.stateChangeMessages)
	if n.heartbeatManager != nil {
		n.heartbeatManager.Stop()
	}
}

// common.ClusterNode
func (n *Node) KVDatabase() common.KeyStore {
	return n.keyDb
}

func (n *Node) NodeTls() common.NodeTLSConfig {
	return n.nodeTls
}

// GetBroadcasts implements memberlist.Delegate.
// GetBroadcasts is called when user data messages can be broadcast.
// It can return a list of buffers to send. Each buffer should assume an
// overhead as provided with a limit on the total byte size allowed.
// The total byte size of the resulting data to send must not exceed
// the limit. Care should be taken that this method does not block,
// since doing so would block the entire UDP packet receive loop.
func (n *Node) GetBroadcasts(overhead int, limit int) [][]byte {
	return nil
}

// LocalState implements memberlist.Delegate.
// LocalState is used for a TCP Push/Pull. This is sent to
// the remote side in addition to the membership information. Any
// data can be sent here. See MergeRemoteState as well. The `join`
// boolean indicates this is for a join instead of a push/pull.
func (n *Node) LocalState(join bool) []byte {
	m := n.NodeStatus()
	b, err := json.Marshal(m)
	if err != nil {
		slog.Error("error serializing localstate", "error", err)
	}
	slog.Debug("Delegate.LocalState(join)", "join", join, "state", m.State, "id", m.Id)
	return b
}

// MergeRemoteState implements memberlist.Delegate.
// MergeRemoteState is invoked after a TCP Push/Pull. This is the
// state received from the remote side and is the result of the
// remote side's LocalState call. The 'join'
// boolean indicates this is for a join instead of a push/pull.
func (n *Node) MergeRemoteState(buf []byte, join bool) {
	var m common.NodeMeta
	err := json.Unmarshal(buf, &m)
	if err != nil {
		slog.Error("MergeRemoteState. error unserializing remotestate", "error", err)
	} else {
		if m.ClusterId != n.cluster {
			panic(fmt.Errorf("auto shutdown, clusterId mismatch, own:%v, remotestate:%v", n.cluster, m.ClusterId))
		}
		slog.Debug("MergeRemoteState", "remote-id", m.Id, "state", m.State, "join", join)
		if n.list == nil {
			slog.Error("should not happen ! no memberlist initiated !!!")
			return
		}

		// Don't mutate .Meta on n.list.Members()[i] which are live pointers into memberlist's
		// internal nodeState. Changing which corrupts the incarnation/refute state and triggers a
		// permanent refute loop when the heartbeat nonce changes
		if m.Id != n.state.nodeInfo.Id && m.HeartBeat != nil && m.HeartBeat.Nonce != "" {
			n.heartbeatManager.OnRemoteHeartBeat(m.Id, *m.HeartBeat)
		}
	}
}

// NodeMeta implements memberlist.Delegate.
// NodeMeta is used to retrieve meta-data about the current node
// when broadcasting an alive message. It's length is limited to
// the given byte size. This metadata is available in the Node structure.
//
// Returns only stable fields (id, clusterId, state); the rotating heartbeat nonce
// must NOT be included, or memberlist's per-message Meta comparison triggers a permanent
// refute loop (heartbeat flows through LocalState/MergeRemoteState instead).
func (n *Node) NodeMeta(limit int) []byte {
	n.lock.Lock()
	nm := &common.NodeMeta{
		Id:        n.state.nodeInfo.Id,
		ClusterId: n.state.nodeInfo.ClusterId,
		State:     n.state.state,
	}
	n.lock.Unlock()
	b, err := json.Marshal(nm)
	if err != nil {
		slog.Error("Delegate.NodeMeta", "error", err)
	}
	slog.Debug("Delegate.NodeMeta()", "state", nm.State, "id", nm.Id)
	return b
}

// NotifyMsg implements memberlist.Delegate.
// NotifyMsg is called when a user-data message is received.
// Care should be taken that this method does not block, since doing
// so would block the entire UDP packet receive loop. Additionally, the byte
// slice may be modified after the call returns, so it should be copied if needed
func (n *Node) NotifyMsg(b []byte) {
	var p PeerMessage
	err := json.Unmarshal(b, &p)
	slog.Debug("Delegate.NotifyMsg(b)")
	if err != nil {
		slog.Error("error deserializing peermsg", "error", err)
	} else {
		slog.Info("PeerMessage", "type", p.Type, "from", p.Sender.Id, "currentState", n.state.state)
		if p.Sender.ClusterId != n.cluster {
			//sth's wrong
			panic(fmt.Errorf("auto shutdown, clusterId mismatch, own:%v, peerMeesage:%v", n.cluster, p.Sender.ClusterId))
		}
		n.inMessages <- p
	}
}

func NewNode(clusterConfig *common.ClusterConfig, enclaveConfig *common.EnclaveConfig, stateListener StateListener) common.ClusterNode {
	if clusterConfig == nil {
		panic("CLUSTER_PEERS undefined")
	}

	if clusterConfig.Port == 0 {
		panic("CLUSTER_PORT undefined")
	}

	if len(clusterConfig.PeerAddresses) == 0 {
		panic("PEERS empty")
	}

	if len(clusterConfig.ValkeyUris) == 0 {
		panic("VALKEY_URIS empty")
	}

	if len(clusterConfig.BindAddress) == 0 {
		panic("BIND_ADDRESS empty")
	}

	hostname, err := os.Hostname()
	if err != nil {
		slog.Error("hostname error", "error", err)
		panic(err)
	}

	nodeTls, err := sgx.NewNodeTlsConfig(clusterConfig.NodeHost, enclaveConfig)
	if err != nil {
		slog.Error("error getting tls config", "error", err)
		panic(err)
	}

	nid := &common.NodeInfo{
		Id:        clusterConfig.NodeHost,
		ClusterId: clusterConfig.Id,
	}

	ks := sgx.NewMasterkeyStore(nid, clusterConfig.MasterKeyFolder, enclaveConfig)
	prov := func() common.Vault {
		var m common.Vault = ks.Read()
		return m
	}

	kss, err := db.NewValKeyKeyService(clusterConfig.ValkeyUris, clusterConfig.ValkeyUser,
		clusterConfig.ValkeyPassword, clusterConfig.ValkeyNamespace, clusterConfig.ValkeyTLS, prov)
	if err != nil {
		panic(err)
	}

	seedNodes := common.NewSet()
	seedNodes.AddAll(clusterConfig.SeedNodes)
	configuredSeedNodes := seedNodes.Sorted()
	seedNodes.Remove(clusterConfig.NodeHost)

	nodeState := &NodeState{
		nodeInfo: nid,
		state:    0,
		seed: &seed{
			id:             nid,
			otherSeedNodes: seedNodes.Sorted(),
		},
	}
	node := &Node{
		id:                      clusterConfig.NodeHost,
		cluster:                 clusterConfig.Id,
		hostname:                hostname,
		configuredPeerAddresses: clusterConfig.PeerAddresses,
		masterKs:                ks,
		keyDb:                   kss,
		state:                   nodeState,
		seedNodes:               configuredSeedNodes,
		inMessages:              make(chan PeerMessage, 1024),
		stateChangeMessages:     make(chan int, 1024),
		stateListener:           stateListener,
		heartbeatManager:        NewHeartBeatManager(prov, 15*time.Minute, 2*time.Minute, stateListener, nodeState),
		nodeTls:                 nodeTls,
	}

	config := memberlist.DefaultWANConfig()
	// DefaultWANConfig was designed for cheap UDP probes. With TCP-only
	// transport every probe/gossip broadcast runs a full RA-TLS attestation handshake.
	// Increase default timeout intervals
	config.ProbeInterval = 30 * time.Second
	config.ProbeTimeout = 10 * time.Second
	config.GossipInterval = 5 * time.Second
	config.PushPullInterval = 60 * time.Second
	sKey := sha256.Sum256([]byte(clusterConfig.EncryptionKey))
	config.Name = clusterConfig.NodeHost
	config.SecretKey = sKey[:]
	config.BindPort = int(clusterConfig.Port)
	config.AdvertisePort = int(clusterConfig.Port)
	config.BindAddr = clusterConfig.BindAddress
	config.AdvertiseAddr, err = common.ResolveIP(clusterConfig.NodeHost)
	if err != nil {
		slog.Error("error resolving advertise address", "error", err)
		panic(err)
	}

	nettransportConfig := &transport.NetTransportConfig{
		BindAddrs:       []string{config.BindAddr},
		BindPort:        config.BindPort,
		TLSConfig:       nodeTls.ServerTlsConfig(),
		TLSClientConfig: nodeTls.ClientTlsConfig(),
	}

	tlsTransport, err := transport.NewNetTransport(nettransportConfig)
	if err != nil {
		log.Fatalf("Failed to create baseTransport: %v", err)
	}

	config.Transport = tlsTransport
	config.Delegate = node

	node.memberlistConfig = config

	slog.Info("new node", "id", node.id, "port", clusterConfig.Port, "advertiseAddress",
		config.AdvertiseAddr, "bindAddress", config.BindAddr, "bindPort", config.BindPort, "seedNodes", clusterConfig.SeedNodes, "seedPeers", node.state.seed.otherSeedNodes)
	slog.Info("memberlist intervals", "probeInterval", config.ProbeInterval, "probeTimeout", config.ProbeTimeout, "gossipInterval", config.GossipInterval, "pushPullInterval", config.PushPullInterval)
	return node
}

// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/sgx"
)

type seed struct {
	//sentPeers       *common.Set
	keyExchangeStat map[string]*keyExchange
	id              *common.NodeInfo
	generatedKey    []byte
	lock            sync.Mutex
	otherSeedNodes  []string
	msgSender       MessageSender
	otherMembers    []*memberlist.Node

	// Attested ephemeral material for the current seeding round. selfOffer and
	// selfKx are this node's own; offers holds the verified offers received
	// from other seed nodes, keyed by node id. All are cleared on cleanup so
	// they never outlive the round.
	selfOffer *seedOffer
	selfKx    *pendingKeyExchange
	offers    map[string]*seedOffer
}

type keyExchange struct {
	sentTo, receivedFrom bool
}

func (s *seed) hasReceivedKeysFromAllSeedPeers() bool {
	if len(s.keyExchangeStat) < len(s.otherSeedNodes) {
		return false
	}
	for _, v := range s.keyExchangeStat {
		if !v.receivedFrom {
			return false
		}
	}
	return true
}

func (s *seed) checkCleanup() {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Only tear down once every peer is accounted for. Falling through on a
	// length mismatch would wipe generatedKey mid-round and stall seeding.
	if len(s.otherSeedNodes) != len(s.keyExchangeStat) {
		return
	}
	for _, ex := range s.keyExchangeStat {
		if !ex.sentTo || !ex.receivedFrom {
			return
		}
	}
	slog.Info("all seed-exchange peers marked as sent and received, cleanup")
	s.generatedKey = make([]byte, 0)
	s.keyExchangeStat = map[string]*keyExchange{}
	s.otherSeedNodes = []string{}
	s.otherMembers = []*memberlist.Node{}
	s.offers = map[string]*seedOffer{}
	s.selfOffer = nil
	s.selfKx = nil
}

// prepareOffer generates this node's ephemeral key for the round (once) and
// broadcasts the attested offer to the other seed members. Peers cannot wrap
// the seed key to this node until they hold it.
func (s *seed) prepareOffer(attestor sgx.Attestor, clusterId string, members []*memberlist.Node) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.selfOffer == nil {
		offer, kx, err := newSeedOffer(attestor, clusterId)
		if err != nil {
			return err
		}
		s.selfOffer, s.selfKx = offer, kx
	}
	payload, err := json.Marshal(s.selfOffer)
	if err != nil {
		return err
	}
	pm := &PeerMessage{Type: MSG_TYPE_SEED_OFFER, Sender: s.id, Data: payload}
	b, err := pm.toJson()
	if err != nil {
		return err
	}
	go func() {
		for _, m := range members {
			if err := s.msgSender.SendReliable(m, b); err != nil {
				slog.Error("error sending seed offer", "to", m.Name, "error", err)
			} else {
				slog.Info("sent seed offer", "to", m.Name)
			}
		}
	}()
	return nil
}

// localOffer returns this node's ephemeral material for the round. Both values
// are immutable once set, so the caller may use them outside the lock.
func (s *seed) localOffer() (*pendingKeyExchange, *seedOffer) {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.selfKx, s.selfOffer
}

// storeOffer records a verified offer from a seed peer. Offers from nodes that
// are not configured seed peers are ignored.
func (s *seed) storeOffer(id string, offer *seedOffer) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	if !slices.Contains(s.otherSeedNodes, id) {
		slog.Debug("ignoring seed offer from non-seed node", "from", id)
		return false
	}
	if s.offers == nil {
		s.offers = map[string]*seedOffer{}
	}
	s.offers[id] = offer
	return true
}

// forwardKeyToOtherSeedPeers sends the seed key to every other seed peer whose
// attested offer has arrived, wrapped to that peer's ephemeral key so the key
// never travels in plaintext. Peers whose offer is still missing are skipped
// and retried when it arrives.
func (s *seed) forwardKeyToOtherSeedPeers() {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Nothing to distribute: either cleaned up, or a slave that has not yet
	// adopted a real key.
	if len(s.generatedKey) == 0 || bytes.Equal(dummyKey, s.generatedKey) {
		return
	}
	if s.selfOffer == nil || s.selfKx == nil {
		slog.Error("cannot forward seed key without a local offer")
		return
	}

	for _, pName := range s.otherSeedNodes {
		ex, ok := s.keyExchangeStat[pName]
		if !ok {
			ex = &keyExchange{
				sentTo:       false,
				receivedFrom: false,
			}
			s.keyExchangeStat[pName] = ex
		}
		if ex.sentTo {
			continue
		}
		offer, ok := s.offers[pName]
		if !ok {
			slog.Debug("no seed offer yet, will retry when it arrives", "peer", pName)
			continue
		}
		init, err := wrapSeedKey(s.selfKx, s.selfOffer, offer, s.generatedKey)
		if err != nil {
			slog.Error("wrapping seed key failed", "peer", pName, "error", err)
			continue
		}
		payload, err := json.Marshal(init)
		if err != nil {
			slog.Error("cannot serialize seed key-init", "peer", pName, "error", err)
			continue
		}
		pm := &PeerMessage{Type: MSG_TYPE_KEYINIT, Sender: s.id, Data: payload}
		b, err := pm.toJson()
		if err != nil {
			slog.Error("cannot serialize seed key-init msg", "peer", pName, "error", err)
			continue
		}
		for _, n := range s.otherMembers {
			if n.Name != pName {
				continue
			}
			if err := s.msgSender.SendReliable(n, b); err != nil {
				slog.Error("error forwarding key to other seed peer", "name", pName, "error", err)
			} else {
				ex.sentTo = true
				slog.Info("mark forwarding wrapped key to other seed peer ok", "name", pName)
			}
		}
	}
	go s.checkCleanup()
}

type MessageSender interface {
	SendReliable(n *memberlist.Node, msg []byte) error
}

var dummyKey = []byte{1}

func (s *seed) startSeedAsMaster(key []byte, otherMembers []*memberlist.Node) {
	s.lock.Lock()
	if len(key) != masterKeyLen {
		s.lock.Unlock()
		panic(fmt.Errorf("requires keysize %v, got %v", masterKeyLen, len(key)))
	}

	s.generatedKey = key
	s.keyExchangeStat = map[string]*keyExchange{}
	s.otherMembers = otherMembers
	s.lock.Unlock()

	// Sends to peers whose offer has already arrived; the rest go out from
	// handleSeedOffer as their offers come in.
	go s.forwardKeyToOtherSeedPeers()
}

func (s *seed) startSeedAsSlave(otherMembers []*memberlist.Node) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.generatedKey = dummyKey
	s.keyExchangeStat = map[string]*keyExchange{}
	s.otherMembers = otherMembers
}

// returns key when completed
func (s *seed) keyReceived(k []byte, senderId string) []byte {
	s.lock.Lock()
	defer s.lock.Unlock()
	if !slices.Contains(s.otherSeedNodes, senderId) {
		panic(fmt.Errorf("seed key from unknown node %v", senderId))
	}
	if len(k) != 32 {
		panic(fmt.Errorf("requires keysize 32, got %v", len(k)))
	}
	if len(s.generatedKey) == 0 {
		slog.Info("key empty")
		return make([]byte, 0)
	}

	if bytes.Equal(dummyKey, s.generatedKey) {
		slog.Info("first received key from peer for seeding", "from", senderId)
		s.generatedKey = k
	}

	if !bytes.Equal(k, s.generatedKey) {
		panic(fmt.Errorf("mismatch key received from %v", senderId))
	}

	var st *keyExchange
	st, ok := s.keyExchangeStat[senderId]
	if !ok {
		st = &keyExchange{
			receivedFrom: true,
			sentTo:       false,
		}
		s.keyExchangeStat[senderId] = st
		slog.Info("receive seed key", "sender", senderId)
	} else {
		st.receivedFrom = true
		slog.Info("mark received seed key", "sender", senderId)
	}

	// Redistribute to the other seed peers, wrapped per recipient.
	go s.forwardKeyToOtherSeedPeers()

	if s.hasReceivedKeysFromAllSeedPeers() {
		slog.Info("enough key copies from peer")
		return k[:]
	} else {
		return make([]byte, 0)
	}
}

func (c *Node) seed(peers []*memberlist.Node) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.state.state = NODE_STATE_SEEDING
	c.stateChangeMessages <- NODE_STATE_SEEDING

	otherOnlinePeers := []*memberlist.Node{}
	for _, p := range peers {
		if p.Name != c.id {
			otherOnlinePeers = append(otherOnlinePeers, p)
		}
	}

	peersNeededForSeed := common.NewSet()
	peersNeededForSeed.Add(c.id)
	peersNeededForSeed.AddAll(c.state.seed.otherSeedNodes)
	allSeedNodes := peersNeededForSeed.Sorted()

	first := allSeedNodes[0]

	//gen MK
	isMaster := first == c.id
	slog.Info("Seeding", "master", first, "isMe", isMaster)

	// Publish this node's attested ephemeral key first: no peer can wrap the
	// seed key to this node until its offer has been seen.
	if err := c.state.seed.prepareOffer(c.attestor, c.cluster, otherOnlinePeers); err != nil {
		panic(fmt.Errorf("cannot prepare seed offer: %w", err))
	}

	if isMaster {
		slog.Info("first node in peer list, will generate a masterkey here", "nodeId", first)
		mkey := make([]byte, masterKeyLen)
		rand.Read(mkey)
		c.state.seed.startSeedAsMaster(mkey, otherOnlinePeers)
	} else {
		c.state.seed.startSeedAsSlave(otherOnlinePeers)
	}
}

// handleSeedOffer records a peer's attested ephemeral key. An offer may unblock
// a wrap that was waiting for it, so the forward loop is re-driven.
func (c *Node) handleSeedOffer(p *PeerMessage) {
	var offer seedOffer
	if err := json.Unmarshal(p.Data, &offer); err != nil {
		slog.Error("malformed seed offer", "from", p.Sender.Id, "error", err)
		return
	}
	if err := verifySeedOffer(c.attestor, c.cluster, &offer); err != nil {
		slog.Error("rejecting seed offer", "from", p.Sender.Id, "error", err)
		return
	}
	if c.state.seed.storeOffer(p.Sender.Id, &offer) {
		slog.Info("stored seed offer", "from", p.Sender.Id)
		go c.state.seed.forwardKeyToOtherSeedPeers()
	}
}

func (c *Node) handleSeedKey(msg *PeerMessage) {
	kx, offer := c.state.seed.localOffer()
	if kx == nil || offer == nil {
		slog.Error("dropping seed key: no local offer for this round", "from", msg.Sender.Id)
		return
	}
	var init seedKeyInit
	if err := json.Unmarshal(msg.Data, &init); err != nil {
		slog.Error("malformed seed key-init", "from", msg.Sender.Id, "error", err)
		return
	}
	plain, err := unwrapSeedKey(c.attestor, c.cluster, kx, offer, &init)
	if err != nil {
		slog.Error("rejecting seed key", "from", msg.Sender.Id, "error", err)
		return
	}

	k := c.state.seed.keyReceived(plain, msg.Sender.Id)
	if len(k) > 0 {
		c.lock.Lock()
		defer c.lock.Unlock()
		slog.Info("got enough seed keys from peers, will clean other peers and mark seed complete", "node", c.id)
		scr := &common.MasterSecret{
			Secret:  hex.EncodeToString(k),
			Created: uint64(time.Now().UnixMilli()),
		}
		c.masterKs.Write(scr)
		slog.Info("stored MK locally")
		c.state.state = NODE_STATE_READY
		c.stateChangeMessages <- NODE_STATE_READY
	}
}

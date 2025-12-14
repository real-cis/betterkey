package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
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

	if len(s.otherSeedNodes) == len(s.keyExchangeStat) {
		for _, ex := range s.keyExchangeStat {
			if !ex.sentTo || !ex.receivedFrom {
				return
			}
		}
	}
	slog.Info("all seed-exchange peers marked as sent and received, cleanup")
	s.generatedKey = make([]byte, 0)
	s.keyExchangeStat = map[string]*keyExchange{}
	s.otherSeedNodes = []string{}
	s.otherMembers = []*memberlist.Node{}
}

func (s *seed) fowardKeyToOtherSeedPeers(pm []byte) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for _, pName := range s.otherSeedNodes {
		var ex *keyExchange
		ex, ok := s.keyExchangeStat[pName]
		if !ok {
			ex = &keyExchange{
				sentTo:       false,
				receivedFrom: false,
			}
			s.keyExchangeStat[pName] = ex
		}
		if !ex.sentTo {
			for _, n := range s.otherMembers {
				if n.Name == pName {
					err := s.msgSender.SendReliable(n, pm)
					if err == nil {
						ex.sentTo = true
						slog.Info("mark forwarding key to other seed peer ok", "name", pName)
					} else {
						slog.Error("error forwarding key to other seed peer", "name", pName, "error", err)
					}
				}
			}

		}
	}
	go s.checkCleanup()
}

type MessageSender interface {
	SendReliable(n *memberlist.Node, msg []byte) error
}

var dummyKey = []byte{1}

func (s *seed) startSeedAsMaster(keyInit *PeerMessage, otherMembers []*memberlist.Node) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if len(keyInit.Data) != 32 {
		panic(fmt.Errorf("requires keysize 32, got %v", len(keyInit.Data)))
	}

	s.generatedKey = keyInit.Data
	s.keyExchangeStat = map[string]*keyExchange{}
	s.otherMembers = otherMembers

	go func() {
		d, err := keyInit.toJson()
		if err != nil {
			slog.Error("cannot serialize keyinit msg", "err", err)
			return
		}
		for _, peer := range s.otherMembers {
			slog.Info("sending seed-key", "to", peer.Name)
			err = s.msgSender.SendReliable(peer, d)
			if err != nil {
				slog.Error("error sending seed-key msg.TODO: schedule resending", "to", peer.Name, "err", err)
			}
		}
	}()
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

	pMsg := &PeerMessage{
		Type:   MSG_TYPE_KEYINIT,
		Sender: s.id,
		Data:   k[:],
	}
	b, err := pMsg.toJson()
	if err == nil {
		go s.fowardKeyToOtherSeedPeers(b)
	}

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

	if isMaster {
		slog.Info("first node in peer list, will generate a masterkey here", "nodeId", first)
		mkey := make([]byte, 32)
		rand.Read(mkey)
		keyInit := &PeerMessage{
			Type:   MSG_TYPE_KEYINIT,
			Data:   mkey[:],
			Sender: c.state.nodeInfo,
		}
		c.state.seed.startSeedAsMaster(keyInit, otherOnlinePeers)
	} else {
		c.state.seed.startSeedAsSlave(otherOnlinePeers)
	}
}

func (c *Node) handleSeedKey(msg *PeerMessage) {
	k := c.state.seed.keyReceived(msg.Data, msg.Sender.Id)
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

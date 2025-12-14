package cluster

import (
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/hashicorp/memberlist"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

type NodeInfo struct {
	Id        string `json:"id"`
	ClusterId string `json:"clusterId"`
}

type MasterSecret struct {
	Secret    string `json:"secret"`
	CreatorId string `json:"creatorId"`
	Created   uint64 `json:"created"`
}

type Member struct {
	NodeInfo     *NodeInfo     `json:"nodeInfo"`
	MasterSecret *MasterSecret `json:"masterSecret"`
}

type NodeState struct {
	nodeInfo *common.NodeInfo
	state    int
	seed     *seed
}

// hook to callback when state of node is set
type StateListener interface {
	HeartBeatHandler
	OnStateChanged(state int)
}

const (
	MSG_TYPE_CHALLENGE      = 1
	MSG_TYPE_CHALLENGE_RESP = 2
	MSG_TYPE_KEYQUERY       = 3
	MSG_TYPE_KEYQUERY_RESP  = 4
	MSG_TYPE_KEYINIT        = 5
)

const (
	NODE_STATE_NO_KEY     = 1
	NODE_STATE_SEEDING    = 2
	NODE_STATE_VALIDATING = 3
	NODE_STATE_QUERY_KEY  = 4
	NODE_STATE_READY      = 5
)

type PeerMessage struct {
	Sender *common.NodeInfo `json:"sender"`
	Type   int              `json:"type"`
	Data   []byte           `json:"data"`
}

func (m *PeerMessage) toJson() ([]byte, error) {
	return json.Marshal(m)
}

func (c *Node) setStatus(stat int) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.state.state = stat
	c.stateChangeMessages <- stat
}

func (c *Node) notifyStateChange() {
	for {
		st := <-c.stateChangeMessages
		if c.stateListener != nil {
			c.stateListener.OnStateChanged(st)
		}
	}
}

func (c *Node) loop() {
	for {
		msg, ok := <-c.inMessages
		if !ok {
			// channel closed, exit gracefully
			slog.Debug("inMessages channel closed, exiting loop")
			return
		}
		state := c.NodeStatus().State
		slog.Debug("received hb message", "type", msg.Type, "from", msg.Sender.Id, "currentState", state)
		switch state {
		case 0:
			slog.Info("Not ready yet")
		case NODE_STATE_SEEDING:
			if msg.Type == MSG_TYPE_KEYINIT {
				c.handleSeedKey(&msg)
			} else {
				slog.Info("drop msg", "type", msg.Type, "currentState", state)
			}
		case NODE_STATE_READY:
			switch msg.Type {
			case MSG_TYPE_KEYQUERY:
				c.handleQueryKey(&msg)
			case MSG_TYPE_CHALLENGE:
				c.handleKeyChallengeRequest(&msg)
			}
		case NODE_STATE_VALIDATING:
			if msg.Type == MSG_TYPE_CHALLENGE_RESP {
				c.handleKeyChallengeResponse(&msg)
			}
		case NODE_STATE_QUERY_KEY:
			if msg.Type == MSG_TYPE_KEYQUERY_RESP {
				c.handleKeyResponse(&msg)
			}
		}
	}
}

func (s *Node) copyClusterPeers() []*memberlist.Node {
	otherPeers := []*memberlist.Node{}
	for _, op := range s.list.Members() {
		cl := &memberlist.Node{
			Name:  op.Name,
			Addr:  op.Addr,
			Port:  op.Port,
			Meta:  op.Meta,
			State: op.State,
			PMin:  op.PMin,
			PMax:  op.PMax,
			PCur:  op.PCur,
			DMin:  op.DMin,
			DMax:  op.DMax,
			DCur:  op.DCur,
		}
		otherPeers = append(otherPeers, cl)
	}
	return otherPeers
}

func sortedPeerNames(peers []*memberlist.Node) []string {
	s := common.NewSet()
	for _, p := range peers {
		s.Add(p.Name)
	}
	return s.Sorted()
}

func (c *Node) onNoKey() {
	c.setStatus(NODE_STATE_NO_KEY)
	// wait until joined
	for {
		pc, err := c.list.Join(c.configuredPeerAddresses)
		if pc == 0 {
			slog.Error("no peers on join(), no peers up ?. wait loop", "error", err, "peers", pc)
			time.Sleep(5 * time.Second)
		} else {
			slog.Info("joined", "error", err, "peers", pc)
			break
		}
	}

	for {
		joinedMembers := c.list.Members()
		slog.Info("loop list members", "member counts", len(joinedMembers))

		for _, m := range joinedMembers {
			ni, err := NodeMetaFromBytes(m.Meta)
			if err == nil {
				slog.Debug("Peer", "id", ni.Id, "state", ni.State)
			}
		}
		membersCanProvideKey := membersCanProvideKey(joinedMembers)

		if membersCanProvideKey {
			c.queryKey(joinedMembers)
			break
		}

		slog.Info("no active peer can provide key")
		// only attempt participate seeding if this is in the list
		if slices.Contains(c.seedNodes, c.id) {
			slog.Info("node in seed list, check precondition to start seeding", "id", c.id)
			seedSet := common.NewSet()
			seedSet.AddAll(c.seedNodes)
			seedSet.Add(c.id)

			sortedJoinedPeers := sortedPeerNames(joinedMembers)
			var allSeedPeersJoined = true
			seeds := seedSet.Sorted()

			for _, seedNode := range seeds {
				if !slices.Contains(sortedJoinedPeers, seedNode) {
					allSeedPeersJoined = false
					break
				}
			}

			slog.Info("onNoKey", "membersCanProvideKey", membersCanProvideKey, "allSeedPeersJoined", allSeedPeersJoined)

			// only seed when memberlist is fixed
			if allSeedPeersJoined {
				c.seed(c.copyClusterPeers())
				break
			}
		} else {
			slog.Info("not in seedlist, wait", "id", c.id, "seeds", c.seedNodes)
		}

		slog.Info("wait loop until either seed or can ask key from other peer")
		time.Sleep(2 * time.Second)
	}
}

func NodeMetaFromBytes(ni []byte) (*common.NodeMeta, error) {
	var nm common.NodeMeta
	err := json.Unmarshal(ni, &nm)
	if err != nil {
		slog.Error("bad json for NodeData", "error", err)
		return nil, err
	}
	return &nm, nil
}

func membersCanProvideKey(nodes []*memberlist.Node) bool {
	for _, m := range nodes {
		ni, err := NodeMetaFromBytes(m.Meta)
		if err == nil && ni.State == NODE_STATE_READY {
			return true
		}
	}
	return false
}

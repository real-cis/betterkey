package cluster

import (
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/hashicorp/memberlist"
	"gitlab.com/real-cis/cc/betterkey/internal/common"
)

func (c *Node) queryKey(peers []*memberlist.Node) {
	c.setStatus(NODE_STATE_QUERY_KEY)
	go func() {
		for _, m := range peers {
			//don't ask myself
			if m.Name != c.id {
				nm, err := NodeMetaFromBytes(m.Meta)
				if err == nil && nm.State == NODE_STATE_READY {
					slog.Info("attempt query key", "to", m.Addr)
					pm := &PeerMessage{
						Type:   MSG_TYPE_KEYQUERY,
						Sender: c.state.nodeInfo,
					}
					d, _ := pm.toJson()
					err := c.list.SendReliable(m, d)
					if err != nil {
						slog.Error("failed sending key-query", "error", err)
					}
					break
				}
			}
		}
	}()
}

func (c *Node) handleQueryKey(p *PeerMessage) {
	mk := c.masterKs.Read()
	k, err := hex.DecodeString(mk.MasterSecret.Secret)
	if err != nil {
		panic(err)
	}
	pmsg := &PeerMessage{
		Sender: c.state.nodeInfo,
		Type:   MSG_TYPE_KEYQUERY_RESP,
		Data:   k,
	}
	pl, err := pmsg.toJson()
	if err != nil {
		slog.Error("error serializing MSG_TYPE_KEYQUERY_RESP", "error", err)
	}
	go func() {
		for {
			for _, m := range c.list.Members() {
				if m.Name != p.Sender.Id {
					continue
				}
				slog.Info("sending key", "to", m.Addr)
				err = c.list.SendReliable(m, pl)
				if err != nil {
					slog.Error("error sending MSG_TYPE_KEYQUERY_RESP", "error", err)
				}
				return
			}
			// Sender not yet visible in member list (gossip not propagated).
			// Retry until it appears.
			slog.Debug("handleQueryKey: sender not yet in member list, retrying", "sender", p.Sender.Id)
			time.Sleep(500 * time.Millisecond)
		}
	}()
}

func (c *Node) handleKeyResponse(p *PeerMessage) {
	c.lock.Lock()
	defer c.lock.Unlock()
	slog.Info("got key, will save and update local status", "from", p.Sender.Id)
	mk := &common.MasterSecret{
		Secret:  hex.EncodeToString(p.Data),
		Created: uint64(time.Now().UnixMilli()),
	}
	c.masterKs.Write(mk)
	c.state.state = NODE_STATE_READY
	c.stateChangeMessages <- NODE_STATE_READY
}

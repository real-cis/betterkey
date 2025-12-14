package cluster

import (
	"errors"
	"fmt"
	"log/slog"
	"time"
)

func (c *Node) validatingExistingKey() {
	c.setStatus(NODE_STATE_VALIDATING)
	for {
		c, err := c.list.Join(c.configuredPeerAddresses)
		if err != nil {
			slog.Error("Error joining, will retry", "error", err)
			time.Sleep(5 * time.Second)
		} else {
			slog.Info("joined cluster", "members", c)
			break
		}
	}

	// wait until someone has key
	joinedMembers := c.list.Members()
	for {
		if !membersCanProvideKey(c.list.Members()) {
			slog.Info("no member has key, loop wait")
			time.Sleep(5 * time.Second)
		} else {
			break
		}
	}

	// send challenge
	peerMsg := PeerMessage{
		Sender: c.state.nodeInfo,
		Type:   MSG_TYPE_CHALLENGE,
		Data:   []byte(c.state.nodeInfo.Id),
	}
	msg, _ := peerMsg.toJson()
	go func() {
		for _, m := range joinedMembers {
			if m.Name != c.id {
				nm, err := NodeMetaFromBytes(m.Meta)
				if err == nil && nm.State == NODE_STATE_READY {
					slog.Info("sending one challenge", "to", m.Name)
					// send challenge
					err := c.list.SendReliable(m, msg)
					if err == nil {
						slog.Info("challenge sent, wait for response", "to", m.Name)
						return
					} else {
						slog.Error("error sending challenge-TODO RESEND", "to", m.Name, "error", err)

					}
				}
			}
		}
	}()
}

func (c *Node) handleKeyChallengeResponse(p *PeerMessage) {
	c.lock.Lock()
	defer c.lock.Unlock()

	localId := c.masterKs.Read()
	if localId == nil {
		panic(errors.New("local key-storage gone"))
	}
	dec, err := localId.Unseal(p.Data)
	if err != nil {
		panic(err)
	}
	//check remote clusterId ?
	if string(dec) != localId.NodeInfo.Id {
		panic(fmt.Errorf("localId(%s) and id sendback(%s) from peer(%s) not match", localId.NodeInfo.Id, string(dec), p.Sender.Id))
	}
	slog.Info("challenge-response valid, setting to ready", "from", p.Sender.Id)
	c.state.state = NODE_STATE_READY
	c.stateChangeMessages <- NODE_STATE_READY
}

func (c *Node) handleKeyChallengeRequest(p *PeerMessage) {
	c.lock.Lock()
	defer c.lock.Unlock()

	localId := c.masterKs.Read()
	if localId == nil {
		panic(errors.New("local key-storage gone"))
	}
	enc, err := localId.Seal(p.Data)
	if err != nil {
		panic(err)
	}

	pm := &PeerMessage{
		Type:   MSG_TYPE_CHALLENGE_RESP,
		Sender: c.state.nodeInfo,
		Data:   enc,
	}
	b, _ := pm.toJson()
	go func() {
		for {
			for _, m := range c.list.Members() {
				if m.Name == p.Sender.Id {
					if err == nil {
						err = c.list.SendReliable(m, b)
						if err != nil {
							slog.Error("Error sending challenge-resp/TODO: resend ?", "to", m.Name)
							break
						} else {
							slog.Info("sent challenge-resp", "to", m.Name)
							return
						}
					}
				}
			}
			slog.Info("loop to retry sending challenge-resp", "to", p.Sender.Id)
			time.Sleep(5 * time.Second)
		}
	}()
}

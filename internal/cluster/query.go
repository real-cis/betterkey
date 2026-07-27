// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
			if m.Name == c.id {
				continue
			}
			nm, err := NodeMetaFromBytes(m.Meta)
			if err != nil || nm.State != NODE_STATE_READY {
				continue
			}
			msg, err := c.newKeyQuery()
			if err != nil {
				slog.Error("failed building key-query", "error", err)
				return
			}
			slog.Info("attempt query key", "to", m.Addr)
			if err := c.list.SendReliable(m, msg); err != nil {
				slog.Error("failed sending key-query", "error", err)
			}
			break
		}
	}()
}

// newKeyQuery generates this node's ephemeral key pair, quotes it, and records
// the private half so that only this node can unwrap the response.
func (c *Node) newKeyQuery() ([]byte, error) {
	req, pending, err := newKeyExchangeRequest(c.attestor)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	c.lock.Lock()
	c.pendingKx = pending
	c.lock.Unlock()

	pm := &PeerMessage{
		Type:   MSG_TYPE_KEYQUERY,
		Sender: c.state.nodeInfo,
		Data:   payload,
	}
	return pm.toJson()
}

// handleQueryKey answers a key query by wrapping the master key to an ephemeral
// key that the requesting enclave proved it holds. The plaintext master key
// never reaches the wire, so relaying the transport yields ciphertext only.
func (c *Node) handleQueryKey(p *PeerMessage) {
	resp, err := c.buildKeyResponse(p)
	if err != nil {
		slog.Error("rejecting key query", "from", p.Sender.Id, "error", err)
		return
	}
	go func() {
		for {
			for _, m := range c.list.Members() {
				if m.Name != p.Sender.Id {
					continue
				}
				slog.Info("sending wrapped key", "to", m.Addr)
				if err := c.list.SendReliable(m, resp); err != nil {
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

func (c *Node) buildKeyResponse(p *PeerMessage) ([]byte, error) {
	var req keyExchangeRequest
	if err := json.Unmarshal(p.Data, &req); err != nil {
		return nil, fmt.Errorf("malformed key-exchange request: %w", err)
	}

	mk := c.masterKs.Read()
	if mk == nil || mk.MasterSecret == nil {
		return nil, errors.New("no local master key to share")
	}
	secret, err := hex.DecodeString(mk.MasterSecret.Secret)
	if err != nil {
		return nil, fmt.Errorf("corrupt local master key: %w", err)
	}

	resp, err := wrapMasterKey(c.attestor, &req, secret)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}

	pm := &PeerMessage{
		Sender: c.state.nodeInfo,
		Type:   MSG_TYPE_KEYQUERY_RESP,
		Data:   payload,
	}
	return pm.toJson()
}

func (c *Node) handleKeyResponse(p *PeerMessage) {
	c.lock.Lock()
	defer c.lock.Unlock()

	// A response is only meaningful for the exchange this node started; drop the
	// pending state either way so a failed attempt cannot be replayed later.
	pending := c.pendingKx
	c.pendingKx = nil
	if pending == nil {
		slog.Error("unsolicited key response", "from", p.Sender.Id)
		return
	}

	var resp keyExchangeResponse
	if err := json.Unmarshal(p.Data, &resp); err != nil {
		slog.Error("malformed key-exchange response", "from", p.Sender.Id, "error", err)
		return
	}
	secret, err := unwrapMasterKey(c.attestor, pending, &resp)
	if err != nil {
		// The node stays in QUERY_KEY; a later queryKey() starts a fresh exchange.
		slog.Error("rejecting key response", "from", p.Sender.Id, "error", err)
		return
	}

	slog.Info("got key, will save and update local status", "from", p.Sender.Id)
	c.masterKs.Write(&common.MasterSecret{
		Secret:  hex.EncodeToString(secret),
		Created: uint64(time.Now().UnixMilli()),
	})
	c.state.state = NODE_STATE_READY
	c.stateChangeMessages <- NODE_STATE_READY
}

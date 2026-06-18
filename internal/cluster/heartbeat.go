// Copyright 2025-2026 real-cis GmbH
// SPDX-License-Identifier: MIT

package cluster

import (
	"bytes"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"gitlab.com/real-cis/cc/betterkey/internal/common"
	"gitlab.com/real-cis/cc/betterkey/internal/crypto"
)

type HeartBeatManager struct {
	encProvider func() common.Vault
	// actual buffer for all events, processed events will be removed
	samples []*peerHeartBeat
	lock    *sync.Mutex
	//only collect events since last run and within this range  run
	window        time.Duration
	interval      time.Duration
	stopC         chan struct{}
	lastRunTs     int64
	windowHandler HeartBeatHandler
	nodeState     *NodeState
}

type peerHeartBeat struct {
	id, nonce, encryptedNonce string
	ts                        int64
}

type HeartBeatHandler interface {
	OnHeartBeatWindow(w *common.HeartBeatWindow)
}

func NewHeartBeatManager(encProvider func() common.Vault, window, granularity time.Duration,
	windowHandler HeartBeatHandler, nodeState *NodeState) *HeartBeatManager {
	return &HeartBeatManager{
		encProvider:   encProvider,
		samples:       []*peerHeartBeat{},
		lock:          &sync.Mutex{},
		window:        window,
		interval:      granularity,
		stopC:         make(chan struct{}),
		lastRunTs:     time.Now().Unix(),
		windowHandler: windowHandler,
		nodeState:     nodeState,
	}
}

func (hbm *HeartBeatManager) LocalHeartBeat() *common.HeartBeat {
	vault := hbm.encProvider()
	if vault == nil {
		slog.Info("no masterkey locally available, no heartbeat")
		return nil
	}
	nonce := crypto.GenerateNonce(16)
	encNonce, err := vault.Seal(nonce)
	if err != nil {
		slog.Error("cannot encrypt nonce", "error", err)
		panic(err)
	}
	return &common.HeartBeat{
		Nonce: hex.EncodeToString(nonce),
		Value: hex.EncodeToString(encNonce),
	}
}

func (hbm *HeartBeatManager) Start() {
	ticker := time.NewTicker(hbm.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now().Unix()
			max := int64(hbm.window.Seconds())
			hbm.lock.Lock()
			//split data
			data := []*peerHeartBeat{}
			samples := []*peerHeartBeat{}
			for _, s := range hbm.samples {
				if s.ts < hbm.lastRunTs {
					slog.Error("BAD! event appears before last run, drop", "id", s.id)
				} else {
					if s.ts-hbm.lastRunTs <= max {
						data = append(data, s)
					} else {
						samples = append(samples, s)
					}
				}
			}
			hbm.samples = samples
			hbm.lastRunTs = now
			hbm.lock.Unlock()
			go hbm.processWindow(data)
		case <-hbm.stopC:
			return
		}
	}
}

func (hbm *HeartBeatManager) Stop() {
	hbm.stopC <- struct{}{}
}

func (hbm *HeartBeatManager) processWindow(data []*peerHeartBeat) {
	stats := make(map[string]*common.HeartBeatStat)
	seenHb := &common.HeartBeatWindow{
		From:   hbm.lastRunTs,
		Window: int64(hbm.window.Seconds()),
		Stats:  &stats,
	}
	slog.Debug("Processing heartbeat window", "from", seenHb.From,
		"window", seenHb.Window, "samples", len(data), "node-state", hbm.nodeState.state)
	if hbm.nodeState.state != NODE_STATE_READY {
		slog.Info("node not in ready state, skip processing heartbeats", "state", hbm.nodeState.state)
		return
	}
	for _, hb := range data {
		err := hbm.validateNonce(hb)
		if err != nil {
			slog.Error("heartbeat invalid/wrong nonce value", "id", hb.id, "error", err)
		}
		ps, ok := (*seenHb.Stats)[hb.id]
		if ok {
			ps.Total = ps.Total + 1
			if err != nil {
				ps.Errors = ps.Errors + 1
			}
		} else {
			seen := &common.HeartBeatStat{
				Total:  1,
				Errors: 0,
			}
			if err != nil {
				seen.Errors = 1
			}
			(*seenHb.Stats)[hb.id] = seen
		}
	}
	if hbm.windowHandler != nil {
		hbm.windowHandler.OnHeartBeatWindow(seenHb)
	}
}

func (hbm *HeartBeatManager) validateNonce(hb *peerHeartBeat) error {
	enc := hbm.encProvider()
	if enc == nil {
		return common.ErrNoEncryptionService
	}
	nonce, err := hex.DecodeString(hb.nonce)
	if err != nil {
		return err
	}
	encNonce, err := hex.DecodeString(hb.encryptedNonce)
	if err != nil {
		return err
	}
	decryptedNonce, err := enc.Unseal(encNonce)
	if err != nil {
		return err
	}
	if !bytes.Equal(nonce, decryptedNonce) {
		return common.ErrHeartBeatNonceMismatched
	}
	return nil
}

func (hbm *HeartBeatManager) OnRemoteHeartBeat(peerId string, hb common.HeartBeat) {
	phb := &peerHeartBeat{
		id:             peerId,
		nonce:          hb.Nonce,
		encryptedNonce: hb.Value,
		ts:             time.Now().Unix(),
	}
	hbm.lock.Lock()
	defer hbm.lock.Unlock()
	hbm.samples = append(hbm.samples, phb)
}

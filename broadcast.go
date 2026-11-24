// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

/*
The broadcast mechanism works by maintaining a sorted list of messages to be
sent out. When a message is to be broadcast, the retransmit count
is set to zero and appended to the queue. The retransmit count serves
as the "priority", ensuring that newer messages get sent first. Once
a message hits the retransmit limit, it is removed from the queue.

Additionally, older entries can be invalidated by new messages that
are contradictory. For example, if we send "{suspect M1 inc: 1},
then a following {alive M1 inc: 2} will invalidate that message
*/

import (
	"net"
	"time"
)

type memberlistBroadcast struct {
	node    string
	msg     []byte
	notify  chan struct{}
	ttl     time.Duration
	targets []string
}

func (b *memberlistBroadcast) Invalidates(other Broadcast) bool {
	// Check if that broadcast is a memberlist type
	mb, ok := other.(*memberlistBroadcast)
	if !ok {
		return false
	}

	// Invalidates any message about the same node
	return b.node == mb.node
}

// memberlist.NamedBroadcast optional interface
func (b *memberlistBroadcast) Name() string {
	return b.node
}

func (b *memberlistBroadcast) Message() []byte {
	return b.msg
}

// BroadcastTTL implements BroadcastTTL. A zero ttl means the queue default
// applies (see queueBroadcast).
func (b *memberlistBroadcast) BroadcastTTL() time.Duration {
	return b.ttl
}

// BroadcastTargets implements BroadcastTarget, enabling the entry to be
// released as soon as every destination node has acknowledged it.
func (b *memberlistBroadcast) BroadcastTargets() []string {
	return b.targets
}

func (b *memberlistBroadcast) Finished() {
	if b.notify == nil {
		return
	}
	select {
	case b.notify <- struct{}{}:
	default:
	}
}

// encodeAndBroadcast encodes a message and enqueues it for broadcast. Fails
// silently if there is an encoding error.
func (m *Memberlist) encodeAndBroadcast(node string, msgType messageType, msg any) {
	m.encodeBroadcastNotify(node, msgType, msg, nil)
}

// encodeBroadcastNotify encodes a message and enqueues it for broadcast
// and notifies the given channel when transmission is finished. Fails
// silently if there is an encoding error.
func (m *Memberlist) encodeBroadcastNotify(node string, msgType messageType, msg any, notify chan struct{}) {
	buf, err := encode(msgType, msg, m.config.MsgpackUseNewTimeFormat)
	if err != nil {
		m.logger.Printf("[ERR] memberlist: Failed to encode message for broadcast: %s", err)
	} else {
		m.queueBroadcast(node, buf.Bytes(), notify)
	}
}

// queueBroadcast is used to start dissemination of a message. It will be
// sent up to a configured number of times. The message could potentially
// be invalidated by a future message about the same node.
//
// All production call sites enqueue while holding nodeLock (the state-change
// handlers), so the gossip target set is computed via the lock-free helper.
func (m *Memberlist) queueBroadcast(node string, msg []byte, notify chan struct{}) {
	b := &memberlistBroadcast{
		node:   node,
		msg:    msg,
		notify: notify,
		ttl:    m.config.BroadcastTTL,
	}
	// Target tracking is opt-in: without it the entry is released by the
	// retransmit limit exactly as in the historical implementation.
	if m.config.EnableGossipAck {
		b.targets = m.gossipTargetsLocked()
	}
	m.broadcasts.QueueBroadcast(b)
}

// gossipTargets returns the names of the remote nodes that are currently
// alive or suspect and therefore valid gossip destinations. The local node
// is excluded: it originates the message and never acknowledges itself.
func (m *Memberlist) gossipTargets() []string {
	m.nodeLock.RLock()
	defer m.nodeLock.RUnlock()
	return m.gossipTargetsLocked()
}

// gossipTargetsLocked computes gossip targets under the assumption that the
// caller already holds nodeLock (read or write). The state-change handlers
// enqueue broadcasts while holding nodeLock, so re-locking here would
// self-deadlock.
func (m *Memberlist) gossipTargetsLocked() []string {
	targets := make([]string, 0, len(m.nodeMap))
	for name, n := range m.nodeMap {
		if name == m.config.Name {
			continue
		}
		if n.State == StateAlive || n.State == StateSuspect {
			targets = append(targets, name)
		}
	}
	return targets
}

// ackBroadcast records that the named sender node has acknowledged receipt
// of the broadcast identified by node (the subject of the state change).
// It is invoked from the inbound state-change handlers so that a message
// echoed back by a peer counts as confirmation; once every gossip target has
// confirmed, the queue entry is released immediately.
func (m *Memberlist) ackBroadcast(node, from string) {
	if !m.config.EnableGossipAck {
		return
	}
	if node == "" || from == "" || node == from {
		// A node never needs to acknowledge its own state change, and both
		// names are required to identify the queue entry.
		return
	}
	// Release (if this completes the target set) is counted by the queue
	// and surfaced through checkBroadcastQueueDepth.
	m.broadcasts.AckBroadcast(node, from)
}

// nodeNameByAddr resolves the name of the peer that sent a packet from its
// transport address. Node names are not required to be IP addresses, so a
// miss is reported as an empty string rather than an error.
func (m *Memberlist) nodeNameByAddr(from net.Addr) string {
	if from == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(from.String())
	if err != nil {
		host = from.String()
	}
	m.nodeLock.RLock()
	defer m.nodeLock.RUnlock()
	for name, n := range m.nodeMap {
		if n.Node.Addr != nil && n.Node.Addr.String() == host {
			return name
		}
	}
	// Fall back to the bare-IP naming convention, where the node name is
	// the address without port.
	if _, ok := m.nodeMap[host]; ok {
		return host
	}
	return ""
}

// getBroadcasts is used to return a slice of broadcasts to send up to
// a maximum byte size, while imposing a per-broadcast overhead. This is used
// to fill a UDP packet with piggybacked data
func (m *Memberlist) getBroadcasts(overhead, limit int) [][]byte {
	// Get memberlist messages first
	toSend := m.broadcasts.GetBroadcasts(overhead, limit)

	// Check if the user has anything to broadcast
	d := m.config.Delegate
	if d != nil {
		// Determine the bytes used already
		bytesUsed := 0
		for _, msg := range toSend {
			bytesUsed += len(msg) + overhead
		}

		// Check space remaining for user messages
		avail := limit - bytesUsed
		if avail > overhead+userMsgOverhead {
			userMsgs := d.GetBroadcasts(overhead+userMsgOverhead, avail)

			// Frame each user message
			for _, msg := range userMsgs {
				buf := make([]byte, 1, len(msg)+1)
				buf[0] = byte(userMsg)
				buf = append(buf, msg...)
				toSend = append(toSend, buf)
			}
		}
	}
	return toSend
}

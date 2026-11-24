// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemberlistBroadcast_Invalidates(t *testing.T) {
	m1 := &memberlistBroadcast{node: "test", msg: nil, notify: nil}
	m2 := &memberlistBroadcast{node: "foo", msg: nil, notify: nil}

	if m1.Invalidates(m2) || m2.Invalidates(m1) {
		t.Fatalf("unexpected invalidation")
	}

	if !m1.Invalidates(m1) {
		t.Fatalf("expected invalidation")
	}
}

func TestMemberlistBroadcast_Message(t *testing.T) {
	m1 := &memberlistBroadcast{node: "test", msg: []byte("test")}
	msg := m1.Message()
	if !reflect.DeepEqual(msg, []byte("test")) {
		t.Fatalf("messages do not match")
	}
}

// newTestMemberlist builds a memberlist without starting its network
// goroutines, so queue behavior can be tested deterministically.
func newTestMemberlist(t *testing.T) *Memberlist {
	t.Helper()
	c := testConfig(t)
	c.BroadcastTTL = 0
	c.MaxBroadcastQueue = 0
	m, err := newMemberlist(c)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown() })
	return m
}

func TestMemberlist_QueueBroadcast_TTLWired(t *testing.T) {
	m := newTestMemberlist(t)

	now, advance := newTestClock()
	m.broadcasts.Now = now
	m.config.BroadcastTTL = 50 * time.Millisecond

	m.queueBroadcast("node-a", []byte("1. this is a test."), nil)
	require.Equal(t, 1, m.broadcasts.NumQueued())

	// After the configured TTL the entry is swept on the next read and
	// counted, instead of being retransmitted forever.
	advance(100 * time.Millisecond)
	got := m.getBroadcasts(2, 80)
	require.Empty(t, got)
	require.Equal(t, int64(1), m.broadcasts.NumExpired())
}

func TestMemberlist_GossipTargets(t *testing.T) {
	m := newTestMemberlist(t)

	m.nodeLock.Lock()
	m.nodeMap["alive-1"] = &nodeState{Node: Node{Name: "alive-1"}, State: StateAlive}
	m.nodeMap["suspect-1"] = &nodeState{Node: Node{Name: "suspect-1"}, State: StateSuspect}
	m.nodeMap["dead-1"] = &nodeState{Node: Node{Name: "dead-1"}, State: StateDead}
	m.nodeMap[m.config.Name] = &nodeState{Node: Node{Name: m.config.Name}, State: StateAlive}
	m.nodeLock.Unlock()

	targets := m.gossipTargets()
	require.ElementsMatch(t, []string{"alive-1", "suspect-1"}, targets)
}

func TestMemberlist_AckBroadcast_ReleasesAfterAllTargets(t *testing.T) {
	m := newTestMemberlist(t)
	m.config.EnableGossipAck = true

	m.nodeLock.Lock()
	m.nodeMap["n1"] = &nodeState{Node: Node{Name: "n1"}, State: StateAlive}
	m.nodeMap["n2"] = &nodeState{Node: Node{Name: "n2"}, State: StateAlive}
	m.nodeMap[m.config.Name] = &nodeState{Node: Node{Name: m.config.Name}, State: StateAlive}
	m.nodeLock.Unlock()

	notify := make(chan struct{}, 1)
	m.queueBroadcast("subject-node", []byte("1. this is a test."), notify)
	require.Equal(t, 1, m.broadcasts.NumQueued())

	// Each inbound state-change from a gossip target counts as an ack. The
	// local node is excluded from the target set at enqueue time.
	m.ackBroadcast("subject-node", "n1")
	require.Equal(t, 1, m.broadcasts.NumQueued())
	require.Equal(t, int64(0), m.broadcasts.NumAckReleased())

	// The final acknowledgement frees the slot immediately, well below the
	// retransmit limit.
	m.ackBroadcast("subject-node", "n2")
	require.Equal(t, 0, m.broadcasts.NumQueued())
	require.Equal(t, int64(1), m.broadcasts.NumAckReleased())

	select {
	case <-notify:
	default:
		t.Fatalf("notify channel should have been signalled on release")
	}
}

func TestMemberlist_AckBroadcast_IgnoresSelfAndUnknown(t *testing.T) {
	m := newTestMemberlist(t)
	m.config.EnableGossipAck = true
	m.queueBroadcast("subject-node", []byte("1. this is a test."), nil)

	// Self-ack and empty names must be no-ops rather than corrupting state.
	m.ackBroadcast("subject-node", "subject-node")
	m.ackBroadcast("", "n1")
	m.ackBroadcast("subject-node", "")
	require.Equal(t, 1, m.broadcasts.NumQueued())
	require.Equal(t, int64(0), m.broadcasts.NumAckReleased())
}

func TestMemberlist_NodeNameByAddr(t *testing.T) {
	m := newTestMemberlist(t)

	m.nodeLock.Lock()
	m.nodeMap["named"] = &nodeState{
		Node: Node{Name: "named", Addr: net.ParseIP("10.0.0.7")},
	}
	m.nodeMap["10.0.0.9"] = &nodeState{
		Node: Node{Name: "10.0.0.9", Addr: net.ParseIP("10.0.0.9")},
	}
	m.nodeLock.Unlock()

	require.Equal(t, "named", m.nodeNameByAddr(&net.UDPAddr{IP: net.ParseIP("10.0.0.7"), Port: 7946}))
	require.Equal(t, "10.0.0.9", m.nodeNameByAddr(&net.UDPAddr{IP: net.ParseIP("10.0.0.9"), Port: 7946}))
	require.Equal(t, "", m.nodeNameByAddr(&net.UDPAddr{IP: net.ParseIP("10.0.0.99"), Port: 7946}))
	require.Equal(t, "", m.nodeNameByAddr(nil))
}

func TestMemberlist_QueueCapacityConfig(t *testing.T) {
	c := testConfig(t)
	c.MaxBroadcastQueue = 2
	c.BroadcastTTL = 0
	m, err := newMemberlist(c)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Shutdown() })

	require.Equal(t, 2, m.broadcasts.MaxLen)

	for i := 0; i < 5; i++ {
		m.queueBroadcast(
			"node-"+string(rune('a'+i)),
			[]byte("1. this is a test."),
			nil,
		)
	}
	require.Equal(t, 2, m.broadcasts.NumQueued())
	require.Equal(t, int64(3), m.broadcasts.NumOverflow())
}

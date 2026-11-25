// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func uid555Alive(name string, inc uint32, gen uint64) *alive {
	return &alive{
		Node:        name,
		Addr:        []byte{127, 0, 0, 1},
		Port:        8001,
		Incarnation: inc,
		Generation:  gen,
		Vsn:         []uint8{ProtocolVersionMin, ProtocolVersionMax, ProtocolVersionMax, 0, 0, 0},
	}
}

func TestUID555_StaleGenerationSuspectIgnored(t *testing.T) {
	m := GetMemberlist(t, nil)
	defer func() { require.NoError(t, m.Shutdown()) }()

	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 1, From: "peer1"})
	require.Equal(t, StateSuspect, m.getNodeState("node"))

	// Recovery starts generation 2 while incarnation can remain equal.
	m.aliveNode(uid555Alive("node", 1, 2), nil, false)
	require.Equal(t, StateAlive, m.getNodeState("node"))

	m.broadcasts.Reset()
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 1, From: "late-peer"})
	require.Equal(t, StateAlive, m.getNodeState("node"))
	require.Zero(t, m.broadcasts.NumQueued(), "stale-generation suspect must not be rebroadcast")

	// The current generation can still be suspected.
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 2, From: "peer2"})
	require.Equal(t, StateSuspect, m.getNodeState("node"))
}

func TestUID555_StaleTimerCannotAdvanceNewGeneration(t *testing.T) {
	m := GetMemberlist(t, func(c *Config) {
		c.ProbeInterval = time.Millisecond
		c.SuspicionMult = 1
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 1, From: "peer1"})

	m.nodeLock.RLock()
	oldTimer := m.nodeTimers["node"]
	m.nodeLock.RUnlock()
	require.NotNil(t, oldTimer)

	m.aliveNode(uid555Alive("node", 1, 2), nil, false)

	// A reordered old timer callback must not terminalize generation 2.
	oldTimer.timeoutFn()
	require.Equal(t, StateAlive, m.getNodeState("node"))

	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 2, From: "peer1"})
	m.nodeLock.RLock()
	newTimer := m.nodeTimers["node"]
	m.nodeLock.RUnlock()
	require.NotSame(t, oldTimer, newTimer)

	newTimer.timeoutFn()
	require.Eventually(t, func() bool {
		return m.getNodeState("node") == StateDead
	}, time.Second, time.Millisecond)
}

func TestUID555_NegativeAcknowledgementClearsSuspectAndBroadcastsRecovery(t *testing.T) {
	m := GetMemberlist(t, nil)
	defer func() { require.NoError(t, m.Shutdown()) }()

	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 1, From: "peer1"})
	require.Equal(t, StateSuspect, m.getNodeState("node"))
	m.broadcasts.Reset()

	require.True(t, m.handleNegativeAck("node", 1))
	require.Equal(t, StateAlive, m.getNodeState("node"))
	require.Empty(t, m.nodeTimers)
	require.Equal(t, 1, m.broadcasts.NumQueued())

	// Recovery is edge-triggered and idempotent.
	require.False(t, m.handleNegativeAck("node", 1))

	// An older generation cannot clear a newer suspicion.
	m.suspectNode(&suspect{Node: "node", Incarnation: 2, Generation: 3, From: "peer2"})
	require.False(t, m.handleNegativeAck("node", 2))
	require.Equal(t, StateSuspect, m.getNodeState("node"))
	require.True(t, m.handleNegativeAck("node", 3))
}

func TestUID555_ActiveLeaveIsNotReclaimedByOldGeneration(t *testing.T) {
	events := make(chan NodeEvent, 8)
	m := GetMemberlist(t, func(c *Config) {
		c.Events = &ChannelEventDelegate{Ch: events}
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	join := <-events
	require.Equal(t, NodeJoin, join.Event)
	require.Equal(t, uint64(1), join.Node.Generation)

	m.deadNode(&dead{Node: "node", From: "node", Incarnation: 1, Generation: 1})
	leave := <-events
	require.Equal(t, NodeLeave, leave.Event)
	require.Equal(t, StateLeft, leave.Node.State)
	require.Equal(t, StateLeft, m.getNodeState("node"))

	// Late same-generation alive/suspect/replays must not pull it back.
	staleAlive := uid555Alive("node", 1, 1)
	staleAlive.Addr = []byte{127, 0, 0, 2}
	staleAlive.Port = 9000
	m.aliveNode(staleAlive, nil, false)
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 1, From: "late"})

	state, ok := m.nodeMap["node"]
	require.True(t, ok)
	require.Equal(t, StateLeft, state.State)
	require.Equal(t, []byte{127, 0, 0, 1}, []byte(state.Addr))
	require.Equal(t, uint16(8001), state.Port)

	select {
	case ev := <-events:
		t.Fatalf("unexpected event after stale leave replay: %+v", ev)
	case <-time.After(20 * time.Millisecond):
	}

	// A strictly newer generation is a new member instance and may join.
	m.aliveNode(uid555Alive("node", 1, 2), nil, false)
	select {
	case ev := <-events:
		require.Equal(t, NodeJoin, ev.Event)
		require.Equal(t, uint64(2), ev.Node.Generation)
	case <-time.After(time.Second):
		t.Fatal("new generation did not emit join")
	}
}

func TestUID555_PartitionTimeoutRemainsRecoverable(t *testing.T) {
	events := make(chan NodeEvent, 8)
	m := GetMemberlist(t, func(c *Config) {
		c.Events = &ChannelEventDelegate{Ch: events}
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	<-events

	// From != Node is the suspicion-timeout/network-partition path.
	m.deadNode(&dead{Node: "node", From: m.config.Name, Incarnation: 1, Generation: 1})
	require.Equal(t, StateDead, m.getNodeState("node"))
	ev := <-events
	require.Equal(t, NodeLeave, ev.Event)
	require.Equal(t, StateDead, ev.Node.State)

	// Same incarnation replay remains dead, preserving existing semantics.
	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	require.Equal(t, StateDead, m.getNodeState("node"))

	// A newer generation recovers it.
	m.aliveNode(uid555Alive("node", 2, 2), nil, false)
	require.Equal(t, StateAlive, m.getNodeState("node"))
	select {
	case ev := <-events:
		require.Equal(t, NodeJoin, ev.Event)
	case <-time.After(time.Second):
		t.Fatal("partitioned node did not emit recovery join")
	}
}

func TestUID555_EventsOrderedAndNotDuplicated(t *testing.T) {
	events := make(chan NodeEvent, 16)
	m := GetMemberlist(t, func(c *Config) {
		c.Events = &ChannelEventDelegate{Ch: events}
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	m.aliveNode(uid555Alive("node", 1, 1), nil, false)
	m.aliveNode(uid555Alive("node", 1, 1), nil, false) // idempotent
	m.suspectNode(&suspect{Node: "node", Incarnation: 1, Generation: 1, From: "p1"})
	m.deadNode(&dead{Node: "node", From: "observer", Incarnation: 1, Generation: 1})
	m.deadNode(&dead{Node: "node", From: "observer", Incarnation: 1, Generation: 1}) // duplicate

	require.Len(t, events, 2)
	first := <-events
	second := <-events
	require.Equal(t, NodeJoin, first.Event)
	require.Equal(t, NodeLeave, second.Event)

	// Recovery emits one join and no update.
	m.aliveNode(uid555Alive("node", 2, 2), nil, false)
	require.Len(t, events, 1)
	require.Equal(t, NodeJoin, (<-events).Event)
}

func TestUID555_SuspicionTimeoutFiresOnce(t *testing.T) {
	var calls atomic.Int32
	s := newSuspicion("from", 1, time.Hour, 2*time.Hour, func(int) {
		calls.Add(1)
	})
	defer s.Stop()

	s.timeoutFn()
	s.timeoutFn()
	require.Equal(t, int32(1), calls.Load())
}

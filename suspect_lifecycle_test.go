// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"sync/atomic"
	"testing"
	"time"
)

// testSuspicionConfig returns a memberlist whose suspicion window is short
// and deterministic enough for lifecycle tests.
func testSuspicionMemberlist(t *testing.T) *Memberlist {
	t.Helper()
	return GetMemberlist(t, func(c *Config) {
		c.ProbeInterval = time.Millisecond
		c.SuspicionMult = 1
	})
}

// TestMemberList_SuspectNode_TimerStoppedOnAlive verifies that an alive
// declaration (a refutation at a newer incarnation) stops the in-flight
// suspicion timer, so an older-generation timer can never mark the node
// dead after it has recovered.
func TestMemberList_SuspectNode_TimerStoppedOnAlive(t *testing.T) {
	m := testSuspicionMemberlist(t)
	defer func() {
		if err := m.Shutdown(); err != nil {
			t.Fatal(err)
		}
	}()

	a := alive{Node: "test", Addr: []byte{127, 0, 0, 1}, Incarnation: 1, Vsn: m.config.BuildVsnArray()}
	m.aliveNode(&a, nil, false)

	s := suspect{Node: "test", Incarnation: 1, From: "peer"}
	m.suspectNode(&s)
	if got := m.getNodeState("test"); got != StateSuspect {
		t.Fatalf("expected suspect, got %v", got)
	}

	m.nodeLock.RLock()
	timer := m.nodeTimers["test"]
	m.nodeLock.RUnlock()
	if timer == nil {
		t.Fatalf("expected a suspicion timer to be registered")
	}

	// The node refutes with a newer incarnation.
	refute := alive{Node: "test", Addr: []byte{127, 0, 0, 1}, Incarnation: 2, Vsn: m.config.BuildVsnArray()}
	m.aliveNode(&refute, nil, false)

	if got := m.getNodeState("test"); got != StateAlive {
		t.Fatalf("expected alive after refutation, got %v", got)
	}
	m.nodeLock.RLock()
	_, present := m.nodeTimers["test"]
	m.nodeLock.RUnlock()
	if present {
		t.Fatalf("suspicion timer should have been removed")
	}

	// Wait well beyond the original suspicion timeout. The stale timer must
	// not have advanced the current generation.
	time.Sleep(50 * time.Millisecond)
	if got := m.getNodeState("test"); got != StateAlive {
		t.Fatalf("stale timer overrode the alive claim: got %v", got)
	}
}

// TestMemberList_SuspectNode_OldTimerDoesNotAdvanceGeneration verifies the
// requirement for network reorder / node re-join: even if an old suspicion
// timer fires while a newer generation is active, it is ignored.
func TestMemberList_SuspectNode_OldTimerDoesNotAdvanceGeneration(t *testing.T) {
	m := testSuspicionMemberlist(t)
	defer func() {
		if err := m.Shutdown(); err != nil {
			t.Fatal(err)
		}
	}()

	a := alive{Node: "test", Addr: []byte{127, 0, 0, 1}, Incarnation: 1, Vsn: m.config.BuildVsnArray()}
	m.aliveNode(&a, nil, false)

	// First suspicion lifecycle (incarnation 1).
	s1 := suspect{Node: "test", Incarnation: 1, From: "peer"}
	m.suspectNode(&s1)
	m.nodeLock.RLock()
	oldTimer := m.nodeTimers["test"]
	m.nodeLock.RUnlock()

	// Refutation restores the node at incarnation 2, retiring the old timer.
	refute := alive{Node: "test", Addr: []byte{127, 0, 0, 1}, Incarnation: 2, Vsn: m.config.BuildVsnArray()}
	m.aliveNode(&refute, nil, false)

	// A second, independent suspicion lifecycle for the new generation.
	s2 := suspect{Node: "test", Incarnation: 2, From: "peer"}
	m.suspectNode(&s2)
	m.nodeLock.RLock()
	newTimer := m.nodeTimers["test"]
	m.nodeLock.RUnlock()
	if oldTimer == newTimer {
		t.Fatalf("expected a fresh timer for the new member generation")
	}

	// Drive the retired timer's callback directly, as an in-flight stale
	// timer from a reordered network might. It must not touch the node.
	oldTimer.timeoutFn()
	if got := m.getNodeState("test"); got != StateSuspect {
		t.Fatalf("stale timer advanced the current generation: got %v", got)
	}
	m.nodeLock.RLock()
	stillCurrent := m.nodeTimers["test"] == newTimer
	m.nodeLock.RUnlock()
	if !stillCurrent {
		t.Fatalf("the current generation's timer was displaced by a stale one")
	}
}

// TestMemberList_SuspectNode_SingleTerminalEvent verifies the timeout path
// goes through the same state machine as an explicit dead message and only
// one terminal leave event is ever emitted, even with a duplicated dead
// message afterwards.
func TestMemberList_SuspectNode_SingleTerminalEvent(t *testing.T) {
	events := make(chan NodeEvent, 8)
	m := GetMemberlist(t, func(c *Config) {
		c.Events = &ChannelEventDelegate{events}
		c.ProbeInterval = time.Millisecond
		c.SuspicionMult = 1
	})
	defer func() {
		if err := m.Shutdown(); err != nil {
			t.Fatal(err)
		}
	}()

	a := alive{Node: "test", Addr: []byte{127, 0, 0, 1}, Incarnation: 1, Vsn: m.config.BuildVsnArray()}
	m.aliveNode(&a, nil, false)
	<-events // drain the join event

	s := suspect{Node: "test", Incarnation: 1, From: "peer"}
	m.suspectNode(&s)

	// Wait for the suspicion timeout to declare the node dead.
	deadline := time.After(2 * time.Second)
	var leaves int
	for leaves == 0 {
		select {
		case ev := <-events:
			if ev.Event == NodeLeave {
				leaves++
			}
		case <-deadline:
			t.Fatalf("timed out waiting for the terminal leave event")
		}
	}

	m.nodeLock.RLock()
	timer := m.nodeTimers["test"]
	m.nodeLock.RUnlock()
	if timer != nil {
		t.Fatalf("timer should have been cleared on death")
	}

	// An explicit dead at the same incarnation must be idempotent and not
	// produce a second terminal event.
	d := dead{Node: "test", Incarnation: 1, From: "peer"}
	m.deadNode(&d)

	select {
	case ev := <-events:
		t.Fatalf("unexpected extra event after terminal state: %v", ev.Event)
	case <-time.After(25 * time.Millisecond):
	}
}

// TestSuspicion_TimeoutFiresOnce verifies the sync.Once guard around the
// suspicion timeout when Confirm underflows the remaining time while the
// underlying timer is also racing to fire.
func TestSuspicion_TimeoutFiresOnce(t *testing.T) {
	const attempts = 16
	var n atomic.Int32
	done := make(chan struct{}, attempts)

	s := newSuspicion("me", 1, time.Hour, 2*time.Hour, func(int) {
		n.Add(1)
		done <- struct{}{}
	})
	defer s.Stop()

	// Expire the underlying timer, then hammer Confirm which takes the
	// direct-fire path once the remaining time underflows.
	s.timer.Stop()
	s.timer.Reset(10 * time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	for range attempts {
		s.Confirm("peer")
	}
	s.timeoutFn()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("timeout function never fired")
	}
	time.Sleep(25 * time.Millisecond)
	if got := n.Load(); got != 1 {
		t.Fatalf("expected exactly one timeout invocation, got %d", got)
	}
}

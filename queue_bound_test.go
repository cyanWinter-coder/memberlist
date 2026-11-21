// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"testing"
)

// TestTransmitLimited_MaxBroadcasts_EvictsOldest verifies that, once the
// configured capacity is reached, the oldest queued broadcast is evicted
// (with its Finished callback honored) while newer messages are retained.
func TestTransmitLimited_MaxBroadcasts_EvictsOldest(t *testing.T) {
	alphaFinished := make(chan struct{}, 1)

	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		MaxBroadcasts:  3,
		NumNodes:       func() int { return 10 },
	}

	// Equal-length names and payloads keep ordering within a transmit tier
	// on the insertion id (rather than message length), so the oldest entry
	// is unambiguous.
	queue := func(name string, notify chan struct{}) {
		q.QueueBroadcast(&memberlistBroadcast{
			node:   name,
			msg:    []byte(name + "-payload"),
			notify: notify,
		})
	}

	queue("node0", alphaFinished)
	queue("node1", nil)
	queue("node2", nil)
	if got := q.NumQueued(); got != 3 {
		t.Fatalf("expected 3 queued messages, got %d", got)
	}

	// The fourth message (a distinct node) must evict the oldest one
	// ("node0"), which is the only entry carrying a Finished callback.
	queue("node3", nil)
	if got := q.NumQueued(); got != 3 {
		t.Fatalf("expected the queue to stay bounded at 3, got %d", got)
	}
	select {
	case <-alphaFinished:
	default:
		t.Fatalf("evicted message did not receive its Finished callback")
	}

	dump := q.orderedView()
	got := make(map[string]bool)
	for _, item := range dump {
		got[item.b.(*memberlistBroadcast).node] = true
	}
	for _, want := range []string{"node1", "node2", "node3"} {
		if !got[want] {
			t.Fatalf("expected %q to be retained, queue contents: %v", want, got)
		}
	}
	if got["node0"] {
		t.Fatalf("oldest message node0 should have been evicted")
	}
}

// TestTransmitLimited_MaxBroadcasts_KeepsTerminalState verifies that under
// capacity pressure the latest state for each node is what survives: newer
// broadcasts about a node invalidate the older ones first, so the terminal
// state is retained rather than intermediate oscillations.
func TestTransmitLimited_MaxBroadcasts_KeepsTerminalState(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		MaxBroadcasts:  2,
		NumNodes:       func() int { return 10 },
	}

	put := func(node string, body string) {
		q.QueueBroadcast(&memberlistBroadcast{
			node: node,
			msg:  []byte(body),
		})
	}

	// Oscillate node "flap": suspect, then alive, then dead. Each new
	// broadcast invalidates the previous one for the same node.
	put("flap", "suspect inc 1")
	put("other", "alive inc 1")
	put("flap", "alive inc 2")
	put("flap", "dead inc 3")

	if got := q.NumQueued(); got > q.MaxBroadcasts {
		t.Fatalf("queue exceeded MaxBroadcasts: %d > %d", got, q.MaxBroadcasts)
	}

	// The only message that can remain for "flap" is its final dead state.
	out := q.GetBroadcasts(0, 1024)
	var sawFlapTerminal bool
	for _, msg := range out {
		if string(msg) == "dead inc 3" {
			sawFlapTerminal = true
		}
		if string(msg) == "suspect inc 1" || string(msg) == "alive inc 2" {
			t.Fatalf("intermediate oscillation state was retained: %q", msg)
		}
	}
	if !sawFlapTerminal {
		t.Fatalf("terminal state for the flapping node was not retained: %v", out)
	}
}

// TestTransmitLimited_ZeroMaxBroadcasts_Unbounded verifies backward
// compatibility: a zero limit preserves the historical unbounded behavior.
func TestTransmitLimited_ZeroMaxBroadcasts_Unbounded(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		MaxBroadcasts:  0,
		NumNodes:       func() int { return 10 },
	}
	for i := range 10 {
		q.queueBroadcast(&memberlistBroadcast{
			node: "node" + string(rune('a'+i)),
			msg:  []byte{byte(i)},
		}, 0)
	}
	if got := q.NumQueued(); got != 10 {
		t.Fatalf("expected unbounded queue to hold all 10 messages, got %d", got)
	}
}

// TestMemberlist_MaxBroadcastsConfigWired verifies the Config field is
// propagated to the memberlist's broadcast queue.
func TestMemberlist_MaxBroadcastsConfigWired(t *testing.T) {
	m := GetMemberlist(t, func(c *Config) {
		c.MaxBroadcasts = 7
	})
	defer func() {
		if err := m.Shutdown(); err != nil {
			t.Fatal(err)
		}
	}()
	if m.broadcasts.MaxBroadcasts != 7 {
		t.Fatalf("expected MaxBroadcasts 7, got %d", m.broadcasts.MaxBroadcasts)
	}
}

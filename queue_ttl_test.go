// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// testBroadcast is a Broadcast that also implements BroadcastTTL and
// BroadcastTarget so the new queue behavior can be exercised directly.
type testBroadcast struct {
	name    string
	msg     []byte
	ttl     time.Duration
	targets []string
	finish  chan struct{}
}

func (b *testBroadcast) Invalidates(other Broadcast) bool {
	ob, ok := other.(*testBroadcast)
	return ok && ob.name == b.name
}

func (b *testBroadcast) Message() []byte { return b.msg }

func (b *testBroadcast) Name() string { return b.name }

func (b *testBroadcast) BroadcastTTL() time.Duration { return b.ttl }

func (b *testBroadcast) BroadcastTargets() []string { return b.targets }

func (b *testBroadcast) Finished() {
	if b.finish != nil {
		select {
		case b.finish <- struct{}{}:
		default:
		}
	}
}

// newTestClock returns a controllable now() and an advance function.
func newTestClock() (func() time.Time, func(time.Duration)) {
	now := time.Unix(1_700_000_000, 0)
	nowFn := func() time.Time { return now }
	advance := func(d time.Duration) { now = now.Add(d) }
	return nowFn, advance
}

func TestTransmitLimited_TTL_ExpiredOnGet(t *testing.T) {
	now, advance := newTestClock()
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		Now:            now,
	}

	q.QueueBroadcast(&testBroadcast{
		name: "a",
		msg:  []byte("1. this is a test."),
		ttl:  100 * time.Millisecond,
	})
	q.QueueBroadcast(&testBroadcast{
		name: "b",
		msg:  []byte("2. this is a test."),
		ttl:  5 * time.Second,
	})
	require.Equal(t, 2, q.NumQueued())

	// Expire the first one. The sweep at the start of GetBroadcasts must
	// remove and count it without ever returning it.
	advance(200 * time.Millisecond)
	all := q.GetBroadcasts(2, 80)
	require.Equal(t, 1, len(all), "expired entry must not be returned")
	require.Equal(t, []byte("2. this is a test."), all[0])
	require.Equal(t, int64(1), q.NumExpired())
	require.Equal(t, 1, q.NumQueued())
}

func TestTransmitLimited_TTL_ExpiredOnEnqueue(t *testing.T) {
	now, advance := newTestClock()
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		Now:            now,
	}

	finished := make(chan struct{}, 1)
	q.QueueBroadcast(&testBroadcast{
		name:   "a",
		msg:    []byte("1. this is a test."),
		ttl:    time.Second,
		finish: finished,
	})

	advance(2 * time.Second)
	q.QueueBroadcast(&testBroadcast{
		name: "b",
		msg:  []byte("2. this is a test."),
		ttl:  time.Minute,
	})

	require.Equal(t, 1, q.NumQueued(), "expired entry must be removed on enqueue")
	require.Equal(t, int64(1), q.NumExpired())
	select {
	case <-finished:
	default:
		t.Fatalf("expired broadcast must have Finished invoked")
	}
}

func TestTransmitLimited_TTL_ZeroMeansNoExpiry(t *testing.T) {
	now, advance := newTestClock()
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		Now:            now,
	}

	// memberlistBroadcast with a zero ttl must never expire.
	q.QueueBroadcast(&memberlistBroadcast{node: "x", msg: []byte("1. this is a test.")})
	advance(time.Hour)
	require.Equal(t, 1, q.NumQueued())
	require.Equal(t, int64(0), q.NumExpired())
}

func TestTransmitLimited_MaxLen_OverflowsOldest(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		MaxLen:         3,
	}

	finished := make(chan struct{}, 4)
	mk := func(name string) *testBroadcast {
		return &testBroadcast{
			name:   name,
			msg:    []byte(name + " this is a test message"),
			finish: finished,
		}
	}

	q.QueueBroadcast(mk("a"))
	q.QueueBroadcast(mk("b"))
	q.QueueBroadcast(mk("c"))

	// The fourth insertion must evict the stalest entry instead of growing.
	q.QueueBroadcast(mk("d"))
	require.Equal(t, 3, q.NumQueued())
	require.Equal(t, int64(1), q.NumOverflow())
	require.Equal(t, 1, len(finished), "evicted entry must have Finished invoked")

	names := map[string]bool{}
	for _, item := range q.orderedView() {
		names[item.b.(*testBroadcast).name] = true
	}
	require.True(t, names["b"] && names["c"] && names["d"], "oldest entry should have been dropped")
	require.False(t, names["a"])
}

func TestTransmitLimited_MaxLen_ZeroMeansUnbounded(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
	}
	for i := 0; i < 100; i++ {
		q.QueueBroadcast(&memberlistBroadcast{
			node: "n" + string(rune('a'+i%26)) + string(rune('a'+i/26)),
			msg:  []byte("1. this is a test."),
		})
	}
	require.Equal(t, 100, q.NumQueued())
	require.Equal(t, int64(0), q.NumOverflow())
}

func TestTransmitLimited_AckBroadcast_ReleasesWhenAllConfirm(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 4,
		NumNodes:       func() int { return 10 },
	}

	finished := make(chan struct{}, 1)
	q.QueueBroadcast(&testBroadcast{
		name:    "node-x",
		msg:     []byte("1. this is a test."),
		targets: []string{"n1", "n2", "n3"},
		finish:  finished,
	})
	require.Equal(t, 1, q.NumQueued())

	// Partial acknowledgements keep the entry queued.
	require.False(t, q.AckBroadcast("node-x", "n1"))
	require.False(t, q.AckBroadcast("node-x", "n2"))
	require.Equal(t, 1, q.NumQueued())
	require.Equal(t, int64(0), q.NumAckReleased())

	// The final acknowledgement frees the slot immediately, well below the
	// retransmit limit.
	require.True(t, q.AckBroadcast("node-x", "n3"))
	require.Equal(t, 0, q.NumQueued())
	require.Equal(t, int64(1), q.NumAckReleased())
	select {
	case <-finished:
	default:
		t.Fatalf("ack-released broadcast must have Finished invoked")
	}

	// Duplicate or unknown acks are no-ops.
	require.False(t, q.AckBroadcast("node-x", "n1"))
	require.False(t, q.AckBroadcast("missing", "n1"))
}

func TestTransmitLimited_AckBroadcast_NoTargetsFallsBackToRetransmit(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
	}
	q.QueueBroadcast(&memberlistBroadcast{node: "node-y", msg: []byte("1. this is a test.")})

	// Entries without an explicit target set ignore acks and rely on the
	// retransmit limit, preserving the historical behavior.
	require.False(t, q.AckBroadcast("node-y", "n1"))
	require.Equal(t, 1, q.NumQueued())
}

func TestTransmitLimited_CoalescesSameNode(t *testing.T) {
	// Requirement: multiple pending messages for the same node are merged so
	// only the newest is ever on the wire. Named broadcasts invalidate the
	// previous entry at enqueue time.
	now, advance := newTestClock()
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		Now:            now,
	}

	first := make(chan struct{}, 1)
	q.QueueBroadcast(&testBroadcast{
		name:   "node-z",
		msg:    []byte("old state"),
		ttl:    time.Minute,
		finish: first,
	})
	q.QueueBroadcast(&testBroadcast{
		name: "node-z",
		msg:  []byte("new state"),
		ttl:  time.Minute,
	})

	require.Equal(t, 1, q.NumQueued(), "same-node messages must coalesce to a single entry")
	select {
	case <-first:
	default:
		t.Fatalf("superseded broadcast must have Finished invoked")
	}

	got := q.GetBroadcasts(2, 80)
	require.Equal(t, 1, len(got))
	require.Equal(t, []byte("new state"), got[0])

	// Advancing the clock past the TTL of the surviving entry expires it.
	advance(2 * time.Minute)
	require.Equal(t, 0, len(q.GetBroadcasts(2, 80)))
	require.Equal(t, int64(1), q.NumExpired())
}

func TestTransmitLimited_ResetClearsCounters(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		MaxLen:         1,
	}
	q.QueueBroadcast(&testBroadcast{name: "a", msg: []byte("x")})
	q.QueueBroadcast(&testBroadcast{name: "b", msg: []byte("y")})
	require.Equal(t, int64(1), q.NumOverflow())

	q.Reset()
	require.Equal(t, 0, q.NumQueued())
	require.Equal(t, int64(0), q.NumOverflow())
	require.Equal(t, int64(0), q.NumExpired())
	require.Equal(t, int64(0), q.NumAckReleased())
}

// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/btree"
	"github.com/stretchr/testify/require"
)

// for testing only
func (q *TransmitLimitedQueue) orderedView() []*limitedBroadcast {
	q.mu.Lock()
	defer q.mu.Unlock()

	out := make([]*limitedBroadcast, 0, q.lenLocked())
	q.walkReadOnlyLocked(true, func(cur *limitedBroadcast) bool {
		out = append(out, cur)
		return true
	})

	return out
}

func TestLimitedBroadcastLess(t *testing.T) {
	cases := []struct {
		Name string
		A    *limitedBroadcast // lesser
		B    *limitedBroadcast
	}{
		{
			"diff-transmits",
			&limitedBroadcast{transmits: 0, msgLen: 10, id: 100},
			&limitedBroadcast{transmits: 1, msgLen: 10, id: 100},
		},
		{
			"same-transmits--diff-len",
			&limitedBroadcast{transmits: 0, msgLen: 12, id: 100},
			&limitedBroadcast{transmits: 0, msgLen: 10, id: 100},
		},
		{
			"same-transmits--same-len--diff-id",
			&limitedBroadcast{transmits: 0, msgLen: 12, id: 100},
			&limitedBroadcast{transmits: 0, msgLen: 12, id: 90},
		},
	}

	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			a, b := c.A, c.B

			require.True(t, a.Less(b))

			tree := btree.New(32)

			tree.ReplaceOrInsert(b)
			tree.ReplaceOrInsert(a)

			min := tree.Min().(*limitedBroadcast)
			require.Equal(t, a.transmits, min.transmits)
			require.Equal(t, a.msgLen, min.msgLen)
			require.Equal(t, a.id, min.id)

			max := tree.Max().(*limitedBroadcast)
			require.Equal(t, b.transmits, max.transmits)
			require.Equal(t, b.msgLen, max.msgLen)
			require.Equal(t, b.id, max.id)
		})
	}
}

func TestTransmitLimited_Queue(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 1 }}
	q.QueueBroadcast(&memberlistBroadcast{node: "test", msg: nil, notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "foo", msg: nil, notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "bar", msg: nil, notify: nil})

	if q.NumQueued() != 3 {
		t.Fatalf("bad len")
	}
	dump := q.orderedView()
	if dump[0].b.(*memberlistBroadcast).node != "test" {
		t.Fatalf("missing test")
	}
	if dump[1].b.(*memberlistBroadcast).node != "foo" {
		t.Fatalf("missing foo")
	}
	if dump[2].b.(*memberlistBroadcast).node != "bar" {
		t.Fatalf("missing bar")
	}

	// Should invalidate previous message
	q.QueueBroadcast(&memberlistBroadcast{node: "test", msg: nil, notify: nil})

	if q.NumQueued() != 3 {
		t.Fatalf("bad len")
	}
	dump = q.orderedView()
	if dump[0].b.(*memberlistBroadcast).node != "foo" {
		t.Fatalf("missing foo")
	}
	if dump[1].b.(*memberlistBroadcast).node != "bar" {
		t.Fatalf("missing bar")
	}
	if dump[2].b.(*memberlistBroadcast).node != "test" {
		t.Fatalf("missing test")
	}
}

func TestTransmitLimited_GetBroadcasts(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 3, NumNodes: func() int { return 10 }}

	// 18 bytes per message
	q.QueueBroadcast(&memberlistBroadcast{node: "test", msg: []byte("1. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "foo", msg: []byte("2. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "bar", msg: []byte("3. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "baz", msg: []byte("4. this is a test."), notify: nil})

	// 2 byte overhead per message, should get all 4 messages
	all := q.GetBroadcasts(2, 80)
	require.Equal(t, 4, len(all), "missing messages: %v", prettyPrintMessages(all))

	// 3 byte overhead, should only get 3 messages back
	partial := q.GetBroadcasts(3, 80)
	require.Equal(t, 3, len(partial), "missing messages: %v", prettyPrintMessages(partial))
}

func TestTransmitLimited_GetBroadcasts_Limit(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	require.Equal(t, int64(0), q.idGen, "the id generator seed starts at zero")
	require.Equal(t, 2, retransmitLimit(q.RetransmitMult, q.NumNodes()), "sanity check transmit limits")

	// 18 bytes per message
	q.QueueBroadcast(&memberlistBroadcast{node: "test", msg: []byte("1. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "foo", msg: []byte("2. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "bar", msg: []byte("3. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "baz", msg: []byte("4. this is a test."), notify: nil})

	require.Equal(t, int64(4), q.idGen, "we handed out 4 IDs")

	// 3 byte overhead, should only get 3 messages back
	partial1 := q.GetBroadcasts(3, 80)
	require.Equal(t, 3, len(partial1), "missing messages: %v", prettyPrintMessages(partial1))

	require.Equal(t, int64(4), q.idGen, "id generator doesn't reset until empty")

	partial2 := q.GetBroadcasts(3, 80)
	require.Equal(t, 3, len(partial2), "missing messages: %v", prettyPrintMessages(partial2))

	require.Equal(t, int64(4), q.idGen, "id generator doesn't reset until empty")

	// Only two not expired
	partial3 := q.GetBroadcasts(3, 80)
	require.Equal(t, 2, len(partial3), "missing messages: %v", prettyPrintMessages(partial3))

	require.Equal(t, int64(0), q.idGen, "id generator resets on empty")

	// Should get nothing
	partial5 := q.GetBroadcasts(3, 80)
	require.Equal(t, 0, len(partial5), "missing messages: %v", prettyPrintMessages(partial5))

	require.Equal(t, int64(0), q.idGen, "id generator resets on empty")
}

func prettyPrintMessages(msgs [][]byte) []string {
	var out []string
	for _, msg := range msgs {
		out = append(out, "'"+string(msg)+"'")
	}
	return out
}

func TestTransmitLimited_Prune(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	ch1 := make(chan struct{}, 1)
	ch2 := make(chan struct{}, 1)

	// 18 bytes per message
	q.QueueBroadcast(&memberlistBroadcast{node: "test", msg: []byte("1. this is a test."), notify: ch1})
	q.QueueBroadcast(&memberlistBroadcast{node: "foo", msg: []byte("2. this is a test."), notify: ch2})
	q.QueueBroadcast(&memberlistBroadcast{node: "bar", msg: []byte("3. this is a test."), notify: nil})
	q.QueueBroadcast(&memberlistBroadcast{node: "baz", msg: []byte("4. this is a test."), notify: nil})

	// Keep only 2
	q.Prune(2)

	require.Equal(t, 2, q.NumQueued())

	// Should notify the first two
	select {
	case <-ch1:
	default:
		t.Fatalf("expected invalidation")
	}
	select {
	case <-ch2:
	default:
		t.Fatalf("expected invalidation")
	}

	dump := q.orderedView()

	if dump[0].b.(*memberlistBroadcast).node != "bar" {
		t.Fatalf("missing bar")
	}
	if dump[1].b.(*memberlistBroadcast).node != "baz" {
		t.Fatalf("missing baz")
	}
}

func TestTransmitLimited_ordering(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	insert := func(name string, transmits int) {
		q.queueBroadcast(&memberlistBroadcast{node: name, msg: []byte(name), notify: make(chan struct{})}, transmits)
	}

	insert("node0", 0)
	insert("node1", 10)
	insert("node2", 3)
	insert("node3", 4)
	insert("node4", 7)

	dump := q.orderedView()

	if dump[0].transmits != 10 {
		t.Fatalf("bad val %v, %d", dump[0].b.(*memberlistBroadcast).node, dump[0].transmits)
	}
	if dump[1].transmits != 7 {
		t.Fatalf("bad val %v, %d", dump[7].b.(*memberlistBroadcast).node, dump[7].transmits)
	}
	if dump[2].transmits != 4 {
		t.Fatalf("bad val %v, %d", dump[2].b.(*memberlistBroadcast).node, dump[2].transmits)
	}
	if dump[3].transmits != 3 {
		t.Fatalf("bad val %v, %d", dump[3].b.(*memberlistBroadcast).node, dump[3].transmits)
	}
	if dump[4].transmits != 0 {
		t.Fatalf("bad val %v, %d", dump[4].b.(*memberlistBroadcast).node, dump[4].transmits)
	}
}

// countingBroadcast records how many times Finished runs so tests can assert
// the callback fires exactly once per terminal transition.
type countingBroadcast struct {
	name     string
	msg      []byte
	terminal bool
	finished atomic.Int64
}

func (c *countingBroadcast) Invalidates(other Broadcast) bool {
	nb, ok := other.(NamedBroadcast)
	if !ok {
		return false
	}
	return c.name == nb.Name()
}

func (c *countingBroadcast) Message() []byte { return c.msg }
func (c *countingBroadcast) Finished()       { c.finished.Add(1) }
func (c *countingBroadcast) Name() string    { return c.name }
func (c *countingBroadcast) Terminal() bool  { return c.terminal }

func finishedCount(c *countingBroadcast) int64 { return c.finished.Load() }

// TestTransmitLimited_TerminalNotEvicted covers requirements 1 and 2: when
// the queue is full, intermediate states are evicted first and a terminal
// (dead) state is never dropped while an intermediate state remains.
func TestTransmitLimited_TerminalNotEvicted(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
		MaxQueueSize:   3,
	}

	s1 := &countingBroadcast{name: "suspect1", msg: []byte("s1")}
	s2 := &countingBroadcast{name: "suspect2", msg: []byte("s2")}
	s3 := &countingBroadcast{name: "suspect3", msg: []byte("s3")}
	dead := &countingBroadcast{name: "dead", msg: []byte("d"), terminal: true}

	q.QueueBroadcast(s1)
	q.QueueBroadcast(s2)
	q.QueueBroadcast(s3)
	q.QueueBroadcast(dead) // exceeds cap by one

	require.Equal(t, 3, q.NumQueued())
	stats := q.Stats()
	require.Equal(t, int64(4), stats.Enqueued)
	require.Equal(t, int64(0), stats.Merged)
	require.Equal(t, int64(1), stats.Evicted)

	// The oldest intermediate state was evicted, the terminal survives.
	require.Equal(t, int64(1), finishedCount(s1), "oldest intermediate must be evicted")
	require.Equal(t, int64(0), finishedCount(dead), "terminal state must not be evicted")

	names := queuedNames(q)
	require.ElementsMatch(t, []string{"suspect2", "suspect3", "dead"}, names)

	// Keep filling: every remaining eviction takes an intermediate, never
	// the terminal, until only terminal states are left.
	s4 := &countingBroadcast{name: "suspect4", msg: []byte("s4")}
	s5 := &countingBroadcast{name: "suspect5", msg: []byte("s5")}
	q.QueueBroadcast(s4)
	q.QueueBroadcast(s5)

	names = queuedNames(q)
	require.Contains(t, names, "dead")
	require.Len(t, names, 3)
	require.Equal(t, int64(0), finishedCount(dead))

	// Once only terminal states exist, the queue is allowed to exceed the
	// cap rather than drop a final state.
	otherDead := &countingBroadcast{name: "otherDead", msg: []byte("od"), terminal: true}
	thirdDead := &countingBroadcast{name: "thirdDead", msg: []byte("td"), terminal: true}
	q.QueueBroadcast(otherDead)
	q.QueueBroadcast(thirdDead)
	require.GreaterOrEqual(t, q.NumQueued(), q.MaxQueueSize)
	require.Equal(t, int64(0), finishedCount(dead))
	require.Equal(t, int64(0), finishedCount(otherDead))
	require.Equal(t, int64(0), finishedCount(thirdDead))
}

// TestTransmitLimited_TerminalReplacesIntermediate covers requirement 1:
// the queue keeps the final state per node and generation, and a new
// terminal state replaces that node's earlier intermediate message.
func TestTransmitLimited_TerminalReplacesIntermediate(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 10 },
	}

	suspect := &countingBroadcast{name: "nodeA", msg: []byte("suspect")}
	dead := &countingBroadcast{name: "nodeA", msg: []byte("dead"), terminal: true}

	q.QueueBroadcast(suspect)
	require.Equal(t, 1, q.NumQueued())
	require.Equal(t, int64(0), finishedCount(suspect))

	q.QueueBroadcast(dead)
	require.Equal(t, 1, q.NumQueued(), "one entry per node, terminal replaces intermediate")

	// The replaced intermediate gets its single Finished callback and is
	// accounted as a merge, not an eviction.
	require.Equal(t, int64(1), finishedCount(suspect))
	require.Equal(t, int64(0), finishedCount(dead))

	stats := q.Stats()
	require.Equal(t, int64(2), stats.Enqueued)
	require.Equal(t, int64(1), stats.Merged)
	require.Equal(t, int64(0), stats.Evicted)

	only := q.orderedView()[0]
	require.True(t, only.terminal)
	require.Equal(t, "nodeA", only.b.(*countingBroadcast).name)

	// A newer generation (alive refutation) can still supersede a terminal
	// state; Terminal only governs capacity eviction, not invalidation.
	alive := &countingBroadcast{name: "nodeA", msg: []byte("alive")}
	q.QueueBroadcast(alive)
	require.Equal(t, 1, q.NumQueued())
	require.Equal(t, int64(1), finishedCount(dead))
	require.False(t, q.orderedView()[0].terminal)
}

// TestTransmitLimited_PruneProtectsTerminal covers requirement 2 through the
// public Prune path: terminal states survive pruning while intermediate
// states are dropped.
func TestTransmitLimited_PruneProtectsTerminal(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	i1 := &countingBroadcast{name: "i1", msg: []byte("i1")}
	i2 := &countingBroadcast{name: "i2", msg: []byte("i2")}
	d1 := &countingBroadcast{name: "d1", msg: []byte("d1"), terminal: true}
	d2 := &countingBroadcast{name: "d2", msg: []byte("d2"), terminal: true}

	q.QueueBroadcast(i1)
	q.QueueBroadcast(i2)
	q.QueueBroadcast(d1)
	q.QueueBroadcast(d2)

	// Ask to retain only one message; both terminals must remain.
	q.Prune(1)
	names := queuedNames(q)
	require.ElementsMatch(t, []string{"d1", "d2"}, names)
	require.Equal(t, int64(1), finishedCount(i1))
	require.Equal(t, int64(1), finishedCount(i2))
	require.Equal(t, int64(0), finishedCount(d1))
	require.Equal(t, int64(0), finishedCount(d2))
	require.Equal(t, int64(2), q.Stats().Evicted)

	// Pruning again changes nothing and never double-invokes Finished.
	q.Prune(0)
	require.ElementsMatch(t, []string{"d1", "d2"}, queuedNames(q))
	require.Equal(t, int64(1), finishedCount(i1))
}

// TestTransmitLimited_StatsCounters covers requirement 3: received, merged
// and evicted messages are counted separately, and normal retransmit
// retirement is attributed to none of them.
func TestTransmitLimited_StatsCounters(t *testing.T) {
	q := &TransmitLimitedQueue{
		RetransmitMult: 1,
		NumNodes:       func() int { return 1 },
		MaxQueueSize:   2,
	}

	a := &countingBroadcast{name: "a", msg: []byte("a")}
	b := &countingBroadcast{name: "b", msg: []byte("b")}
	c := &countingBroadcast{name: "c", msg: []byte("c")}
	q.QueueBroadcast(a)
	q.QueueBroadcast(b)
	q.QueueBroadcast(c) // evicts the oldest intermediate (a)

	// Same-node replacement counts as a merge.
	b2 := &countingBroadcast{name: "b", msg: []byte("b2")}
	q.QueueBroadcast(b2)

	stats := q.Stats()
	require.Equal(t, int64(4), stats.Enqueued)
	require.Equal(t, int64(1), stats.Merged)
	require.Equal(t, int64(1), stats.Evicted)
	require.Equal(t, 2, stats.NumQueued)
	require.False(t, stats.Closed)

	// Transmitting until the retransmit limit retires a message but does
	// not touch the counters.
	before := q.Stats()
	for range 10 {
		if q.NumQueued() == 0 {
			break
		}
		q.GetBroadcasts(0, 1024)
	}
	after := q.Stats()
	require.Equal(t, before.Enqueued, after.Enqueued)
	require.Equal(t, before.Merged, after.Merged)
	require.Equal(t, before.Evicted, after.Evicted)
}

// TestTransmitLimited_Close covers requirement 4: Close drains each queued
// message's Finished callback exactly once, converges on a single terminal
// state under concurrent calls, and rejects later enqueues.
func TestTransmitLimited_Close(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	items := []*countingBroadcast{
		{name: "a", msg: []byte("a")},
		{name: "b", msg: []byte("b")},
		{name: "c", msg: []byte("c"), terminal: true},
	}
	for _, it := range items {
		q.QueueBroadcast(it)
	}
	require.Equal(t, 3, q.NumQueued())

	// Concurrent and repeated Close calls must converge on one state.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			q.Close()
		}()
	}
	wg.Wait()
	q.Close()

	require.True(t, q.Stats().Closed)
	require.Equal(t, 0, q.NumQueued())
	for _, it := range items {
		require.Equal(t, int64(1), finishedCount(it),
			"%s Finished must run exactly once", it.name)
	}

	// New broadcasts are rejected and never queued or finished.
	rejected := &countingBroadcast{name: "late", msg: []byte("late")}
	q.QueueBroadcast(rejected)
	require.Equal(t, 0, q.NumQueued())
	require.Equal(t, int64(0), finishedCount(rejected))
	require.Equal(t, int64(3), q.Stats().Enqueued, "rejected enqueue is not counted")

	// Reads on a closed queue remain safe and return empty.
	require.Nil(t, q.GetBroadcasts(0, 1024))
	q.Prune(0)
}

// TestTransmitLimited_ConcurrentLifecycle exercises requirement 4 with
// concurrent enqueue, batch and close operations, run under -race.
func TestTransmitLimited_ConcurrentLifecycle(t *testing.T) {
	for trial := 0; trial < 20; trial++ {
		q := &TransmitLimitedQueue{
			RetransmitMult: 3,
			NumNodes:       func() int { return 10 },
			MaxQueueSize:   16,
		}

		var wg sync.WaitGroup
		stop := make(chan struct{})

		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for i := 0; ; i++ {
					select {
					case <-stop:
						return
					default:
					}
					terminal := i%7 == 0
					q.QueueBroadcast(&countingBroadcast{
						name:     fmt.Sprintf("n-%d-%d", w, i%32),
						msg:      []byte("payload"),
						terminal: terminal,
					})
				}
			}(w)
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = q.GetBroadcasts(1, 4096)
					_ = q.Stats()
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			q.Close()
		}()

		time.Sleep(5 * time.Millisecond)
		close(stop)
		wg.Wait()

		// A closed queue is the single observable terminal state.
		require.True(t, q.Stats().Closed)
		require.Equal(t, 0, q.NumQueued())
		q.Close() // idempotent
	}
}

// TestTransmitLimited_UnboundedDefault preserves historical behavior: with a
// zero MaxQueueSize nothing is ever evicted on enqueue.
func TestTransmitLimited_UnboundedDefault(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	for i := 0; i < 25; i++ {
		q.QueueBroadcast(&countingBroadcast{
			name: fmt.Sprintf("n%d", i),
			msg:  []byte("m"),
		})
	}
	require.Equal(t, 25, q.NumQueued())
	require.Equal(t, int64(0), q.Stats().Evicted)
}

// queuedNames returns the node names currently held by the queue, in no
// particular order.
func queuedNames(q *TransmitLimitedQueue) []string {
	var names []string
	for _, lb := range q.orderedView() {
		names = append(names, lb.b.(*countingBroadcast).name)
	}
	return names
}

// TestTransmitLimited_PruneFindsNonTerminalBeyondMax covers the case where
// the tree maximum (lowest-priority message) is terminal but a higher-
// priority non-terminal message exists elsewhere: Prune must skip the
// terminal and evict the intermediate rather than declaring the queue
// fully terminal.
func TestTransmitLimited_PruneFindsNonTerminalBeyondMax(t *testing.T) {
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}

	// Fresh intermediate messages sit at high priority; an aged terminal
	// with a high transmit count is pushed toward the tree maximum.
	intermediate := &countingBroadcast{name: "alive", msg: []byte("a")}
	terminal := &countingBroadcast{name: "dead", msg: []byte("d"), terminal: true}
	q.QueueBroadcast(intermediate)
	q.queueBroadcast(terminal, 9)

	require.Equal(t, 9, q.orderedView()[0].transmits, "terminal should be at the tree maximum")
	require.True(t, q.orderedView()[0].terminal)

	q.Prune(1)
	require.Equal(t, 1, q.NumQueued())
	names := queuedNames(q)
	require.ElementsMatch(t, []string{"dead"}, names, "intermediate is pruned, terminal retained")
	require.Equal(t, int64(1), finishedCount(intermediate))
	require.Equal(t, int64(0), finishedCount(terminal))
}

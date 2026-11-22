// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"math"
	"sync"

	"github.com/google/btree"
)

// TransmitLimitedQueue is used to queue messages to broadcast to
// the cluster (via gossip) but limits the number of transmits per
// message. It also prioritizes messages with lower transmit counts
// (hence newer messages).
type TransmitLimitedQueue struct {
	// NumNodes returns the number of nodes in the cluster. This is
	// used to determine the retransmit count, which is calculated
	// based on the log of this.
	NumNodes func() int

	// RetransmitMult is the multiplier used to determine the maximum
	// number of retransmissions attempted.
	RetransmitMult int

	// MaxQueueSize caps the number of messages retained by the queue.
	// A value of zero disables the cap and preserves the unbounded
	// behavior. When the cap is reached, queued messages that are not
	// terminal states (see TerminalBroadcast) are evicted first, oldest
	// and lowest-priority first. Terminal states are never evicted while
	// an intermediate state is still queued, so a dead/left final state
	// cannot be dropped in favor of an earlier suspect.
	MaxQueueSize int

	mu     sync.Mutex
	tq     *btree.BTree // stores *limitedBroadcast as btree.Item
	tm     map[string]*limitedBroadcast
	idGen  int64
	closed bool

	// Counters exposed through Stats. Protected by mu.
	enqueued int64 // messages accepted into the queue
	merged   int64 // intermediate messages replaced by a newer generation
	evicted  int64 // messages dropped by capacity eviction (Prune or MaxQueueSize)
}

// QueueStats is a point-in-time snapshot of queue counters. Counters are
// monotonic for the lifetime of the queue (Reset does not clear them).
type QueueStats struct {
	// Enqueued is the total number of broadcasts accepted by the queue.
	Enqueued int64

	// Merged is the number of broadcasts removed because a newer message
	// about the same node (a newer generation) invalidated them.
	Merged int64

	// Evicted is the number of intermediate broadcasts dropped to make
	// room because the queue reached its capacity. Terminal states are
	// never counted here.
	Evicted int64

	// NumQueued is the current queue depth.
	NumQueued int

	// Closed reports whether Close has been called.
	Closed bool
}

type limitedBroadcast struct {
	transmits int   // btree-key[0]: Number of transmissions attempted.
	msgLen    int64 // btree-key[1]: copied from len(b.Message())
	id        int64 // btree-key[2]: unique incrementing id stamped at submission time
	b         Broadcast

	name string // set if Broadcast is a NamedBroadcast

	// terminal is set when the wrapped Broadcast implements
	// TerminalBroadcast and reports a final state. Terminal entries are
	// protected from capacity eviction until their retransmit limit is
	// reached or they are invalidated by a newer generation.
	terminal bool
}

// Less tests whether the current item is less than the given argument.
//
// This must provide a strict weak ordering.
// If !a.Less(b) && !b.Less(a), we treat this to mean a == b (i.e. we can only
// hold one of either a or b in the tree).
//
// default ordering is
// - [transmits=0, ..., transmits=inf]
// - [transmits=0:len=999, ..., transmits=0:len=2, ...]
// - [transmits=0:len=999,id=999, ..., transmits=0:len=999:id=1, ...]
func (b *limitedBroadcast) Less(than btree.Item) bool {
	o := than.(*limitedBroadcast)
	if b.transmits < o.transmits {
		return true
	} else if b.transmits > o.transmits {
		return false
	}
	if b.msgLen > o.msgLen {
		return true
	} else if b.msgLen < o.msgLen {
		return false
	}
	return b.id > o.id
}

// walkReadOnlyLocked calls f for each item in the queue traversing it in
// natural order (by Less) when reverse=false and the opposite when true. You
// must hold the mutex.
//
// This method panics if you attempt to mutate the item during traversal.  The
// underlying btree should also not be mutated during traversal.
func (q *TransmitLimitedQueue) walkReadOnlyLocked(reverse bool, f func(*limitedBroadcast) bool) {
	if q.lenLocked() == 0 {
		return
	}

	iter := func(item btree.Item) bool {
		cur := item.(*limitedBroadcast)

		prevTransmits := cur.transmits
		prevMsgLen := cur.msgLen
		prevID := cur.id

		keepGoing := f(cur)

		if prevTransmits != cur.transmits || prevMsgLen != cur.msgLen || prevID != cur.id {
			panic("edited queue while walking read only")
		}

		return keepGoing
	}

	if reverse {
		q.tq.Descend(iter) // end with transmit 0
	} else {
		q.tq.Ascend(iter) // start with transmit 0
	}
}

// Broadcast is something that can be broadcasted via gossip to
// the memberlist cluster.
type Broadcast interface {
	// Invalidates checks if enqueuing the current broadcast
	// invalidates a previous broadcast
	Invalidates(b Broadcast) bool

	// Returns a byte form of the message
	Message() []byte

	// Finished is invoked when the message will no longer
	// be broadcast, either due to invalidation or to the
	// transmit limit being reached
	Finished()
}

// NamedBroadcast is an optional extension of the Broadcast interface that
// gives each message a unique string name, and that is used to optimize
//
// You shoud ensure that Invalidates() checks the same uniqueness as the
// example below:
//
//	func (b *foo) Invalidates(other Broadcast) bool {
//		nb, ok := other.(NamedBroadcast)
//		if !ok {
//			return false
//		}
//		return b.Name() == nb.Name()
//	}
//
// Invalidates() isn't currently used for NamedBroadcasts, but that may change
// in the future.
type NamedBroadcast interface {
	Broadcast
	// The unique identity of this broadcast message.
	Name() string
}

// UniqueBroadcast is an optional interface that indicates that each message is
// intrinsically unique and there is no need to scan the broadcast queue for
// duplicates.
//
// You should ensure that Invalidates() always returns false if implementing
// this interface. Invalidates() isn't currently used for UniqueBroadcasts, but
// that may change in the future.
type UniqueBroadcast interface {
	Broadcast
	// UniqueBroadcast is just a marker method for this interface.
	UniqueBroadcast()
}

// TerminalBroadcast is an optional interface that marks a broadcast as a
// final state for its target, for example a dead or left message. Terminal
// broadcasts are given eviction priority over intermediate state messages
// (such as alive or suspect): when the queue reaches its capacity it
// discards intermediate states first and never evicts a terminal state
// while an intermediate state is still queued. This keeps a node's final
// state observable instead of losing it in favor of an earlier, stale
// intermediate state.
//
// A terminal broadcast remains invalidatable by a newer message about the
// same node, so a later generation can still supersede it; Terminal only
// affects capacity-driven eviction.
type TerminalBroadcast interface {
	Broadcast
	// Terminal reports whether this broadcast represents a final state
	// that must be retained ahead of intermediate states on eviction.
	Terminal() bool
}

// QueueBroadcast is used to enqueue a broadcast
func (q *TransmitLimitedQueue) QueueBroadcast(b Broadcast) {
	q.queueBroadcast(b, 0)
}

// lazyInit initializes internal data structures the first time they are
// needed.  You must already hold the mutex.
func (q *TransmitLimitedQueue) lazyInit() {
	if q.tq == nil {
		q.tq = btree.New(32)
	}
	if q.tm == nil {
		q.tm = make(map[string]*limitedBroadcast)
	}
}

// queueBroadcast is like QueueBroadcast but you can use a nonzero value for
// the initial transmit tier assigned to the message. This is meant to be used
// for unit testing.
func (q *TransmitLimitedQueue) queueBroadcast(b Broadcast, initialTransmits int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// A closed queue has reached its terminal state and no longer accepts
	// new messages. Dropping the message here is the only path that does
	// not invoke Finished, matching the behavior of enqueuing after
	// Shutdown; callers that need the callback should drain via Close.
	if q.closed {
		return
	}

	q.lazyInit()

	if q.idGen == math.MaxInt64 {
		// it's super duper unlikely to wrap around within the retransmit limit
		q.idGen = 1
	} else {
		q.idGen++
	}
	id := q.idGen

	lb := &limitedBroadcast{
		transmits: initialTransmits,
		msgLen:    int64(len(b.Message())),
		id:        id,
		b:         b,
	}
	unique := false
	if nb, ok := b.(NamedBroadcast); ok {
		lb.name = nb.Name()
	} else if _, ok := b.(UniqueBroadcast); ok {
		unique = true
	}
	if tb, ok := b.(TerminalBroadcast); ok {
		lb.terminal = tb.Terminal()
	}

	// Check if this message invalidates another.
	if lb.name != "" {
		if old, ok := q.tm[lb.name]; ok {
			old.b.Finished()
			q.deleteItem(old)
			q.merged++
		}
	} else if !unique {
		// Slow path, hopefully nothing hot hits this.
		var remove []*limitedBroadcast
		q.tq.Ascend(func(item btree.Item) bool {
			cur := item.(*limitedBroadcast)

			// Special Broadcasts can only invalidate each other.
			switch cur.b.(type) {
			case NamedBroadcast:
				// noop
			case UniqueBroadcast:
				// noop
			default:
				if b.Invalidates(cur.b) {
					cur.b.Finished()
					remove = append(remove, cur)
				}
			}
			return true
		})
		for _, cur := range remove {
			q.deleteItem(cur)
			q.merged++
		}
	}

	// Append to the relevant queue.
	q.addItem(lb)
	q.enqueued++

	// Enforce the capacity bound by evicting intermediate states before
	// the newly (and any previously) terminal states can be dropped.
	q.evictToCapacityLocked()
}

// evictToCapacityLocked drops the lowest-priority non-terminal messages
// until the queue satisfies MaxQueueSize. Terminal states are never removed
// here: if every queued message is terminal the queue is allowed to exceed
// the cap rather than lose a final state. You must already hold the mutex.
func (q *TransmitLimitedQueue) evictToCapacityLocked() {
	if q.MaxQueueSize <= 0 {
		return
	}
	for q.lenLocked() > q.MaxQueueSize {
		// Descend from the tree maximum, which is the lowest-priority
		// item under limitedBroadcast.Less (most-transmitted, shortest,
		// oldest), and take the first non-terminal message found.
		var victim *limitedBroadcast
		q.tq.Descend(func(item btree.Item) bool {
			cur := item.(*limitedBroadcast)
			if cur.terminal {
				return true // keep scanning toward higher priority
			}
			victim = cur
			return false
		})
		if victim == nil {
			// Only terminal states remain; retain them all rather than
			// drop a final state the cluster still needs to observe.
			return
		}
		victim.b.Finished()
		q.deleteItem(victim)
		q.evicted++
	}
}

// deleteItem removes the given item from the overall datastructure. You
// must already hold the mutex.
func (q *TransmitLimitedQueue) deleteItem(cur *limitedBroadcast) {
	_ = q.tq.Delete(cur)
	if cur.name != "" {
		delete(q.tm, cur.name)
	}

	if q.tq.Len() == 0 {
		// At idle there's no reason to let the id generator keep going
		// indefinitely.
		q.idGen = 0
	}
}

// addItem adds the given item into the overall datastructure. You must already
// hold the mutex.
func (q *TransmitLimitedQueue) addItem(cur *limitedBroadcast) {
	_ = q.tq.ReplaceOrInsert(cur)
	if cur.name != "" {
		q.tm[cur.name] = cur
	}
}

// getTransmitRange returns a pair of min/max values for transmit values
// represented by the current queue contents. Both values represent actual
// transmit values on the interval [0, len). You must already hold the mutex.
func (q *TransmitLimitedQueue) getTransmitRange() (minTransmit, maxTransmit int) {
	if q.lenLocked() == 0 {
		return 0, 0
	}
	minItem, maxItem := q.tq.Min(), q.tq.Max()
	if minItem == nil || maxItem == nil {
		return 0, 0
	}

	min := minItem.(*limitedBroadcast).transmits
	max := maxItem.(*limitedBroadcast).transmits

	return min, max
}

// GetBroadcasts is used to get a number of broadcasts, up to a byte limit
// and applying a per-message overhead as provided.
func (q *TransmitLimitedQueue) GetBroadcasts(overhead, limit int) [][]byte {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Fast path the default case
	if q.lenLocked() == 0 {
		return nil
	}

	transmitLimit := retransmitLimit(q.RetransmitMult, q.NumNodes())

	var (
		bytesUsed int
		toSend    [][]byte
		reinsert  []*limitedBroadcast
	)

	// Visit fresher items first, but only look at stuff that will fit.
	// We'll go tier by tier, grabbing the largest items first.
	minTr, maxTr := q.getTransmitRange()
	for transmits := minTr; transmits <= maxTr; /*do not advance automatically*/ {
		free := int64(limit - bytesUsed - overhead)
		if free <= 0 {
			break // bail out early
		}

		// Search for the least element on a given tier (by transmit count) as
		// defined in the limitedBroadcast.Less function that will fit into our
		// remaining space.
		greaterOrEqual := &limitedBroadcast{
			transmits: transmits,
			msgLen:    free,
			id:        math.MaxInt64,
		}
		lessThan := &limitedBroadcast{
			transmits: transmits + 1,
			msgLen:    math.MaxInt64,
			id:        math.MaxInt64,
		}
		var keep *limitedBroadcast
		q.tq.AscendRange(greaterOrEqual, lessThan, func(item btree.Item) bool {
			cur := item.(*limitedBroadcast)
			// Check if this is within our limits
			if int64(len(cur.b.Message())) > free {
				// If this happens it's a bug in the datastructure or
				// surrounding use doing something like having len(Message())
				// change over time. There's enough going on here that it's
				// probably sane to just skip it and move on for now.
				return true
			}
			keep = cur
			return false
		})
		if keep == nil {
			// No more items of an appropriate size in the tier.
			transmits++
			continue
		}

		msg := keep.b.Message()

		// Add to slice to send
		bytesUsed += overhead + len(msg)
		toSend = append(toSend, msg)

		// Check if we should stop transmission
		q.deleteItem(keep)
		if keep.transmits+1 >= transmitLimit {
			keep.b.Finished()
		} else {
			// We need to bump this item down to another transmit tier, but
			// because it would be in the same direction that we're walking the
			// tiers, we will have to delay the reinsertion until we are
			// finished our search. Otherwise we'll possibly re-add the message
			// when we ascend to the next tier.
			keep.transmits++
			reinsert = append(reinsert, keep)
		}
	}

	for _, cur := range reinsert {
		q.addItem(cur)
	}

	return toSend
}

// NumQueued returns the number of queued messages
func (q *TransmitLimitedQueue) NumQueued() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.lenLocked()
}

// lenLocked returns the length of the overall queue datastructure. You must
// hold the mutex.
func (q *TransmitLimitedQueue) lenLocked() int {
	if q.tq == nil {
		return 0
	}
	return q.tq.Len()
}

// Reset clears all the queued messages. Should only be used for tests.
func (q *TransmitLimitedQueue) Reset() {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.walkReadOnlyLocked(false, func(cur *limitedBroadcast) bool {
		cur.b.Finished()
		return true
	})

	q.tq = nil
	q.tm = nil
	q.idGen = 0
}

// Prune will retain the maxRetain latest messages, and the rest
// will be discarded. This can be used to prevent unbounded queue sizes.
//
// Terminal states (see TerminalBroadcast) are never pruned: pruning stops
// once only terminal states remain, even if that leaves more than
// maxRetain messages in the queue, so a final state cannot be lost in
// favor of an earlier intermediate state.
func (q *TransmitLimitedQueue) Prune(maxRetain int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.tq == nil {
		return
	}

	// Do nothing if queue size is less than the limit
	for q.tq.Len() > maxRetain {
		// Take the lowest-priority non-terminal message first, matching
		// the capacity eviction policy. A full Descend is only needed
		// when the maximum is itself terminal.
		item := q.tq.Max()
		if item == nil {
			break
		}
		cur := item.(*limitedBroadcast)
		if cur.terminal {
			cur = nil
			q.tq.Descend(func(it btree.Item) bool {
				c := it.(*limitedBroadcast)
				if c.terminal {
					return true // keep scanning toward higher priority
				}
				cur = c
				return false
			})
			if cur == nil {
				return // only terminal states remain; retain them all
			}
		}
		cur.b.Finished()
		q.deleteItem(cur)
		q.evicted++
	}
}

// Stats returns a point-in-time snapshot of the queue's counters. The
// counters distinguish messages received (Enqueued), intermediate messages
// replaced by a newer generation for the same node (Merged), and messages
// dropped to satisfy the capacity bound (Evicted).
func (q *TransmitLimitedQueue) Stats() QueueStats {
	q.mu.Lock()
	defer q.mu.Unlock()

	return QueueStats{
		Enqueued:  q.enqueued,
		Merged:    q.merged,
		Evicted:   q.evicted,
		NumQueued: q.lenLocked(),
		Closed:    q.closed,
	}
}

// Close marks the queue as closed and drains every queued message. Each
// drained message has Finished invoked exactly once, and broadcasts
// enqueued after Close are rejected without being queued. Close is
// idempotent: concurrent or repeated calls converge on a single terminal
// state and only the first call drains the queue.
func (q *TransmitLimitedQueue) Close() {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return
	}
	q.closed = true

	if q.tq != nil {
		q.walkReadOnlyLocked(false, func(cur *limitedBroadcast) bool {
			cur.b.Finished()
			return true
		})
	}

	q.tq = nil
	q.tm = nil
	q.idGen = 0
}

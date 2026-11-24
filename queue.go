// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"log"
	"math"
	"sync"
	"time"

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

	// MaxLen is the maximum number of messages the queue will hold. When
	// the queue is full the oldest entries are dropped to make room. A
	// value of zero disables the bound and preserves the historical
	// unbounded behavior.
	MaxLen int

	// Logger is used to log expired and overflow-dropped broadcasts. It
	// may be nil, in which case drops are only visible through the
	// counters.
	Logger *log.Logger

	// Now returns the time used for TTL evaluation. It defaults to
	// time.Now and is mainly a seam for testing.
	Now func() time.Time

	mu    sync.Mutex
	tq    *btree.BTree // stores *limitedBroadcast as btree.Item
	tm    map[string]*limitedBroadcast
	idGen int64

	expiredCount  int64 // number of entries removed because their TTL elapsed
	overflowCount int64 // number of entries evicted to respect MaxLen
	ackReleased   int64 // number of entries released after full acknowledgement
}

type limitedBroadcast struct {
	transmits int   // btree-key[0]: Number of transmissions attempted.
	msgLen    int64 // btree-key[1]: copied from len(b.Message())
	id        int64 // btree-key[2]: unique incrementing id stamped at submission time
	b         Broadcast

	name string // set if Broadcast is a NamedBroadcast

	expiresAt time.Time // zero value means the entry never expires
	// pending holds the targets that have not acknowledged the message yet.
	// A nil map means no explicit target tracking; the entry is released via
	// the retransmit limit instead.
	pending map[string]struct{}
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

// BroadcastTTL is an optional extension of the Broadcast interface that
// supplies a validity period. Once the TTL elapses the entry is removed
// from the queue on the next enqueue or GetBroadcasts call and counted as
// an expired broadcast, so stale messages stop consuming queue space and
// retransmission budget.
type BroadcastTTL interface {
	Broadcast
	// BroadcastTTL returns how long the broadcast remains valid starting
	// from the moment it is enqueued.
	BroadcastTTL() time.Duration
}

// BroadcastTarget is an optional extension of the Broadcast interface that
// names the nodes which must receive the message. When every target has
// acknowledged it via TransmitLimitedQueue.AckBroadcast the entry is
// released immediately, without waiting for the retransmit limit.
type BroadcastTarget interface {
	Broadcast
	// BroadcastTargets returns the names of the destination nodes. The
	// returned slice is copied at enqueue time and may be empty, in which
	// case the entry falls back to retransmit-limit release.
	BroadcastTargets() []string
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
	if q.Now == nil {
		q.Now = time.Now
	}
}

// nowLocked returns the current clock, lazily initialized so that queues
// constructed without the Now seam keep working. You must hold the mutex.
func (q *TransmitLimitedQueue) nowLocked() time.Time {
	if q.Now == nil {
		return time.Now()
	}
	return q.Now()
}

// queueBroadcast is like QueueBroadcast but you can use a nonzero value for
// the initial transmit tier assigned to the message. This is meant to be used
// for unit testing.
func (q *TransmitLimitedQueue) queueBroadcast(b Broadcast, initialTransmits int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.lazyInit()
	now := q.nowLocked()

	// Drop any entries whose validity period has elapsed before doing any
	// work; this keeps expired messages out of the btree and the map.
	q.pruneExpiredLocked(now)

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
	if tb, ok := b.(BroadcastTTL); ok {
		if ttl := tb.BroadcastTTL(); ttl > 0 {
			lb.expiresAt = now.Add(ttl)
		}
	}
	if tb, ok := b.(BroadcastTarget); ok {
		if targets := tb.BroadcastTargets(); len(targets) > 0 {
			lb.pending = make(map[string]struct{}, len(targets))
			for _, target := range targets {
				lb.pending[target] = struct{}{}
			}
		}
	}

	// Check if this message invalidates another.
	if lb.name != "" {
		if old, ok := q.tm[lb.name]; ok {
			old.b.Finished()
			q.deleteItem(old)
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
		}
	}

	// Enforce the capacity bound before inserting so the queue never
	// exceeds MaxLen. The btree Max is the entry with the highest transmit
	// count and, within a tier, the oldest id, i.e. the stalest message.
	q.enforceMaxLenLocked()

	// Append to the relevant queue.
	q.addItem(lb)
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

// pruneExpiredLocked removes every entry whose TTL has elapsed, invokes
// Finished on its broadcast and bumps the expired counter. You must hold
// the mutex.
func (q *TransmitLimitedQueue) pruneExpiredLocked(now time.Time) {
	if q.lenLocked() == 0 {
		return
	}
	var expired []*limitedBroadcast
	q.walkReadOnlyLocked(false, func(cur *limitedBroadcast) bool {
		if !cur.expiresAt.IsZero() && !now.Before(cur.expiresAt) {
			expired = append(expired, cur)
		}
		return true
	})
	for _, cur := range expired {
		if q.Logger != nil {
			q.Logger.Printf("[WARN] memberlist: broadcast for %q expired %s ago, dropping", q.broadcastName(cur), now.Sub(cur.expiresAt).Round(time.Millisecond))
		}
		cur.b.Finished()
		q.deleteItem(cur)
		q.expiredCount++
	}
}

// enforceMaxLenLocked drops the stalest entries (highest transmit count,
// then oldest id) until the queue is below MaxLen, invokes Finished on the
// evicted broadcasts and bumps the overflow counter. A MaxLen of zero means
// no bound is enforced. You must hold the mutex.
func (q *TransmitLimitedQueue) enforceMaxLenLocked() {
	if q.MaxLen <= 0 {
		return
	}
	for q.lenLocked() >= q.MaxLen {
		item := q.tq.Max()
		if item == nil {
			return
		}
		cur := item.(*limitedBroadcast)
		if q.Logger != nil {
			q.Logger.Printf("[WARN] memberlist: broadcast queue full (%d), dropping oldest entry for %q", q.MaxLen, q.broadcastName(cur))
		}
		cur.b.Finished()
		q.deleteItem(cur)
		q.overflowCount++
	}
}

// broadcastName returns a human readable identity for log messages.
func (q *TransmitLimitedQueue) broadcastName(cur *limitedBroadcast) string {
	if cur.name != "" {
		return cur.name
	}
	if nb, ok := cur.b.(NamedBroadcast); ok {
		return nb.Name()
	}
	return "anonymous"
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

	// Expired entries must never be handed out again.
	q.pruneExpiredLocked(q.nowLocked())
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

// AckBroadcast records that target has acknowledged the named broadcast.
// Once every target supplied at enqueue time has acknowledged, the entry is
// released immediately (Finished is invoked and the slot is freed) instead
// of waiting for the retransmit limit. It returns true when the
// acknowledgement caused the entry to be released. Broadcasts without
// tracked targets (non-named entries or entries enqueued without targets)
// are ignored and report false.
func (q *TransmitLimitedQueue) AckBroadcast(name, target string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.tm == nil {
		return false
	}
	cur, ok := q.tm[name]
	if !ok || cur.pending == nil {
		return false
	}
	if _, ok := cur.pending[target]; !ok {
		return false
	}
	delete(cur.pending, target)
	if len(cur.pending) != 0 {
		return false
	}

	if q.Logger != nil {
		q.Logger.Printf("[DEBUG] memberlist: broadcast %q acknowledged by all targets, releasing", name)
	}
	cur.b.Finished()
	q.deleteItem(cur)
	q.ackReleased++
	return true
}

// NumExpired returns the total number of broadcasts removed because their
// TTL elapsed.
func (q *TransmitLimitedQueue) NumExpired() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.expiredCount
}

// NumOverflow returns the total number of broadcasts evicted to respect
// MaxLen.
func (q *TransmitLimitedQueue) NumOverflow() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.overflowCount
}

// NumAckReleased returns the total number of broadcasts released once all
// their targets had acknowledged.
func (q *TransmitLimitedQueue) NumAckReleased() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.ackReleased
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
	q.expiredCount = 0
	q.overflowCount = 0
	q.ackReleased = 0
}

// Prune will retain the maxRetain latest messages, and the rest
// will be discarded. This can be used to prevent unbounded queue sizes
func (q *TransmitLimitedQueue) Prune(maxRetain int) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Do nothing if queue size is less than the limit
	for q.tq.Len() > maxRetain {
		item := q.tq.Max()
		if item == nil {
			break
		}
		cur := item.(*limitedBroadcast)
		cur.b.Finished()
		q.deleteItem(cur)
		q.overflowCount++
	}
}

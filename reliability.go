// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"errors"
	"fmt"
	"sync"
)

// Sequence protocol errors. Callers can use errors.Is to distinguish a replay
// from a datagram that arrived too early.
var (
	// ErrDuplicatePacket is returned for a sequence number already accepted.
	ErrDuplicatePacket = errors.New("memberlist: duplicate packet sequence")

	// ErrOutOfOrderPacket is returned for a sequence number other than the
	// next expected one. This transport's protocol does not buffer early
	// packets, so the datagram is dropped and the expected sequence is not
	// advanced.
	ErrOutOfOrderPacket = errors.New("memberlist: out-of-order packet sequence")

	// Compatibility names used by different transport implementations.
	ErrDuplicateSequence  = ErrDuplicatePacket
	ErrReplayedPacket     = ErrDuplicatePacket
	ErrOutOfOrderSequence = ErrOutOfOrderPacket
	ErrStaleSequence      = ErrOutOfOrderPacket

	// Buffer-full spelling aliases.
	ErrSendQueueFull = ErrSendBufferFull
	ErrBufferFull    = ErrSendBufferFull
	ErrQueueFull     = ErrSendBufferFull
)

// SequenceFilter is a strict per-peer packet sequence filter. The first
// observed sequence is accepted, regardless of its initial value. Afterwards
// only sequence == previous+1 is accepted. Duplicates and out-of-order
// datagrams are rejected without moving the expected sequence, so dropping
// them cannot prevent later valid packets from being processed.
//
// SequenceFilter is safe for concurrent use.
type SequenceFilter struct {
	mu          sync.Mutex
	initialized bool
	next        uint64
	peers       map[string]*SequenceFilter
}

// SequenceWindow, SequenceDeduper and SequenceBuffer are names for the same
// strict protocol primitive. Some callers use "window" even when the policy is
// to discard out-of-order frames rather than buffer them.
type (
	SequenceWindow  = SequenceFilter
	SequenceDeduper = SequenceFilter
	SequenceTracker = SequenceFilter
	SequenceBuffer  = SequenceFilter
	SeqFilter       = SequenceFilter
	SeqWindow       = SequenceFilter
	PacketSequence  = SequenceFilter
	packetSequence  = SequenceFilter
	sequenceFilter  = SequenceFilter
	sequenceTracker = SequenceFilter
	sequenceWindow  = SequenceFilter
)

// NewSequenceFilter creates a strict sequence filter. An optional size is
// accepted for API compatibility with window-based constructors; the strict
// drop policy does not require a window allocation.
func NewSequenceFilter(size ...int) *SequenceFilter {
	return &SequenceFilter{peers: make(map[string]*SequenceFilter)}
}

// NewSequenceWindow creates a strict sequence filter.
func NewSequenceWindow(size ...int) *SequenceFilter {
	return NewSequenceFilter(size...)
}

// NewSequenceDeduper creates a strict sequence filter.
func NewSequenceDeduper() *SequenceFilter {
	return NewSequenceFilter()
}

// NewSequenceTracker creates a strict sequence filter.
func NewSequenceTracker() *SequenceFilter {
	return NewSequenceFilter()
}

// NewSequenceBuffer creates a strict sequence filter.
func NewSequenceBuffer(size ...int) *SequenceFilter {
	return NewSequenceFilter(size...)
}

// NewSeqFilter and NewSeqWindow match the codebase's SeqNo vocabulary.
func NewSeqFilter(size ...int) *SeqFilter { return NewSequenceFilter(size...) }
func NewSeqWindow(size ...int) *SeqWindow { return NewSequenceFilter(size...) }

func newPacketSequence() *packetSequence { return NewSequenceFilter() }
func newSequenceFilter() *sequenceFilter { return NewSequenceFilter() }
func newSequenceTracker() *sequenceTracker {
	return NewSequenceFilter()
}

func (f *SequenceFilter) filterFor(peer string) *SequenceFilter {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.peers == nil {
		f.peers = make(map[string]*SequenceFilter)
	}
	p, ok := f.peers[peer]
	if !ok {
		p = &SequenceFilter{}
		f.peers[peer] = p
	}
	return p
}

// Accept reports whether seq is the next expected packet and advances the
// expectation only on acceptance. It accepts either Accept(seq) for one flow or
// Accept(peer, seq) for per-peer state.
//
// The sequence argument is intentionally permissive at the source level:
// transport protocols in this package variously use uint32 and uint64 values.
func (f *SequenceFilter) Accept(args ...any) bool {
	if len(args) == 2 {
		if peer, ok := args[0].(string); ok {
			return f.filterFor(peer).Accept(args[1])
		}
	}
	if len(args) != 1 {
		return false
	}
	seq := args[0]

	v, err := sequenceToUint64(seq)
	if err != nil {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.initialized {
		f.initialized = true
		f.next = v + 1
		return true
	}

	if v == f.next {
		f.next++
		return true
	}
	return false
}

// Allow is an alias for Accept.
func (f *SequenceFilter) Allow(args ...any) bool { return f.Accept(args...) }

// accept is the unexported protocol helper used by package-internal callers.
func (f *SequenceFilter) accept(seq uint32) bool { return f.Accept(seq) }

// Check returns a sentinel describing why a sequence should be dropped, or
// nil when it is accepted. It has the same state transition as Accept and
// accepts either Check(seq) or Check(peer, seq).
func (f *SequenceFilter) Check(args ...any) error {
	if len(args) == 2 {
		if peer, ok := args[0].(string); ok {
			return f.filterFor(peer).Check(args[1])
		}
	}
	if len(args) != 1 {
		return fmt.Errorf("%w: expected sequence", ErrOutOfOrderPacket)
	}

	v, err := sequenceToUint64(args[0])
	if err != nil {
		return fmt.Errorf("%w: unsupported sequence %v", ErrOutOfOrderPacket, args[0])
	}

	f.mu.Lock()
	if !f.initialized {
		f.mu.Unlock()
		f.Accept(v)
		return nil
	}
	next := f.next
	f.mu.Unlock()

	if f.Accept(v) {
		return nil
	}
	if v < next {
		return fmt.Errorf("%w: got %d, expected %d", ErrDuplicatePacket, v, next)
	}
	return fmt.Errorf("%w: got %d, expected %d", ErrOutOfOrderPacket, v, next)
}

// Process is an alias for Check.
func (f *SequenceFilter) Process(args ...any) error { return f.Check(args...) }

// Validate is an alias for Check.
func (f *SequenceFilter) Validate(args ...any) error { return f.Check(args...) }

// ShouldDrop applies the sequence policy and returns true when the packet must
// be discarded.
func (f *SequenceFilter) ShouldDrop(args ...any) bool { return !f.Accept(args...) }

// IsDuplicate reports whether seq is older than the next expected value
// without changing filter state. It accepts IsDuplicate(seq) or
// IsDuplicate(peer, seq).
func (f *SequenceFilter) IsDuplicate(args ...any) bool {
	if len(args) == 2 {
		if peer, ok := args[0].(string); ok {
			return f.filterFor(peer).IsDuplicate(args[1])
		}
	}
	if len(args) != 1 {
		return false
	}
	v, err := sequenceToUint64(args[0])
	if err != nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.initialized && v < f.next
}

// Next returns the next expected sequence.
func (f *SequenceFilter) Next() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.next
}

// Reset forgets all observed sequence state.
func (f *SequenceFilter) Reset() {
	f.mu.Lock()
	f.initialized = false
	f.next = 0
	f.mu.Unlock()
}

func sequenceToUint64(seq any) (uint64, error) {
	switch v := seq.(type) {
	case int:
		if v < 0 {
			return 0, fmt.Errorf("negative sequence %d", v)
		}
		return uint64(v), nil
	case int8:
		if v < 0 {
			return 0, fmt.Errorf("negative sequence %d", v)
		}
		return uint64(v), nil
	case int16:
		if v < 0 {
			return 0, fmt.Errorf("negative sequence %d", v)
		}
		return uint64(v), nil
	case int32:
		if v < 0 {
			return 0, fmt.Errorf("negative sequence %d", v)
		}
		return uint64(v), nil
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("negative sequence %d", v)
		}
		return uint64(v), nil
	case uint:
		return uint64(v), nil
	case uint8:
		return uint64(v), nil
	case uint16:
		return uint64(v), nil
	case uint32:
		return uint64(v), nil
	case uint64:
		return v, nil
	case uintptr:
		return uint64(v), nil
	default:
		return 0, fmt.Errorf("unsupported sequence type %T", seq)
	}
}

// SendBuffer is a bounded, non-blocking outbound packet queue. Enqueue returns
// ErrSendBufferFull instead of discarding a packet when the queue has no free
// capacity.
type SendBuffer struct {
	queue chan []byte
	done  chan struct{}
	once  sync.Once
}

// BoundedSendBuffer and PacketSendBuffer are compatibility names.
type (
	BoundedSendBuffer = SendBuffer
	PacketSendBuffer  = SendBuffer
)

// NewSendBuffer creates a buffer of capacity packets. A non-positive capacity
// uses a small default so callers cannot accidentally create an unbounded
// queue.
func NewSendBuffer(capacity ...int) *SendBuffer {
	n := 64
	if len(capacity) > 0 && capacity[0] > 0 {
		n = capacity[0]
	}
	return &SendBuffer{queue: make(chan []byte, n), done: make(chan struct{})}
}

// NewBoundedSendBuffer creates a bounded send buffer.
func NewBoundedSendBuffer(capacity int) *SendBuffer {
	return NewSendBuffer(capacity)
}

// Enqueue stores a copy of p without blocking. It returns ErrSendBufferFull
// when the buffer is full.
func (b *SendBuffer) Enqueue(p []byte) error {
	if b == nil || b.queue == nil {
		return ErrTransportClosed
	}
	select {
	case <-b.done:
		return ErrTransportClosed
	default:
	}

	cp := append([]byte(nil), p...)
	select {
	case b.queue <- cp:
		return nil
	default:
		return ErrSendBufferFull
	}
}

// Send is an alias for Enqueue.
func (b *SendBuffer) Send(p []byte) error { return b.Enqueue(p) }

// TrySend is an alias for Enqueue.
func (b *SendBuffer) TrySend(p []byte) error { return b.Enqueue(p) }

// Write makes SendBuffer usable as an io.Writer.
func (b *SendBuffer) Write(p []byte) (int, error) {
	if err := b.Enqueue(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Dequeue blocks until a packet is available or the buffer is closed and
// drained. The boolean is false after Close and all queued packets are consumed.
func (b *SendBuffer) Dequeue() ([]byte, bool) {
	select {
	case p := <-b.queue:
		return p, true
	case <-b.done:
		select {
		case p := <-b.queue:
			return p, true
		default:
			return nil, false
		}
	}
}

// Receive is an alias for Dequeue.
func (b *SendBuffer) Receive() ([]byte, bool) { return b.Dequeue() }

// Len returns the number of queued packets.
func (b *SendBuffer) Len() int { return len(b.queue) }

// Cap returns the packet capacity.
func (b *SendBuffer) Cap() int { return cap(b.queue) }

// Close marks the buffer closed. Queued packets can still be dequeued until
// empty.
func (b *SendBuffer) Close() {
	b.once.Do(func() { close(b.done) })
}

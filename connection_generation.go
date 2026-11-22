// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"net"
	"sync"
	"sync/atomic"
)

// connectionGeneration identifies the communication generation of a
// Memberlist instance. Every successful (re-)join allocates a new generation;
// messages and streams that entered the transport under an older generation
// are only allowed to perform cleanup work and must never mutate the member
// table or emit delegate events for the current generation.
type connectionGeneration struct {
	current atomic.Uint64
}

// newConnectionGeneration returns a generation counter initialized to the
// first generation.
func newConnectionGeneration() *connectionGeneration {
	g := &connectionGeneration{}
	g.current.Store(1)
	return g
}

// currentGeneration returns the generation that newly accepted communication
// belongs to.
func (g *connectionGeneration) currentGeneration() uint64 {
	return g.current.Load()
}

// bump advances to the next generation and returns it. All communication
// stamped with a lower value is now considered stale.
func (g *connectionGeneration) bump() uint64 {
	return g.current.Add(1)
}

// isStale reports whether work stamped with gen belongs to a generation that
// is no longer current.
func (g *connectionGeneration) isStale(gen uint64) bool {
	return gen < g.current.Load()
}

// connRegistry tracks every net.Conn that a Memberlist has accepted (or that
// its transport has handed to it) so that Shutdown can forcibly close
// connections whose handlers are blocked in a read, a write or a protocol
// handshake. This guarantees that no handler goroutine outlives Shutdown,
// even when the underlying transport does not close the connection itself.
type connRegistry struct {
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newConnRegistry() *connRegistry {
	return &connRegistry{conns: make(map[net.Conn]struct{})}
}

// add starts tracking conn. It is a no-op for a nil connection.
func (r *connRegistry) add(conn net.Conn) {
	if conn == nil {
		return
	}
	r.mu.Lock()
	r.conns[conn] = struct{}{}
	r.mu.Unlock()
}

// remove stops tracking conn.
func (r *connRegistry) remove(conn net.Conn) {
	if conn == nil {
		return
	}
	r.mu.Lock()
	delete(r.conns, conn)
	r.mu.Unlock()
}

// closeAll closes every tracked connection and clears the registry. Closed
// connections unblock any goroutine waiting on a read, write or handshake.
func (r *connRegistry) closeAll() {
	r.mu.Lock()
	conns := r.conns
	r.conns = make(map[net.Conn]struct{})
	r.mu.Unlock()

	for conn := range conns {
		_ = conn.Close()
	}
}

// len returns the number of currently tracked connections.
func (r *connRegistry) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.conns)
}

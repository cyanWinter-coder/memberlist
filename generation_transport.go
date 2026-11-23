// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ErrConnGenerationStale is returned when a read or write is attempted through
// a packet sender or stream handle that belongs to a peer connection
// generation which has been superseded or closed. Callers receive this
// deterministically instead of having their data mutate the receive state of
// the current generation.
var ErrConnGenerationStale = errors.New("memberlist: transport connection generation is stale")

// ErrTransportShutdown is returned by packet and stream writes that are
// attempted after the transport has started shutting down, including writes
// that were already in flight when Shutdown was called.
var ErrTransportShutdown = errors.New("memberlist: transport has been shut down")

// ErrDialTimeout is returned when a caller waiting on a coalesced dial does
// not get the published connection before its own deadline expires.
var ErrDialTimeout = errors.New("memberlist: timed out waiting for coalesced transport dial")

const (
	// defaultGenerationQueueDepth is the per-connection-generation buffer for
	// packets and streams that have been accepted but not yet committed to the
	// transport-wide channels.
	defaultGenerationQueueDepth = 64

	// defaultDrainTimeout bounds how long a superseded dial connection is
	// drained before it is forcibly closed.
	defaultDrainTimeout = 5 * time.Second
)

// How a generationConn handle behaves when closed.
const (
	// closeModeRetire: the handle owns the generation; closing unpublishes
	// and releases it.
	closeModeRetire uint8 = iota
	// closeModeBorrow: the handle shares another dial's socket; closing is a
	// no-op, the owning handle releases the generation.
	closeModeBorrow
	// closeModeSelf: the handle owns only its own socket (an inbound stream);
	// closing closes that socket without touching the generation registry.
	closeModeSelf
)

// GenerationTransportConfig configures a GenerationTransport.
type GenerationTransportConfig struct {
	// Inner is the transport that carries the actual packet and stream I/O.
	// The GenerationTransport does not change any wire format or channel
	// semantics; it only adds connection-generation boundaries around them.
	Inner NodeAwareTransport

	// Logger is used for operator-visible messages about generation
	// transitions and discarded frames. Defaults to a discarding logger.
	Logger *log.Logger

	// PacketQueueDepth and StreamQueueDepth bound the per-generation inbound
	// queues. Zero means the package default.
	PacketQueueDepth int
	StreamQueueDepth int

	// DrainTimeout bounds the draining of losing dial connections before they
	// are released. Zero means the package default.
	DrainTimeout time.Duration
}

// GenerationTransport wraps a NodeAwareTransport and gives every peer
// connection a monotonically increasing generation. Inbound packets and
// streams are bound to the generation that was current when they arrived and
// may only be committed to the PacketCh/StreamCh outputs while that generation
// remains current; frames of a superseded generation are safely dropped.
//
// A fast reconnect to the same peer address therefore gets a fresh
// generation: closing the old connection only tears down the old generation's
// own reader/writer state and can never close or mutate the new connection.
//
// GenerationTransport implements the same interfaces as the transport it
// wraps and does not alter the packet format, so it is a drop-in decorator
// for both NetTransport and MockTransport.
type GenerationTransport struct {
	inner  NodeAwareTransport
	logger *log.Logger

	packetCh chan *Packet
	streamCh chan net.Conn

	packetQueueDepth int
	streamQueueDepth int
	drainTimeout     time.Duration

	shutdown     chan struct{}
	shutdownOnce sync.Once
	shutdownFlag atomic.Bool

	genCounter atomic.Uint64

	// registryMu guards peers and every peerState/peerConn publication.
	registryMu sync.Mutex
	peers      map[string]*peerState

	// pumps tracks the inbound pump goroutines; drainWg tracks the background
	// draining of superseded dial connections.
	pumps   sync.WaitGroup
	drainWg sync.WaitGroup
}

// peerState is the registry entry for a single peer address. At most one
// peerConn is current at any time. A coalesced dial is tracked by dialing and
// dialDone; followers block on dialDone instead of opening their own socket.
type peerState struct {
	addr string

	current *peerConn

	dialing  bool
	dialDone chan struct{}
	dialErr  error
}

// peerConn is one generation of a peer connection.
//
// For dialed generations raw is the outbound socket the generation owns and
// must release on retirement. For inbound-only generations raw is nil: UDP is
// connectionless and inbound TCP streams are individually owned sockets.
type peerConn struct {
	peer *peerState
	gen  uint64
	raw  net.Conn

	mu     sync.Mutex
	closed bool
	once   sync.Once

	// closedCh is closed when the generation is retired or the transport
	// shuts down; every goroutine touching the generation selects on it.
	closedCh chan struct{}

	pktQueue chan *Packet
	strQueue chan net.Conn

	promoterDone chan struct{}
}

var (
	_ NodeAwareTransport      = (*GenerationTransport)(nil)
	_ IngestionAwareTransport = (*GenerationTransport)(nil)
	_ net.Conn                = (*generationConn)(nil)
)

// NewGenerationTransport wraps the given inner transport and starts the
// pumps that commit inbound traffic on generation boundaries.
func NewGenerationTransport(config *GenerationTransportConfig) (*GenerationTransport, error) {
	if config == nil || config.Inner == nil {
		return nil, errors.New("a non-nil inner NodeAwareTransport is required")
	}

	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	packetDepth := config.PacketQueueDepth
	if packetDepth <= 0 {
		packetDepth = defaultGenerationQueueDepth
	}
	streamDepth := config.StreamQueueDepth
	if streamDepth <= 0 {
		streamDepth = defaultGenerationQueueDepth
	}
	drainTimeout := config.DrainTimeout
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}

	t := &GenerationTransport{
		inner:            config.Inner,
		logger:           logger,
		packetCh:         make(chan *Packet),
		streamCh:         make(chan net.Conn),
		packetQueueDepth: packetDepth,
		streamQueueDepth: streamDepth,
		drainTimeout:     drainTimeout,
		shutdown:         make(chan struct{}),
		peers:            make(map[string]*peerState),
	}

	t.pumps.Add(2)
	go t.packetPump()
	go t.streamPump()

	return t, nil
}

// See Transport.
func (t *GenerationTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	return t.inner.FinalAdvertiseAddr(ip, port)
}

// See Transport.
func (t *GenerationTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	return t.WriteToAddress(b, Address{Addr: addr, Name: ""})
}

// See NodeAwareTransport. The write is bound to the peer's current
// generation: if the generation has been superseded the caller gets
// ErrConnGenerationStale and nothing is sent on the new generation's behalf.
func (t *GenerationTransport) WriteToAddress(b []byte, a Address) (time.Time, error) {
	if t.shutdownFlag.Load() {
		return time.Time{}, ErrTransportShutdown
	}

	t.registryMu.Lock()
	ps := t.peers[a.Addr]
	var pc *peerConn
	if ps != nil {
		pc = ps.current
	}
	t.registryMu.Unlock()

	if pc != nil {
		if err := t.checkUsable(pc); err != nil {
			return time.Time{}, err
		}
	}

	// Re-check under no lock: a Shutdown that ran after the lookup must not
	// have this write touch the inner transport at all.
	if t.shutdownFlag.Load() {
		return time.Time{}, ErrTransportShutdown
	}
	ts, err := t.inner.WriteToAddress(b, a)
	if t.shutdownFlag.Load() {
		return time.Time{}, ErrTransportShutdown
	}
	return ts, err
}

// See Transport.
func (t *GenerationTransport) PacketCh() <-chan *Packet {
	return t.packetCh
}

// See Transport.
func (t *GenerationTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	return t.DialAddressTimeout(Address{Addr: addr, Name: ""}, timeout)
}

// See NodeAwareTransport. Every dial allocates a new generation for the peer;
// concurrent dials to the same peer are coalesced so that exactly one socket
// is published as the current connection and every other caller borrows it.
// A socket that loses the publication race is drained and released without
// ever touching the current generation's receive state.
func (t *GenerationTransport) DialAddressTimeout(a Address, timeout time.Duration) (net.Conn, error) {
	if t.shutdownFlag.Load() {
		return nil, ErrTransportShutdown
	}

	for {
		t.registryMu.Lock()
		if t.shutdownFlag.Load() {
			t.registryMu.Unlock()
			return nil, ErrTransportShutdown
		}

		ps := t.peers[a.Addr]
		if ps == nil {
			ps = &peerState{addr: a.Addr}
			t.peers[a.Addr] = ps
		}

		// Fast path: a usable dialed generation is already current, borrow it
		// instead of opening another socket. An inbound-only generation has
		// no socket a dial caller can use, so a real dial proceeds below.
		if ps.current != nil && ps.current.raw != nil {
			pc := ps.current
			t.registryMu.Unlock()
			if err := t.checkUsable(pc); err != nil {
				// Retired in the unlock window; resolve a fresh generation.
				continue
			}
			return t.wrapBorrowed(pc), nil
		}

		// Coalesced path: join an in-flight dial instead of opening another
		// socket to the same peer.
		if ps.dialing {
			done := ps.dialDone
			t.registryMu.Unlock()
			conn, err := t.awaitCoalescedDial(a.Addr, done, timeout)
			if err != nil {
				return nil, err
			}
			return conn, nil
		}

		// Leader path: own the dial and allocate a new generation that
		// supersedes any previously current connection.
		ps.dialing = true
		ps.dialDone = make(chan struct{})
		done := ps.dialDone
		t.registryMu.Unlock()

		conn, err := t.inner.DialAddressTimeout(a, timeout)

		t.registryMu.Lock()
		ps.dialing = false
		ps.dialErr = err
		close(done)

		if err != nil {
			t.registryMu.Unlock()
			if t.shutdownFlag.Load() {
				return nil, ErrTransportShutdown
			}
			return nil, err
		}

		if t.shutdownFlag.Load() {
			t.registryMu.Unlock()
			_ = conn.Close()
			return nil, ErrTransportShutdown
		}

		// The leader dial always wins publication: it allocates a fresh
		// generation that supersedes whatever was current, including an
		// inbound-only generation or the previous fast-reconnect dial. The
		// superseded generation is released independently below; concurrent
		// followers were coalesced on dialDone and will borrow this one.
		old := ps.current
		pc := t.newPeerConnLocked(ps, conn)
		t.registryMu.Unlock()

		if old != nil {
			t.releaseGeneration(old, true)
		}
		return t.wrapOwned(pc), nil
	}
}

// See Transport.
func (t *GenerationTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// See IngestionAwareTransport.
func (t *GenerationTransport) IngestPacket(conn net.Conn, addr net.Addr, now time.Time, shouldClose bool) error {
	it, ok := t.inner.(IngestionAwareTransport)
	if !ok {
		return fmt.Errorf("inner transport %T does not support packet ingestion", t.inner)
	}
	return it.IngestPacket(conn, addr, now, shouldClose)
}

// See IngestionAwareTransport.
func (t *GenerationTransport) IngestStream(conn net.Conn) error {
	it, ok := t.inner.(IngestionAwareTransport)
	if !ok {
		return fmt.Errorf("inner transport %T does not support stream ingestion", t.inner)
	}
	return it.IngestStream(conn)
}

// Shutdown stops the pumps and releases every registered generation. It is
// idempotent and blocks until all pump goroutines have observed the boundary,
// after which all reads and writes deterministically fail with
// ErrTransportShutdown or ErrConnGenerationStale. The inner transport is shut
// down last so frames arriving during the transition are read and dropped
// rather than racing a closed socket.
func (t *GenerationTransport) Shutdown() error {
	t.shutdownOnce.Do(func() {
		t.shutdownFlag.Store(true)
		close(t.shutdown)
	})
	t.pumps.Wait()

	// Release all generation-owned sockets promptly so blocked senders are
	// unblocked with a deterministic error.
	t.registryMu.Lock()
	conns := make([]*peerConn, 0, len(t.peers))
	for _, ps := range t.peers {
		if ps.current != nil {
			conns = append(conns, ps.current)
			ps.current = nil
		}
	}
	t.registryMu.Unlock()
	for _, pc := range conns {
		t.releaseGeneration(pc, false)
	}

	return t.inner.Shutdown()
}

// packetPump reads packets from the inner transport and attributes each one
// to the peer generation current at arrival.
func (t *GenerationTransport) packetPump() {
	defer t.pumps.Done()
	for {
		select {
		case pkt := <-t.inner.PacketCh():
			t.acceptPacket(pkt)
		case <-t.shutdown:
			return
		}
	}
}

// streamPump reads streams from the inner transport and attributes each one
// to the peer generation current at acceptance.
func (t *GenerationTransport) streamPump() {
	defer t.pumps.Done()
	for {
		select {
		case conn := <-t.inner.StreamCh():
			t.acceptStream(conn)
		case <-t.shutdown:
			return
		}
	}
}

// acceptPacket enqueues a packet into its arrival generation, re-resolving the
// generation if it was retired during the handoff. Once the transport is
// shutting down the frame is dropped here and reaches no receive state.
func (t *GenerationTransport) acceptPacket(pkt *Packet) {
	for {
		pc, ok := t.inboundGeneration(pkt.From.String())
		if !ok {
			t.logger.Printf("[WARN] memberlist: generation transport: dropping packet from %s: transport shutting down", LogAddress(pkt.From))
			return
		}
		select {
		case pc.pktQueue <- pkt:
			return
		case <-pc.closedCh:
			// The generation retired while we waited; commit against the
			// successor or drop if the transport is winding down.
			continue
		case <-t.shutdown:
			t.logger.Printf("[WARN] memberlist: generation transport: dropping packet from %s: transport shutting down", LogAddress(pkt.From))
			return
		}
	}
}

// acceptStream enqueues an inbound stream into its arrival generation with
// the same re-resolution guarantee as acceptPacket.
func (t *GenerationTransport) acceptStream(conn net.Conn) {
	key := conn.RemoteAddr().String()
	for {
		pc, ok := t.inboundGeneration(key)
		if !ok {
			// Transport shutting down: close the socket promptly so the
			// sender receives a deterministic failure instead of a half-open
			// connection.
			t.logger.Printf("[WARN] memberlist: generation transport: dropping stream from %s: transport shutting down", key)
			_ = conn.Close()
			return
		}
		select {
		case pc.strQueue <- conn:
			return
		case <-pc.closedCh:
			continue
		case <-t.shutdown:
			t.logger.Printf("[WARN] memberlist: generation transport: dropping stream from %s: transport shutting down", key)
			_ = conn.Close()
			return
		}
	}
}

// inboundGeneration returns the generation current for inbound traffic from
// addr, creating a fresh generation when the peer is unknown or its previous
// generation has been retired and no successor has been published yet. The
// only case that yields ok == false is an in-flight transport shutdown.
func (t *GenerationTransport) inboundGeneration(addr string) (*peerConn, bool) {
	t.registryMu.Lock()
	defer t.registryMu.Unlock()

	if t.shutdownFlag.Load() {
		return nil, false
	}

	ps, ok := t.peers[addr]
	if !ok {
		ps = &peerState{addr: addr}
		t.peers[addr] = ps
	}
	if ps.current != nil {
		return ps.current, true
	}
	return t.newPeerConnLocked(ps, nil), true
}

// newPeerConnLocked allocates a numbered generation, publishes it as the
// peer's current connection, and starts its commit goroutine. The registry
// lock must be held.
func (t *GenerationTransport) newPeerConnLocked(ps *peerState, raw net.Conn) *peerConn {
	pc := &peerConn{
		peer:         ps,
		gen:          t.genCounter.Add(1),
		raw:          raw,
		closedCh:     make(chan struct{}),
		pktQueue:     make(chan *Packet, t.packetQueueDepth),
		strQueue:     make(chan net.Conn, t.streamQueueDepth),
		promoterDone: make(chan struct{}),
	}
	ps.current = pc
	go t.promote(pc)
	return pc
}

// promote is the commit boundary for a generation. Frames are forwarded to the
// transport-wide channels only while the generation remains current; when it
// is superseded the goroutine exits and the queued frames are drained away.
func (t *GenerationTransport) promote(pc *peerConn) {
	defer close(pc.promoterDone)
	for {
		select {
		case <-t.shutdown:
			return
		case <-pc.closedCh:
			return
		case pkt := <-pc.pktQueue:
			if !t.stillCurrent(pc) {
				t.logStaleDrop(pc, "packet")
				return
			}
			select {
			case t.packetCh <- pkt:
			case <-pc.closedCh:
				t.logStaleDrop(pc, "packet")
				return
			case <-t.shutdown:
				return
			}
		case conn := <-pc.strQueue:
			if !t.stillCurrent(pc) {
				t.logStaleDrop(pc, "stream")
				_ = conn.Close()
				return
			}
			select {
			case t.streamCh <- t.wrapInbound(pc, conn):
			case <-pc.closedCh:
				t.logStaleDrop(pc, "stream")
				_ = conn.Close()
				return
			case <-t.shutdown:
				_ = conn.Close()
				return
			}
		}
	}
}

// awaitCoalescedDial waits for the leader dial to publish a generation,
// applying the caller's own timeout. Followers borrow the published
// connection and cannot retire it by closing their own handle.
func (t *GenerationTransport) awaitCoalescedDial(addr string, done chan struct{}, timeout time.Duration) (net.Conn, error) {
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			return nil, ErrDialTimeout
		case <-t.shutdown:
			return nil, ErrTransportShutdown
		}
	} else {
		select {
		case <-done:
		case <-t.shutdown:
			return nil, ErrTransportShutdown
		}
	}

	t.registryMu.Lock()
	defer t.registryMu.Unlock()

	if t.shutdownFlag.Load() {
		return nil, ErrTransportShutdown
	}
	ps := t.peers[addr]
	if ps == nil {
		return nil, ErrConnGenerationStale
	}
	if ps.current == nil {
		if ps.dialErr != nil {
			return nil, ps.dialErr
		}
		return nil, ErrConnGenerationStale
	}
	if err := t.checkUsableLocked(ps.current); err != nil {
		return nil, err
	}
	if ps.current.raw == nil {
		// Leader lost to an inbound-only generation with no usable socket.
		return nil, ErrConnGenerationStale
	}
	return t.wrapBorrowed(ps.current), nil
}

// retire unpublishes a generation and releases only that generation's state:
// its queued frames are discarded, its commit goroutine is stopped, and a
// dialed socket is closed. A newer current generation is never touched.
func (t *GenerationTransport) retire(pc *peerConn) {
	t.registryMu.Lock()
	if ps := t.peers[pc.peer.addr]; ps != nil && ps.current == pc {
		ps.current = nil
	}
	t.registryMu.Unlock()

	t.releaseGeneration(pc, false)
}

// releaseGeneration stops a generation's commit goroutine, discards its
// queued frames, and releases its socket. When drain is true the socket is
// first drained in the background (bounded by DrainTimeout) so a peer still
// sending on a superseded dial connection is not cut off mid-write; otherwise
// the socket is closed immediately so blocked senders get a prompt error.
func (t *GenerationTransport) releaseGeneration(pc *peerConn, drain bool) {
	pc.shutdown()
	t.drainQueues(pc)
	if pc.raw == nil {
		return
	}
	if drain {
		t.drainConn(pc.gen, pc.raw)
	} else {
		_ = pc.raw.Close()
	}
}

// drainQueues discards every frame still buffered in a retired generation so
// none can reach the transport-wide channels afterwards.
func (t *GenerationTransport) drainQueues(pc *peerConn) {
	for {
		select {
		case <-pc.pktQueue:
		case conn := <-pc.strQueue:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}

// drainConn flushes in-flight data from a losing dial connection in the
// background and then closes its own socket, bounded by DrainTimeout so a
// peer that stays silent cannot hold the release up. The drain never touches
// any transport-wide channel, so drained data cannot reach a newer
// generation's receive state.
func (t *GenerationTransport) drainConn(gen uint64, conn net.Conn) {
	t.drainWg.Add(1)
	go func() {
		defer t.drainWg.Done()

		copied := make(chan struct{})
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			close(copied)
		}()

		timer := time.NewTimer(t.drainTimeout)
		select {
		case <-copied:
			timer.Stop()
		case <-timer.C:
			t.logger.Printf("[WARN] memberlist: generation transport: drain of generation %d timed out after %s; forcing close",
				gen, t.drainTimeout)
		case <-t.shutdown:
			timer.Stop()
		}
		_ = conn.Close()
		<-copied
	}()
}

// waitForDrain blocks until all background connection drains complete or the
// timeout elapses. It exists to make the drain-then-release ordering
// deterministically observable in tests.
func (t *GenerationTransport) waitForDrain(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		t.drainWg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// checkUsable verifies that pc may still originate reads or writes: the
// transport is up and the generation is both unclosed and still published as
// current.
func (t *GenerationTransport) checkUsable(pc *peerConn) error {
	if t.shutdownFlag.Load() {
		return ErrTransportShutdown
	}
	pc.mu.Lock()
	closed := pc.closed
	pc.mu.Unlock()
	if closed {
		return ErrConnGenerationStale
	}
	t.registryMu.Lock()
	defer t.registryMu.Unlock()
	return t.checkUsableLocked(pc)
}

// checkUsableLocked is the lock-holding half of checkUsable.
func (t *GenerationTransport) checkUsableLocked(pc *peerConn) error {
	if t.shutdownFlag.Load() {
		return ErrTransportShutdown
	}
	ps, ok := t.peers[pc.peer.addr]
	if !ok || ps.current != pc {
		return ErrConnGenerationStale
	}
	return nil
}

// stillCurrent reports whether pc is the published generation for its peer.
func (t *GenerationTransport) stillCurrent(pc *peerConn) bool {
	t.registryMu.Lock()
	defer t.registryMu.Unlock()
	ps, ok := t.peers[pc.peer.addr]
	return ok && ps.current == pc
}

func (t *GenerationTransport) logStaleDrop(pc *peerConn, kind string) {
	t.logger.Printf("[WARN] memberlist: generation transport: discarding %s from superseded generation %d (%s)",
		kind, pc.gen, pc.peer.addr)
}

// wrapOwned returns the caller-visible handle for a dial that published the
// current generation; closing it retires that generation.
func (t *GenerationTransport) wrapOwned(pc *peerConn) *generationConn {
	return &generationConn{
		Conn:      pc.raw,
		gen:       pc,
		transport: t,
		closeMode: closeModeRetire,
	}
}

// wrapBorrowed returns a handle for a coalesced follower; it shares the
// leader's socket and closing it does not affect the generation.
func (t *GenerationTransport) wrapBorrowed(pc *peerConn) *generationConn {
	return &generationConn{
		Conn:      pc.raw,
		gen:       pc,
		transport: t,
		closeMode: closeModeBorrow,
	}
}

// wrapInbound binds an accepted stream to the generation that was current at
// acceptance. Closing the handle closes only its own socket; the generation
// lifecycle is owned by the registry.
func (t *GenerationTransport) wrapInbound(pc *peerConn, conn net.Conn) *generationConn {
	return &generationConn{
		Conn:      conn,
		gen:       pc,
		transport: t,
		closeMode: closeModeSelf,
	}
}

// shutdown marks the generation closed exactly once and wakes every goroutine
// selecting on closedCh.
func (pc *peerConn) shutdown() {
	pc.once.Do(func() {
		pc.mu.Lock()
		pc.closed = true
		pc.mu.Unlock()
		close(pc.closedCh)
	})
}

// generationConn is a net.Conn handle whose reads and writes are bound to a
// specific connection generation.
type generationConn struct {
	net.Conn
	gen       *peerConn
	transport *GenerationTransport

	closeMode uint8
	closeOnce sync.Once
}

// Read fails deterministically once the generation is no longer usable.
func (c *generationConn) Read(p []byte) (int, error) {
	if err := c.transport.checkUsable(c.gen); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

// Write fails deterministically once the generation is no longer usable, so a
// stale connection can never write into the state of a newer generation.
func (c *generationConn) Write(p []byte) (int, error) {
	if err := c.transport.checkUsable(c.gen); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

// Close releases exactly the resources this handle owns: the whole generation
// for an owning dial handle, nothing for a borrowed handle, or only the
// handle's own socket for an inbound stream. It is safe to call multiple
// times.
func (c *generationConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		switch c.closeMode {
		case closeModeRetire:
			c.transport.retire(c.gen)
		case closeModeSelf:
			err = c.Conn.Close()
		case closeModeBorrow:
			// No-op: the owning dial handle releases the shared socket.
		}
	})
	return err
}

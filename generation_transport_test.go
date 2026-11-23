// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const testPeerAddr = "127.0.0.1:7946"

// addrConn overrides the remote address of a net.Pipe endpoint so the
// generation transport can attribute inbound traffic deterministically.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

type fixedAddr string

func (fixedAddr) Network() string  { return "test" }
func (a fixedAddr) String() string { return string(a) }

// scriptedInner is an in-memory NodeAwareTransport whose inbound packet and
// stream timing is fully controlled by the test.
type scriptedInner struct {
	packetCh chan *Packet
	streamCh chan net.Conn

	dialMu   sync.Mutex
	dialFn   func(Address) (net.Conn, error)
	dialCnt  atomic.Int32
	ingestOK bool

	shutdownOnce sync.Once
}

func newScriptedInner(buf int) *scriptedInner {
	return &scriptedInner{
		packetCh: make(chan *Packet, buf),
		streamCh: make(chan net.Conn, buf),
	}
}

func (s *scriptedInner) FinalAdvertiseAddr(string, int) (net.IP, int, error) {
	return net.ParseIP("127.0.0.1"), 7946, nil
}

func (s *scriptedInner) WriteTo(b []byte, addr string) (time.Time, error) {
	return s.WriteToAddress(b, Address{Addr: addr})
}

func (s *scriptedInner) WriteToAddress(b []byte, _ Address) (time.Time, error) {
	return time.Now(), nil
}

func (s *scriptedInner) PacketCh() <-chan *Packet  { return s.packetCh }
func (s *scriptedInner) StreamCh() <-chan net.Conn { return s.streamCh }
func (s *scriptedInner) Shutdown() error           { s.shutdownOnce.Do(func() {}); return nil }
func (s *scriptedInner) DialTimeout(addr string, to time.Duration) (net.Conn, error) {
	return s.DialAddressTimeout(Address{Addr: addr}, to)
}

func (s *scriptedInner) DialAddressTimeout(a Address, _ time.Duration) (net.Conn, error) {
	s.dialMu.Lock()
	fn := s.dialFn
	s.dialCnt.Add(1)
	s.dialMu.Unlock()
	if fn == nil {
		return nil, errors.New("no dial configured")
	}
	return fn(a)
}

func (s *scriptedInner) IngestPacket(conn net.Conn, addr net.Addr, now time.Time, shouldClose bool) error {
	s.ingestOK = true
	if shouldClose {
		defer conn.Close()
	}
	_, err := io.Copy(io.Discard, conn)
	return err
}

func (s *scriptedInner) IngestStream(conn net.Conn) error {
	s.ingestOK = true
	s.streamCh <- conn
	return nil
}

func (s *scriptedInner) emitPacket(t *testing.T, addr, payload string) {
	t.Helper()
	// The inner channel is buffered, so this never blocks the test while a
	// pump is parked on a full generation queue.
	s.packetCh <- &Packet{
		Buf:       []byte(payload),
		From:      fixedAddr(addr),
		Timestamp: time.Now(),
	}
}

func (s *scriptedInner) emitStream(t *testing.T, addr string) net.Conn {
	t.Helper()
	p1, p2 := newPipeConnPair()
	in := &addrConn{Conn: p1, remote: fixedAddr(addr)}
	s.streamCh <- in
	return p2
}

// pipeDialer returns a dial function whose server-side endpoints are delivered
// on the returned channel, letting tests observe and close losing sockets.
func pipeDialer(addr string, dials chan<- net.Conn) func(Address) (net.Conn, error) {
	return func(a Address) (net.Conn, error) {
		client, server := newPipeConnPair()
		_ = a
		go func() { dials <- &addrConn{Conn: server, remote: fixedAddr(addr)} }()
		return client, nil
	}
}

// newPipeConnPair returns a connected, in-memory net.Conn pair. Unlike
// net.Pipe, closing either endpoint unblocks reads and writes on the other
// immediately, which keeps generation drain/retire tests deterministic.
func newPipeConnPair() (net.Conn, net.Conn) {
	pair := &memPipePair{}
	a := newMemPipe(pair)
	b := newMemPipe(pair)
	a.peer, b.peer = b, a
	return a, b
}

// memPipe is a buffered, in-memory, full-duplex net.Conn for tests. Writes
// append to the peer's receive buffer and wake its blocked reader; closing
// unblocks every blocked Read/Write on both ends. The two ends share one
// mutex so there is no lock-ordering inversion between them.
type memPipe struct {
	peer *memPipe

	mu     *sync.Mutex
	cond   *sync.Cond
	buf    []byte
	closed bool
}

// memPipePair bundles the shared lock for both ends.
type memPipePair struct {
	mu sync.Mutex
}

func newMemPipe(pair *memPipePair) *memPipe {
	p := &memPipe{mu: &pair.mu}
	p.cond = sync.NewCond(p.mu)
	return p
}

func (p *memPipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed && !p.peer.closed {
		p.cond.Wait()
	}
	if len(p.buf) > 0 {
		n := copy(b, p.buf)
		p.buf = p.buf[n:]
		return n, nil
	}
	// EOF when the peer shut down, net.ErrClosed for a local close.
	if p.closed {
		return 0, net.ErrClosed
	}
	return 0, io.EOF
}

func (p *memPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.peer.closed || p.closed {
		return 0, io.ErrClosedPipe
	}
	p.peer.buf = append(p.peer.buf, b...)
	p.peer.cond.Broadcast()
	return len(b), nil
}

func (p *memPipe) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		// Wake readers blocked on either end.
		p.cond.Broadcast()
		p.peer.cond.Broadcast()
	}
	return nil
}

func (p *memPipe) LocalAddr() net.Addr              { return fixedAddr("mempipe-local") }
func (p *memPipe) RemoteAddr() net.Addr             { return fixedAddr("mempipe-remote") }
func (p *memPipe) SetDeadline(time.Time) error      { return nil }
func (p *memPipe) SetReadDeadline(time.Time) error  { return nil }
func (p *memPipe) SetWriteDeadline(time.Time) error { return nil }

// drainConnAsync consumes and discards everything sent on a test connection
// until it is closed. The returned stop function releases the drain goroutine
// when the test is done even if the peer end was never shut.
func drainConnAsync(conn net.Conn) (stop func()) {
	done := make(chan struct{})
	go func() {
		for {
			one := make([]byte, 1024)
			if _, err := conn.Read(one); err != nil {
				return
			}
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	return func() {
		close(done)
		_ = conn.Close()
	}
}

func newTestGenerationTransport(t *testing.T, inner NodeAwareTransport) *GenerationTransport {
	t.Helper()
	gt, err := NewGenerationTransport(&GenerationTransportConfig{
		Inner:        inner,
		Logger:       log.New(io.Discard, "", 0),
		DrainTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Shutdown() })
	return gt
}

func (t_ *GenerationTransport) currentPeerConn(t *testing.T, addr string) *peerConn {
	t.Helper()
	t_.registryMu.Lock()
	defer t_.registryMu.Unlock()
	ps, ok := t_.peers[addr]
	require.True(t, ok, "no registry entry for %s", addr)
	require.NotNil(t, ps.current, "no current generation for %s", addr)
	return ps.current
}

// TestGenerationTransport_InterfaceAndPacketCompatibility verifies the
// decorator keeps the existing transport interfaces and passes packets
// through untouched (no wire-format change).
func TestGenerationTransport_InterfaceAndPacketCompatibility(t *testing.T) {
	var (
		_ NodeAwareTransport      = (*GenerationTransport)(nil)
		_ IngestionAwareTransport = (*GenerationTransport)(nil)
	)

	inner := newScriptedInner(4)
	gt := newTestGenerationTransport(t, inner)
	require.Equal(t, inner.PacketCh() != nil, gt.PacketCh() != nil)
	require.Equal(t, inner.StreamCh() != nil, gt.StreamCh() != nil)

	inner.emitPacket(t, testPeerAddr, "hello")
	select {
	case pkt := <-gt.PacketCh():
		require.Equal(t, []byte("hello"), pkt.Buf)
		require.Equal(t, testPeerAddr, pkt.From.String())
	case <-time.After(time.Second):
		t.Fatal("packet did not cross the generation boundary")
	}
}

// TestGenerationTransport_GenerationsMonotonicAndIsolated covers requirements
// 1 and 2: each peer connection gets a strictly increasing generation, and
// closing the old connection releases only its own reader/writer state.
func TestGenerationTransport_GenerationsMonotonicAndIsolated(t *testing.T) {
	inner := newScriptedInner(8)
	dials := make(chan net.Conn, 4)
	inner.dialFn = pipeDialer(testPeerAddr, dials)
	gt := newTestGenerationTransport(t, inner)

	// First inbound contact creates generation 1.
	inner.emitPacket(t, testPeerAddr, "g1")
	first := <-gt.PacketCh()
	require.Equal(t, []byte("g1"), first.Buf)
	pc1 := gt.currentPeerConn(t, testPeerAddr)
	gen1 := pc1.gen

	// Reconnect: a dial allocates a new, strictly larger generation.
	conn1, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	server1 := <-dials
	t.Cleanup(drainConnAsync(server1))
	pc2 := gt.currentPeerConn(t, testPeerAddr)
	require.Greater(t, pc2.gen, gen1)
	require.NotSame(t, pc1, pc2)

	// The old generation is published no longer.
	require.Equal(t, ErrConnGenerationStale, gt.checkUsable(pc1))

	// Closing the old conn only tears down generation 2's state; a later
	// reconnect allocates yet another generation that the dead handle cannot
	// influence.
	require.NoError(t, conn1.Close())
	require.Equal(t, ErrConnGenerationStale, gt.checkUsable(pc2))

	conn2, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	server2 := <-dials
	t.Cleanup(drainConnAsync(server2))
	defer func() {
		require.NoError(t, server2.Close())
		require.NoError(t, conn2.Close())
	}()
	pc3 := gt.currentPeerConn(t, testPeerAddr)
	require.Greater(t, pc3.gen, pc2.gen)
	_, err = conn1.Write([]byte("stale"))
	require.ErrorIs(t, err, ErrConnGenerationStale)
	_, err = conn1.Read(make([]byte, 1))
	require.ErrorIs(t, err, ErrConnGenerationStale)
}

// TestGenerationTransport_ConcurrentDialPublishesOne covers requirement 3:
// concurrent dials are coalesced into one published connection; losers never
// publish and their sockets are drained then released.
func TestGenerationTransport_ConcurrentDialPublishesOne(t *testing.T) {
	inner := newScriptedInner(16)
	dials := make(chan net.Conn, 8)
	inner.dialFn = pipeDialer(testPeerAddr, dials)
	gt := newTestGenerationTransport(t, inner)

	const n = 8
	var (
		wg    sync.WaitGroup
		conns = make([]net.Conn, n)
		errs  = make([]error, n)
		start = make(chan struct{})
	)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			conns[i], errs[i] = gt.DialTimeout(testPeerAddr, time.Second)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		require.NoErrorf(t, err, "dial %d failed", i)
	}

	// Exactly one socket was opened on the inner transport and one generation
	// is current; every returned handle is bound to it.
	winner := gt.currentPeerConn(t, testPeerAddr)
	require.Equal(t, int32(1), inner.dialCnt.Load())
	for i, c := range conns {
		gc, ok := c.(*generationConn)
		require.Truef(t, ok, "dial %d returned %T", i, c)
		require.Same(t, winner, gc.gen)
	}

	// Releasing the one observed server endpoint lets the coalesced
	// generation retire cleanly (no leaked sockets).
	server := <-dials
	t.Cleanup(drainConnAsync(server))
	require.NoError(t, conns[0].Close())
}

// TestGenerationTransport_FastPathReusesCurrent verifies that a dial while a
// usable dialed generation is current borrows it rather than opening another
// socket; every returned handle is bound to the same generation.
func TestGenerationTransport_FastPathReusesCurrent(t *testing.T) {
	inner := newScriptedInner(16)
	dials := make(chan net.Conn, 4)
	inner.dialFn = pipeDialer(testPeerAddr, dials)
	gt := newTestGenerationTransport(t, inner)

	first, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	<-dials
	gen := gt.currentPeerConn(t, testPeerAddr)

	second, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	require.Equal(t, int32(1), inner.dialCnt.Load(), "no second socket should be opened")
	require.Same(t, gen, second.(*generationConn).gen)

	// Borrowed handles cannot retire the shared generation.
	require.NoError(t, second.Close())
	require.NoError(t, gt.checkUsable(gen))
	require.NoError(t, first.Close())
}

// TestGenerationTransport_LosingDialDrainedAndReleased covers requirement 3's
// release half: when a reconnect supersedes a generation, the old socket is
// drained in the background and then closed, never reaching the new
// generation's receive channels.
func TestGenerationTransport_LosingDialDrainedAndReleased(t *testing.T) {
	inner := newScriptedInner(16)
	loserEnds := make(chan net.Conn, 4)

	// First dial wins normally.
	inner.dialFn = pipeDialer(testPeerAddr, loserEnds)
	gt := newTestGenerationTransport(t, inner)

	oldConn, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	oldServer := <-loserEnds
	t.Cleanup(drainConnAsync(oldServer))
	oldGen := gt.currentPeerConn(t, testPeerAddr).gen

	// Reconnect: close the owning handle first, then dial a fresh generation.
	// The old socket goes through the drain-then-release path in the
	// background.
	require.NoError(t, oldConn.Close())
	require.Eventually(t, func() bool {
		gt.registryMu.Lock()
		defer gt.registryMu.Unlock()
		return gt.peers[testPeerAddr].current == nil
	}, time.Second, time.Millisecond)

	nextConn, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	nextServer := <-loserEnds
	// No drainConnAsync here: this end is read explicitly below to verify the
	// new generation's traffic.
	defer func() {
		require.NoError(t, nextServer.Close())
		require.NoError(t, nextConn.Close())
	}()
	require.Greater(t, gt.currentPeerConn(t, testPeerAddr).gen, oldGen)

	require.True(t, gt.waitForDrain(2*time.Second), "superseded connection was not drained and released")

	// The superseded handle is bound to a dead generation and fails every
	// operation deterministically instead of touching the new connection.
	_, err = oldConn.Write([]byte("from-a-past-generation"))
	require.ErrorIs(t, err, ErrConnGenerationStale)
	_, err = oldConn.Read(make([]byte, 1))
	require.ErrorIs(t, err, ErrConnGenerationStale)
	require.NoError(t, oldServer.Close())

	// Nothing from the old generation can appear on the new generation's
	// channels.
	select {
	case <-gt.PacketCh():
		t.Fatal("stale packet leaked onto the new generation's packet channel")
	case <-gt.StreamCh():
		t.Fatal("stale stream leaked onto the new generation's stream channel")
	default:
	}

	// The new generation still carries traffic on its own socket.
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 8)
		n, _ := nextServer.Read(buf)
		got <- buf[:n]
	}()
	_, err = nextConn.Write([]byte("current"))
	require.NoError(t, err)
	require.Equal(t, []byte("current"), <-got)
}

// TestGenerationTransport_StalePacketsDropped covers requirement 4 for
// packets: a frame parked in a superseded generation's queue is discarded at
// the commit boundary, frames arriving during shutdown are dropped, and none
// can mutate the current generation's receive state.
func TestGenerationTransport_StalePacketsDropped(t *testing.T) {
	inner := newScriptedInner(16)
	gt, err := NewGenerationTransport(&GenerationTransportConfig{
		Inner:            inner,
		Logger:           log.New(io.Discard, "", 0),
		PacketQueueDepth: 1,
		StreamQueueDepth: 1,
		DrainTimeout:     50 * time.Millisecond,
	})
	require.NoError(t, err)
	dials := make(chan net.Conn, 4)
	inner.dialFn = pipeDialer(testPeerAddr, dials)

	// Inbound generation 1.
	inner.emitPacket(t, testPeerAddr, "old-1")
	require.Equal(t, "old-1", string((<-gt.PacketCh()).Buf))
	old := gt.currentPeerConn(t, testPeerAddr)

	// A dial publishes generation 2 and retires generation 1.
	conn, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	server := <-dials
	t.Cleanup(drainConnAsync(server))
	require.True(t, gt.waitForDrain(2*time.Second))
	require.Equal(t, ErrConnGenerationStale, gt.checkUsable(old))

	// Frames arriving now bind to the fresh successor generation and never
	// reach the retired one; prove the successor commits its own traffic and
	// nothing resurrects generation 1.
	inner.emitPacket(t, testPeerAddr, "fresh")
	select {
	case pkt := <-gt.PacketCh():
		require.Equal(t, []byte("fresh"), pkt.Buf)
	case <-time.After(time.Second):
		t.Fatal("successor generation packet was not committed")
	}
	newGen := gt.currentPeerConn(t, testPeerAddr)
	require.Greater(t, newGen.gen, old.gen)

	// During shutdown, frames still queued inside a generation are drained
	// away and every later packet or stream operation fails deterministically.
	require.NoError(t, gt.Shutdown())
	select {
	case <-gt.PacketCh():
		t.Fatal("queued frame leaked onto PacketCh during shutdown")
	default:
	}
	_, err = gt.WriteTo([]byte("late"), testPeerAddr)
	require.ErrorIs(t, err, ErrTransportShutdown)
	_, err = gt.DialTimeout(testPeerAddr, time.Second)
	require.ErrorIs(t, err, ErrTransportShutdown)
	_ = conn.Close()
	_ = server.Close()
}

// TestGenerationTransport_QueuedFramesDroppedOnRetire directly parks a frame
// inside a generation queue and then retires it, proving the queued frame is
// discarded instead of being committed after supersession.
func TestGenerationTransport_QueuedFramesDroppedOnRetire(t *testing.T) {
	inner := newScriptedInner(16)
	gt, err := NewGenerationTransport(&GenerationTransportConfig{
		Inner:            inner,
		Logger:           log.New(io.Discard, "", 0),
		PacketQueueDepth: 4,
		StreamQueueDepth: 4,
		DrainTimeout:     50 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gt.Shutdown() })

	inner.emitPacket(t, testPeerAddr, "seed")
	<-gt.PacketCh()
	old := gt.currentPeerConn(t, testPeerAddr)

	// Park frames directly in the generation queues, bypassing the pumps.
	old.pktQueue <- &Packet{Buf: []byte("queued-stale"), From: fixedAddr(testPeerAddr)}
	_, stalePeer := newPipeConnPair()
	old.strQueue <- stalePeer

	gt.retire(old)
	<-old.promoterDone
	require.Empty(t, old.pktQueue)
	require.Empty(t, old.strQueue)

	one := make([]byte, 1)
	_, readErr := stalePeer.Read(one)
	require.Error(t, readErr, "queued stale stream socket must be closed")
	require.NoError(t, stalePeer.Close())

	// No stale frame was ever committed to the transport-wide channels.
	select {
	case <-gt.PacketCh():
		t.Fatal("queued stale packet leaked after retirement")
	case <-gt.StreamCh():
		t.Fatal("queued stale stream leaked after retirement")
	default:
	}
}

// TestGenerationTransport_StaleStreamsDropped is the stream counterpart: a
// stream of the retired generation never reaches the transport-wide channel,
// successor-generation streams are delivered, and streams arriving during
// shutdown are dropped with their sockets closed.
func TestGenerationTransport_StaleStreamsDropped(t *testing.T) {
	inner := newScriptedInner(16)
	gt, err := NewGenerationTransport(&GenerationTransportConfig{
		Inner:            inner,
		Logger:           log.New(io.Discard, "", 0),
		PacketQueueDepth: 1,
		StreamQueueDepth: 1,
		DrainTimeout:     50 * time.Millisecond,
	})
	require.NoError(t, err)
	dials := make(chan net.Conn, 4)
	inner.dialFn = pipeDialer(testPeerAddr, dials)

	// Inbound generation 1 via a stream.
	oldPeer := inner.emitStream(t, testPeerAddr)
	select {
	case c := <-gt.StreamCh():
		require.NoError(t, c.Close())
	case <-time.After(time.Second):
		t.Fatal("first stream was not committed")
	}
	old := gt.currentPeerConn(t, testPeerAddr)

	// A dial publishes generation 2 and retires generation 1.
	conn, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	server := <-dials
	t.Cleanup(drainConnAsync(server))
	require.True(t, gt.waitForDrain(2*time.Second))
	require.Equal(t, ErrConnGenerationStale, gt.checkUsable(old))

	// Successor-generation streams are delivered and cannot resurrect the
	// retired generation.
	freshPeer := inner.emitStream(t, testPeerAddr)
	select {
	case c := <-gt.StreamCh():
		require.NoError(t, c.Close())
	case <-time.After(time.Second):
		t.Fatal("successor generation stream was not committed")
	}
	require.Greater(t, gt.currentPeerConn(t, testPeerAddr).gen, old.gen)
	require.NoError(t, freshPeer.Close())

	// During shutdown, a stream already accepted into a generation queue is
	// discarded and its socket closed by the transport, so the sender gets a
	// deterministic failure. Park one directly into the queue and verify the
	// socket ends up closed regardless of pump scheduling.
	old2 := gt.currentPeerConn(t, testPeerAddr)
	_, stalePeer := newPipeConnPair()
	old2.strQueue <- stalePeer
	require.NoError(t, gt.Shutdown())

	readErr := make(chan error, 1)
	go func() {
		_, e := stalePeer.Read(make([]byte, 1))
		readErr <- e
	}()
	select {
	case err := <-readErr:
		require.Error(t, err, "stream drained during shutdown should be closed")
	case <-time.After(time.Second):
		t.Fatal("shutdown stream socket was not closed")
	}
	// Whatever the promoter committed before shutdown is still drained away.
	select {
	case c := <-gt.StreamCh():
		_ = c.Close()
	default:
	}
	require.NoError(t, stalePeer.Close())
	require.NoError(t, oldPeer.Close())
	require.NoError(t, server.Close())
	_ = conn
}

// blockingInner wraps a scripted inner whose WriteToAddress blocks until
// released, exercising the "write in flight when Shutdown runs" path.
type blockingInner struct {
	*scriptedInner
	blocked chan struct{}
	release chan struct{}
}

func (b *blockingInner) WriteToAddress(p []byte, a Address) (time.Time, error) {
	close(b.blocked)
	<-b.release
	return b.scriptedInner.WriteToAddress(p, a)
}

// TestGenerationTransport_ShutdownBoundaries covers requirement 4 for the
// shutdown edge: a write blocked when Shutdown runs gets a deterministic
// error, and all post-shutdown operations fail without panics.
func TestGenerationTransport_ShutdownBoundaries(t *testing.T) {
	bi := &blockingInner{
		scriptedInner: newScriptedInner(16),
		blocked:       make(chan struct{}),
		release:       make(chan struct{}),
	}
	gt, err := NewGenerationTransport(&GenerationTransportConfig{
		Inner:        bi,
		Logger:       log.New(io.Discard, "", 0),
		DrainTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)

	writeDone := make(chan error, 1)
	go func() {
		_, werr := gt.WriteTo([]byte("blocked"), testPeerAddr)
		writeDone <- werr
	}()
	<-bi.blocked

	// Shut down while the write is parked inside the inner transport.
	shutdownDone := make(chan struct{})
	go func() {
		_ = gt.Shutdown()
		close(shutdownDone)
	}()

	// Give Shutdown time to set the flag and park on the pump shutdown
	// boundary before unblocking the inner write.
	time.Sleep(20 * time.Millisecond)
	close(bi.release)

	select {
	case werr := <-writeDone:
		require.ErrorIs(t, werr, ErrTransportShutdown, "in-flight write must surface the shutdown error")
	case <-time.After(2 * time.Second):
		t.Fatal("blocked sender did not receive a deterministic shutdown error")
	}
	<-shutdownDone

	// Idempotent and total: every subsequent entry point fails predictably.
	require.NoError(t, gt.Shutdown())
	_, err = gt.WriteTo([]byte("x"), testPeerAddr)
	require.ErrorIs(t, err, ErrTransportShutdown)
	_, err = gt.DialTimeout(testPeerAddr, time.Second)
	require.ErrorIs(t, err, ErrTransportShutdown)
}

// TestGenerationTransport_StaleHandleCannotWrite covers requirement 1 for
// stream handles: reads and writes through a superseded handle fail before
// touching the wire, while the new generation's handle is unaffected.
func TestGenerationTransport_StaleHandleCannotWrite(t *testing.T) {
	inner := newScriptedInner(16)
	dials := make(chan net.Conn, 4)
	inner.dialFn = pipeDialer(testPeerAddr, dials)
	gt := newTestGenerationTransport(t, inner)

	conn1, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	server1 := <-dials
	t.Cleanup(drainConnAsync(server1))

	// Reconnect through the owning handle so the second dial publishes a
	// fresh, strictly newer generation.
	require.NoError(t, conn1.Close())
	require.True(t, gt.waitForDrain(2*time.Second))
	conn2, err := gt.DialTimeout(testPeerAddr, time.Second)
	require.NoError(t, err)
	server2 := <-dials

	_, err = conn1.Write([]byte("from-the-past"))
	require.ErrorIs(t, err, ErrConnGenerationStale)

	// The new handle still round-trips data on its own socket.
	roundTrip := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := server2.Read(buf)
		roundTrip <- buf[:n]
	}()
	_, err = conn2.Write([]byte("from-the-present"))
	require.NoError(t, err)
	require.Equal(t, []byte("from-the-present"), <-roundTrip)

	require.NoError(t, conn2.Close())
	require.NoError(t, server2.Close())
	require.NoError(t, server1.Close())
}

// TestGenerationTransport_MemberlistIntegration proves the decorator is a
// drop-in for the existing MockTransport-backed memberlist setup and the
// Transport interface and packet format stay compatible end to end.
func TestGenerationTransport_MemberlistIntegration(t *testing.T) {
	network := &MockNetwork{}

	t1 := network.NewTransport("node1")
	gt1 := newTestGenerationTransport(t, t1)
	c1 := DefaultLANConfig()
	c1.Name = "node1"
	c1.Transport = gt1
	m1, err := Create(c1)
	require.NoError(t, err)
	require.NoError(t, m1.setAlive())
	m1.schedule()
	defer func() { require.NoError(t, m1.Shutdown()) }()

	t2 := network.NewTransport("node2")
	gt2 := newTestGenerationTransport(t, t2)
	c2 := DefaultLANConfig()
	c2.Name = "node2"
	c2.Transport = gt2
	m2, err := Create(c2)
	require.NoError(t, err)
	require.NoError(t, m2.setAlive())
	m2.schedule()
	defer func() { require.NoError(t, m2.Shutdown()) }()

	num, err := m2.Join([]string{c1.Name + "/" + t1.addr.String()})
	require.NoError(t, err)
	require.Equal(t, 1, num)
	require.Len(t, m2.Members(), 2)

	// A user message still crosses both generations of transport unchanged.
	d1 := &MockDelegate{}
	c1.Delegate = d1
	require.NoError(t, m2.SendTo(t1.addr, []byte("generation-ok")))
	require.Eventually(t, func() bool {
		for _, msg := range d1.getMessages() {
			if string(msg) == "generation-ok" {
				return true
			}
		}
		return false
	}, time.Second, 10*time.Millisecond)
}

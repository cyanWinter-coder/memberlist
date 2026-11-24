// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	metrics "github.com/hashicorp/go-metrics"
	sockaddr "github.com/hashicorp/go-sockaddr"
)

const (
	// udpPacketBufSize is used to buffer incoming packets during read
	// operations.
	udpPacketBufSize = 65536

	// udpRecvBufSize is a large buffer size that we attempt to set UDP
	// sockets to in order to handle a large volume of messages.
	udpRecvBufSize = 2 * 1024 * 1024

	// defaultMaxUDPPacketSize is the conservative payload limit used when a
	// transport does not configure one. It matches Memberlist's default
	// UDPBufferSize.
	defaultMaxUDPPacketSize = 1400

	// defaultTCPFallbackTimeout bounds dialing and writing an oversized
	// packet over TCP when the caller's context does not provide a deadline.
	defaultTCPFallbackTimeout = 10 * time.Second

	// tcpFallbackHeaderSize is the size of the framed header used to carry
	// packet-shaped payloads over a reliable stream.
	tcpFallbackHeaderSize = 12

	// packetSequenceHeaderSize carries a magic prefix and uint32 sequence.
	packetSequenceHeaderSize = 12
)

var (
	// ErrUDPPacketTooLarge is returned when a packet exceeds the configured
	// UDP limit and TCP fallback is disabled.
	ErrUDPPacketTooLarge = errors.New("memberlist: UDP packet exceeds configured maximum size")

	// ErrSendBufferFull is returned by a non-blocking enqueue when the
	// transport's bounded send buffer has no capacity.
	ErrSendBufferFull = errors.New("memberlist: transport send buffer is full")

	// ErrTransportClosed is returned by writes attempted after Shutdown.
	ErrTransportClosed = errors.New("memberlist: transport is closed")

	// tcpFallbackMagic prefixes an internal framed packet sent over TCP. The
	// first byte is outside memberlist's normal messageType range, allowing
	// the listener to distinguish fallback packets from stream protocols.
	tcpFallbackMagic = [4]byte{'M', 'L', 'F', 'B'}

	// packetSequenceMagic prefixes an opt-in sequenced datagram.
	packetSequenceMagic = [4]byte{'M', 'L', 'S', 'Q'}
)

// NetTransportConfig is used to configure a net transport.
type NetTransportConfig struct {
	// BindAddrs is a list of addresses to bind to for both TCP and UDP
	// communications.
	BindAddrs []string

	// BindPort is the port to listen on, for each address above.
	BindPort int

	// Logger is a logger for operator messages.
	Logger *log.Logger

	// MetricLabels is a map of optional labels to apply to all metrics
	// emitted by this transport.
	MetricLabels []metrics.Label

	// MaxUDPPacketSize is the maximum payload size placed in one UDP
	// datagram. Payloads larger than this are sent over TCP when
	// TCPFallback is enabled. A zero value uses 1400.
	MaxUDPPacketSize int

	// MaxPacketSize, MaxUDPSize, PacketBufferSize and UDPBufferSize are
	// compatibility aliases for MaxUDPPacketSize. The first positive value
	// among the aliases is used.
	MaxPacketSize    int
	MaxUDPSize       int
	PacketBufferSize int
	UDPBufferSize    int

	// TCPFallback enables automatic reliable-stream delivery for packets
	// larger than the configured UDP limit.
	TCPFallback bool

	// EnableTCPFallback and FallbackToTCP are compatibility aliases for
	// TCPFallback.
	EnableTCPFallback bool
	FallbackToTCP     bool

	// TCPFallbackTimeout bounds dial and write operations for fallback
	// deliveries. Zero uses 10 seconds.
	TCPFallbackTimeout time.Duration

	// EnablePacketSequence adds a small sequence header to UDP datagrams and
	// drops duplicate or out-of-order datagrams from each peer. It is opt-in
	// to preserve the baseline wire format.
	EnablePacketSequence bool

	// PacketSequence and SequencePackets are compatibility aliases.
	PacketSequence  bool
	SequencePackets bool
}

// NetTransport is a Transport implementation that uses connectionless UDP for
// packet operations, and ad-hoc TCP connections for stream operations.
type NetTransport struct {
	config       *NetTransportConfig
	packetCh     chan *Packet
	streamCh     chan net.Conn
	logger       *log.Logger
	wg           sync.WaitGroup
	tcpListeners []*net.TCPListener
	udpListeners []*net.UDPConn
	shutdown     atomic.Int32

	// closeCh is closed once when Shutdown begins. Selecting on it prevents
	// listener and handoff goroutines from blocking forever on channels.
	closeCh   chan struct{}
	closeOnce sync.Once

	// connWg tracks per-connection goroutines spawned by tcpListen. activeConns
	// lets Shutdown unblock reads from connections that callers have not taken
	// ownership of yet.
	connWg      sync.WaitGroup
	connMu      sync.Mutex
	activeConns map[net.Conn]struct{}

	seqMu   sync.Mutex
	sendSeq map[string]uint32
	recvSeq *SequenceFilter

	metricLabels []metrics.Label
}

var _ NodeAwareTransport = (*NetTransport)(nil)

// NewNetTransport returns a net transport with the given configuration. On
// success all the network listeners will be created and listening.
func NewNetTransport(config *NetTransportConfig) (*NetTransport, error) {
	// If we reject the empty list outright we can assume that there's at
	// least one listener of each type later during operation.
	if len(config.BindAddrs) == 0 {
		return nil, fmt.Errorf("at least one bind address is required")
	}

	// Build out the new transport.
	var ok bool
	logger := config.Logger
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	t := NetTransport{
		config:       config,
		packetCh:     make(chan *Packet),
		streamCh:     make(chan net.Conn),
		logger:       logger,
		closeCh:      make(chan struct{}),
		activeConns:  make(map[net.Conn]struct{}),
		sendSeq:      make(map[string]uint32),
		recvSeq:      NewSequenceFilter(),
		metricLabels: config.MetricLabels,
	}

	// Clean up listeners if there's an error.
	defer func() {
		if !ok {
			_ = t.Shutdown()
		}
	}()

	// Build all the TCP and UDP listeners.
	port := config.BindPort
	for _, addr := range config.BindAddrs {
		ip := net.ParseIP(addr)

		tcpAddr := &net.TCPAddr{IP: ip, Port: port}
		tcpLn, err := net.ListenTCP("tcp", tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to start TCP listener on %q port %d: %v", addr, port, err)
		}
		t.tcpListeners = append(t.tcpListeners, tcpLn)

		// If the config port given was zero, use the first TCP listener
		// to pick an available port and then apply that to everything
		// else.
		if port == 0 {
			port = tcpLn.Addr().(*net.TCPAddr).Port
		}

		udpAddr := &net.UDPAddr{IP: ip, Port: port}
		udpLn, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to start UDP listener on %q port %d: %v", addr, port, err)
		}
		if err := setUDPRecvBuf(udpLn); err != nil {
			return nil, fmt.Errorf("failed to resize UDP buffer: %v", err)
		}
		t.udpListeners = append(t.udpListeners, udpLn)
	}

	// Fire them up now that we've been able to create them all.
	for i := 0; i < len(config.BindAddrs); i++ {
		t.wg.Add(2)
		go t.tcpListen(t.tcpListeners[i])
		go t.udpListen(t.udpListeners[i])
	}

	ok = true
	return &t, nil
}

// GetAutoBindPort returns the bind port that was automatically given by the
// kernel, if a bind port of 0 was given.
func (t *NetTransport) GetAutoBindPort() int {
	// We made sure there's at least one TCP listener, and that one's
	// port was applied to all the others for the dynamic bind case.
	return t.tcpListeners[0].Addr().(*net.TCPAddr).Port
}

// See Transport.
func (t *NetTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	var advertiseAddr net.IP
	var advertisePort int
	if ip != "" {
		// If they've supplied an address, use that.
		advertiseAddr = net.ParseIP(ip)
		if advertiseAddr == nil {
			return nil, 0, fmt.Errorf("failed to parse advertise address %q", ip)
		}

		// Ensure IPv4 conversion if necessary.
		if ip4 := advertiseAddr.To4(); ip4 != nil {
			advertiseAddr = ip4
		}
		advertisePort = port
	} else {
		if t.config.BindAddrs[0] == "0.0.0.0" {
			// Otherwise, if we're not bound to a specific IP, let's
			// use a suitable private IP address.
			var err error
			ip, err = sockaddr.GetPrivateIP()
			if err != nil {
				return nil, 0, fmt.Errorf("failed to get interface addresses: %v", err)
			}
			if ip == "" {
				return nil, 0, fmt.Errorf("no private IP address found, and explicit IP not provided")
			}

			advertiseAddr = net.ParseIP(ip)
			if advertiseAddr == nil {
				return nil, 0, fmt.Errorf("failed to parse advertise address: %q", ip)
			}
		} else {
			// Use the IP that we're bound to, based on the first
			// TCP listener, which we already ensure is there.
			advertiseAddr = t.tcpListeners[0].Addr().(*net.TCPAddr).IP
		}

		// Use the port we are bound to.
		advertisePort = t.GetAutoBindPort()
	}

	return advertiseAddr, advertisePort, nil
}

// maxUDPPacketSize returns the configured UDP payload limit, applying
// compatibility aliases and the safe default.
func (t *NetTransport) maxUDPPacketSize() int {
	c := t.config
	if c == nil {
		return defaultMaxUDPPacketSize
	}
	for _, n := range []int{
		c.MaxUDPPacketSize,
		c.MaxPacketSize,
		c.MaxUDPSize,
		c.PacketBufferSize,
		c.UDPBufferSize,
	} {
		if n > 0 {
			return n
		}
	}
	return defaultMaxUDPPacketSize
}

// tcpFallbackEnabled reports whether oversized packets may use TCP.
func (t *NetTransport) tcpFallbackEnabled() bool {
	c := t.config
	return c != nil && (c.TCPFallback || c.EnableTCPFallback || c.FallbackToTCP)
}

func (t *NetTransport) tcpFallbackTimeout() time.Duration {
	if t.config != nil && t.config.TCPFallbackTimeout > 0 {
		return t.config.TCPFallbackTimeout
	}
	return defaultTCPFallbackTimeout
}

func (t *NetTransport) packetSequenceEnabled() bool {
	c := t.config
	return c != nil && (c.EnablePacketSequence || c.PacketSequence || c.SequencePackets)
}

func (t *NetTransport) nextPacketSequence(addr string) uint32 {
	t.seqMu.Lock()
	defer t.seqMu.Unlock()
	seq := t.sendSeq[addr]
	t.sendSeq[addr] = seq + 1
	return seq
}

func encodePacketSequence(seq uint32) []byte {
	header := make([]byte, packetSequenceHeaderSize)
	copy(header[0:4], packetSequenceMagic[:])
	header[4] = 1 // version
	binary.BigEndian.PutUint32(header[8:12], seq)
	return header
}

// acceptSequencedPacket strips and validates an optional sequence header. It
// returns ok=false for a duplicate or out-of-order datagram that must be
// discarded. Non-sequenced packets are passed through when sequencing is
// enabled to retain interoperability with unmarked local probes.
func (t *NetTransport) acceptSequencedPacket(buf []byte, from net.Addr) ([]byte, bool) {
	if !t.packetSequenceEnabled() || len(buf) < packetSequenceHeaderSize ||
		!bytes.Equal(buf[0:4], packetSequenceMagic[:]) {
		return buf, true
	}

	seq := binary.BigEndian.Uint32(buf[8:12])
	peer := LogAddress(from)
	if err := t.recvSeq.Check(peer, seq); err != nil {
		metrics.IncrCounterWithLabels([]string{"memberlist", "udp", "sequence_dropped"}, 1, t.metricLabels)
		t.logger.Printf("[DEBUG] memberlist: dropping packet from %s: %v", peer, err)
		return nil, false
	}
	return buf[packetSequenceHeaderSize:], true
}

func (t *NetTransport) isClosed() bool {
	return t.shutdown.Load() == 1
}

// See Transport.
func (t *NetTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	a := Address{Addr: addr, Name: ""}
	return t.WriteToAddress(b, a)
}

// See NodeAwareTransport.
func (t *NetTransport) WriteToAddress(b []byte, a Address) (time.Time, error) {
	if t.isClosed() {
		return time.Time{}, ErrTransportClosed
	}

	addr := a.Addr
	payload := b
	if t.packetSequenceEnabled() {
		header := encodePacketSequence(t.nextPacketSequence(addr))
		payload = make([]byte, 0, len(header)+len(b))
		payload = append(payload, header...)
		payload = append(payload, b...)
	}

	if len(payload) > t.maxUDPPacketSize() {
		if !t.tcpFallbackEnabled() {
			return time.Time{}, ErrUDPPacketTooLarge
		}
		if err := t.writePacketViaTCP(payload, addr); err != nil {
			return time.Time{}, err
		}
		return time.Now(), nil
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return time.Time{}, err
	}

	// We made sure there's at least one UDP listener, so just use the
	// packet sending interface on the first one. Take the time after the
	// write call comes back, which will underestimate the time a little,
	// but help account for any delays before the write occurs.
	_, err = t.udpListeners[0].WriteTo(payload, udpAddr)
	if err != nil {
		return time.Time{}, err
	}
	if t.isClosed() {
		return time.Time{}, ErrTransportClosed
	}
	return time.Now(), nil
}

// writePacketViaTCP sends one packet-shaped payload in a length-prefixed
// fallback frame. The peer's tcpListen loop recognizes the frame and delivers
// the payload to PacketCh.
func (t *NetTransport) writePacketViaTCP(b []byte, addr string) error {
	conn, err := t.DialTimeout(addr, t.tcpFallbackTimeout())
	if err != nil {
		return fmt.Errorf("TCP fallback dial failed: %w", err)
	}
	defer func() {
		_ = conn.Close()
	}()

	if deadline := time.Now().Add(t.tcpFallbackTimeout()); deadline.After(time.Now()) {
		_ = conn.SetWriteDeadline(deadline)
	}

	header := make([]byte, tcpFallbackHeaderSize)
	copy(header[0:4], tcpFallbackMagic[:])
	header[4] = 1 // version
	header[5] = 0 // flags
	binary.BigEndian.PutUint32(header[8:12], uint32(len(b)))

	if _, err := conn.Write(header); err != nil {
		return fmt.Errorf("TCP fallback header write failed: %w", err)
	}
	if _, err := conn.Write(b); err != nil {
		return fmt.Errorf("TCP fallback payload write failed: %w", err)
	}
	return nil
}

// See Transport.
func (t *NetTransport) PacketCh() <-chan *Packet {
	return t.packetCh
}

// See IngestionAwareTransport.
func (t *NetTransport) IngestPacket(conn net.Conn, addr net.Addr, now time.Time, shouldClose bool) error {
	if shouldClose {
		defer func() {
			_ = conn.Close()
		}()
	}

	// Copy everything from the stream into packet buffer.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, conn); err != nil {
		return fmt.Errorf("failed to read packet: %v", err)
	}

	// Check the length - it needs to have at least one byte to be a proper
	// message. This is checked elsewhere for writes coming in directly from
	// the UDP socket.
	if n := buf.Len(); n < 1 {
		return fmt.Errorf("packet too short (%d bytes) %s", n, LogAddress(addr))
	}

	// Inject the packet.
	packet := &Packet{
		Buf:       buf.Bytes(),
		From:      addr,
		Timestamp: now,
	}
	select {
	case t.packetCh <- packet:
		return nil
	case <-t.closeChannel():
		return ErrTransportClosed
	}
}

func (t *NetTransport) closeChannel() <-chan struct{} {
	if t.closeCh != nil {
		return t.closeCh
	}
	// A nil channel in a select blocks forever, preserving the historical
	// blocking behavior for tests that construct a partial NetTransport.
	return nil
}

// See Transport.
func (t *NetTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	a := Address{Addr: addr, Name: ""}
	return t.DialAddressTimeout(a, timeout)
}

// See NodeAwareTransport.
func (t *NetTransport) DialAddressTimeout(a Address, timeout time.Duration) (net.Conn, error) {
	addr := a.Addr

	dialer := net.Dialer{Timeout: timeout}
	return dialer.Dial("tcp", addr)
}

// See Transport.
func (t *NetTransport) StreamCh() <-chan net.Conn {
	return t.streamCh
}

// See IngestionAwareTransport.
func (t *NetTransport) IngestStream(conn net.Conn) error {
	select {
	case t.streamCh <- conn:
		return nil
	case <-t.closeChannel():
		return ErrTransportClosed
	}
}

// See Transport.
func (t *NetTransport) Shutdown() error {
	// This will avoid log spam about errors when we shut down.
	t.shutdown.Store(1)
	if t.closeCh != nil {
		t.closeOnce.Do(func() { close(t.closeCh) })
	}

	// Rip through all the listeners and shut them down.
	for _, conn := range t.tcpListeners {
		_ = conn.Close()
	}
	for _, conn := range t.udpListeners {
		_ = conn.Close()
	}

	// Unblock per-connection reads and handoff selects.
	t.closeActiveConns()

	// Block until all the listener threads have died.
	t.wg.Wait()

	// Listener loops no longer spawn new connection goroutines after wg.Wait
	// returns; wait for the ones already accepted to wind down.
	t.connWg.Wait()
	return nil
}

func (t *NetTransport) addActiveConn(conn net.Conn) {
	if t.activeConns == nil {
		t.activeConns = make(map[net.Conn]struct{})
	}
	t.connMu.Lock()
	t.activeConns[conn] = struct{}{}
	t.connMu.Unlock()
}

func (t *NetTransport) removeActiveConn(conn net.Conn) {
	t.connMu.Lock()
	delete(t.activeConns, conn)
	t.connMu.Unlock()
}

func (t *NetTransport) closeActiveConns() {
	t.connMu.Lock()
	conns := t.activeConns
	t.activeConns = make(map[net.Conn]struct{})
	t.connMu.Unlock()

	for conn := range conns {
		_ = conn.Close()
	}
}

// tcpListen is a long running goroutine that accepts incoming TCP connections
// and hands them off to the stream channel.
func (t *NetTransport) tcpListen(tcpLn *net.TCPListener) {
	defer t.wg.Done()

	// baseDelay is the initial delay after an AcceptTCP() error before attempting again
	const baseDelay = 5 * time.Millisecond

	// maxDelay is the maximum delay after an AcceptTCP() error before attempting again.
	// In the case that tcpListen() is error-looping, it will delay the shutdown check.
	// Therefore, changes to maxDelay may have an effect on the latency of shutdown.
	const maxDelay = 1 * time.Second

	var loopDelay time.Duration
	for {
		conn, err := tcpLn.AcceptTCP()
		if err != nil {
			if s := t.shutdown.Load(); s == 1 {
				break
			}

			if loopDelay == 0 {
				loopDelay = baseDelay
			} else {
				loopDelay *= 2
			}

			if loopDelay > maxDelay {
				loopDelay = maxDelay
			}

			t.logger.Printf("[ERR] memberlist: Error accepting TCP connection: %v", err)
			time.Sleep(loopDelay)
			continue
		}
		// No error, reset loop delay
		loopDelay = 0

		// Hand the connection to StreamCh immediately, as NetTransport has
		// always done. In fallback mode a background classifier can route our
		// own framed TCP fallback back to PacketCh without delaying StreamCh.
		if !t.tcpFallbackEnabled() {
			select {
			case t.streamCh <- conn:
			case <-t.closeChannel():
				_ = conn.Close()
				return
			}
			continue
		}

		connWrapper := newFallbackClassifiedConn(conn)
		t.connWg.Add(1)
		go t.classifyTCPFallbackConn(connWrapper)

		select {
		case t.streamCh <- connWrapper:
		case <-t.closeChannel():
			_ = connWrapper.Close()
			return
		}
	}
}

// fallbackClassifiedConn lets a background goroutine peek for the transport's
// TCP fallback magic while the connection remains immediately available from
// StreamCh. Read serializes against that peek. Once a fallback frame is claimed,
// ordinary stream readers see EOF because the frame was consumed internally.
type fallbackClassifiedConn struct {
	net.Conn
	br    *bufio.Reader
	ready chan struct{}

	fallback bool
}

func newFallbackClassifiedConn(conn net.Conn) *fallbackClassifiedConn {
	return &fallbackClassifiedConn{
		Conn:  conn,
		br:    bufio.NewReader(conn),
		ready: make(chan struct{}),
	}
}

// Read waits for classification so a stream reader cannot race the classifier
// and consume bytes from a fallback frame.
func (c *fallbackClassifiedConn) Read(p []byte) (int, error) {
	<-c.ready
	if c.fallback {
		return 0, io.EOF
	}
	return c.br.Read(p)
}

func (t *NetTransport) classifyTCPFallbackConn(conn *fallbackClassifiedConn) {
	defer close(conn.ready)
	defer t.connWg.Done()

	t.addActiveConn(conn.Conn)
	defer t.removeActiveConn(conn.Conn)

	// Peeking must not allow an idle connection to pin this goroutine forever
	// during shutdown. Normal stream handlers install their own deadline after
	// receiving the connection.
	_ = conn.Conn.SetReadDeadline(time.Now().Add(t.tcpFallbackTimeout()))
	first, err := conn.br.Peek(1)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !t.isClosed() {
			t.logger.Printf("[ERR] memberlist: Error inspecting TCP connection: %v", err)
		}
		_ = conn.Conn.Close()
		return
	}
	if first[0] != tcpFallbackMagic[0] {
		_ = conn.Conn.SetReadDeadline(time.Time{})
		return
	}

	peeked, err := conn.br.Peek(len(tcpFallbackMagic))
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !t.isClosed() {
			t.logger.Printf("[ERR] memberlist: Error inspecting TCP fallback preamble: %v", err)
		}
		_ = conn.Conn.Close()
		return
	}
	if !bytes.Equal(peeked, tcpFallbackMagic[:]) {
		_ = conn.Conn.SetReadDeadline(time.Time{})
		return
	}

	conn.fallback = true
	t.readTCPFallbackFrame(conn.br, conn.Conn)
}

// readTCPFallbackFrame reads one framed packet and delivers it to packetCh.
// The connection is always closed before returning.
func (t *NetTransport) readTCPFallbackFrame(br *bufio.Reader, conn net.Conn) {
	defer func() {
		_ = conn.Close()
	}()

	header := make([]byte, tcpFallbackHeaderSize)
	if _, err := io.ReadFull(br, header); err != nil {
		if !t.isClosed() {
			t.logger.Printf("[ERR] memberlist: Error reading TCP fallback header: %v", err)
		}
		return
	}
	if !bytes.Equal(header[0:4], tcpFallbackMagic[:]) {
		t.logger.Printf("[ERR] memberlist: Invalid TCP fallback magic")
		return
	}

	n := binary.BigEndian.Uint32(header[8:12])
	if n > uint32(maxUserMsgBytes) {
		t.logger.Printf("[ERR] memberlist: TCP fallback packet too large: %d", n)
		return
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		if !t.isClosed() {
			t.logger.Printf("[ERR] memberlist: Error reading TCP fallback payload: %v", err)
		}
		return
	}

	from := net.Addr(conn.RemoteAddr())
	if tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		from = &net.UDPAddr{IP: tcpAddr.IP, Port: tcpAddr.Port, Zone: tcpAddr.Zone}
	}

	payload, ok := t.acceptSequencedPacket(payload, from)
	if !ok {
		return
	}
	n = uint32(len(payload))

	metrics.IncrCounterWithLabels([]string{"memberlist", "tcp_fallback", "received"}, float32(n), t.metricLabels)
	packet := &Packet{Buf: payload, From: from, Timestamp: time.Now()}
	select {
	case t.packetCh <- packet:
	case <-t.closeChannel():
	}
}

// readLoop is the descriptive alias used for the UDP receive loop. It exits
// when its underlying connection is closed or Shutdown signals completion.
func (t *NetTransport) readLoop(udpLn *net.UDPConn) { t.udpListen(udpLn) }

// udpListen is a long running goroutine that accepts incoming UDP packets and
// hands them off to the packet channel.
func (t *NetTransport) udpListen(udpLn *net.UDPConn) {
	defer t.wg.Done()
	for {
		// Do a blocking read into a fresh buffer. Grab a time stamp as
		// close as possible to the I/O.
		buf := make([]byte, udpPacketBufSize)
		n, addr, err := udpLn.ReadFrom(buf)
		ts := time.Now()
		if err != nil {
			if t.isClosed() || errors.Is(err, net.ErrClosed) {
				break
			}

			t.logger.Printf("[ERR] memberlist: Error reading UDP packet: %v", err)
			continue
		}

		// Check the length - it needs to have at least one byte to be a
		// proper message.
		if n < 1 {
			t.logger.Printf("[ERR] memberlist: UDP packet too short (%d bytes) %s",
				len(buf), LogAddress(addr))
			continue
		}

		payload, ok := t.acceptSequencedPacket(buf[:n], addr)
		if !ok {
			continue
		}
		n = len(payload)

		// Ingest the packet. A select on closeCh prevents a reader that has
		// stopped consuming packetCh from leaking this goroutine on shutdown.
		metrics.IncrCounterWithLabels([]string{"memberlist", "udp", "received"}, float32(n), t.metricLabels)
		packet := &Packet{
			Buf:       payload,
			From:      addr,
			Timestamp: ts,
		}
		select {
		case t.packetCh <- packet:
		case <-t.closeChannel():
			return
		}
	}
}

// setUDPRecvBuf is used to resize the UDP receive window. The function
// attempts to set the read buffer to `udpRecvBuf` but backs off until
// the read buffer can be set.
func setUDPRecvBuf(c *net.UDPConn) error {
	size := udpRecvBufSize
	var err error
	for size > 0 {
		if err = c.SetReadBuffer(size); err == nil {
			return nil
		}
		size = size / 2
	}
	return err
}

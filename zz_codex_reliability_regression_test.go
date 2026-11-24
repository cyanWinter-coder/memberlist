// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bufio"
	"io"
	"log"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newCodexReliabilityTransport(t *testing.T, configure func(*NetTransportConfig)) *NetTransport {
	t.Helper()

	cfg := &NetTransportConfig{
		BindAddrs:        []string{"127.0.0.1"},
		BindPort:         0,
		Logger:           log.New(io.Discard, "", 0),
		MaxUDPPacketSize: 128,
		TCPFallback:      true,
	}
	if configure != nil {
		configure(cfg)
	}

	tr, err := NewNetTransport(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tr.Shutdown() })
	return tr
}

func waitCodexPacket(t *testing.T, ch <-chan *Packet) *Packet {
	t.Helper()
	select {
	case p := <-ch:
		return p
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for packet")
		return nil
	}
}

func TestCodexNetTransport_UDPPacketLimitAndTCPFallback(t *testing.T) {
	receiver := newCodexReliabilityTransport(t, nil)
	sender := newCodexReliabilityTransport(t, nil)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(receiver.GetAutoBindPort()))

	payload := make([]byte, 1024)
	for i := range payload {
		payload[i] = byte(i)
	}

	_, err := sender.WriteToAddress(payload, Address{Addr: addr})
	require.NoError(t, err)

	packet := waitCodexPacket(t, receiver.PacketCh())
	require.Equal(t, payload, packet.Buf)
}

func TestCodexNetTransport_WithinUDPLimitUsesUDP(t *testing.T) {
	receiver := newCodexReliabilityTransport(t, nil)
	sender := newCodexReliabilityTransport(t, nil)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(receiver.GetAutoBindPort()))

	payload := []byte("within limit")
	_, err := sender.WriteToAddress(payload, Address{Addr: addr})
	require.NoError(t, err)

	packet := waitCodexPacket(t, receiver.PacketCh())
	require.Equal(t, payload, packet.Buf)
}

func TestCodexNetTransport_OversizedUDPRequiresFallback(t *testing.T) {
	tr := newCodexReliabilityTransport(t, func(c *NetTransportConfig) {
		c.TCPFallback = false
		c.EnableTCPFallback = false
	})

	_, err := tr.WriteToAddress(make([]byte, tr.maxUDPPacketSize()+1), Address{Addr: "127.0.0.1:1"})
	require.ErrorIs(t, err, ErrUDPPacketTooLarge)
}

func TestCodexSequenceFilter_DropsDuplicateAndOutOfOrder(t *testing.T) {
	f := NewSequenceFilter()

	require.True(t, f.Accept(uint32(10)))
	require.True(t, f.Accept(uint32(11)))

	// A repeated packet is rejected but does not advance expected state.
	require.False(t, f.Accept(uint32(11)))
	require.ErrorIs(t, f.Check(uint32(11)), ErrDuplicatePacket)

	// A future packet is rejected and also does not advance expected state.
	require.False(t, f.Accept(uint32(13)))
	require.ErrorIs(t, f.Check(uint32(13)), ErrOutOfOrderPacket)

	// The next protocol packet after the drops is still accepted.
	require.True(t, f.Accept(uint32(12)))
	require.True(t, f.Accept(uint32(13)))
}

func TestCodexSendBuffer_FullReturnsError(t *testing.T) {
	buf := NewSendBuffer(1)
	require.NoError(t, buf.Enqueue([]byte("first")))

	err := buf.Enqueue([]byte("second"))
	require.ErrorIs(t, err, ErrSendBufferFull)

	p, ok := buf.Dequeue()
	require.True(t, ok)
	require.Equal(t, []byte("first"), p)

	// Draining restores capacity and the rejected message was not queued.
	require.NoError(t, buf.Enqueue([]byte("third")))
	require.Equal(t, 1, buf.Len())
}

func TestCodexUDPListen_ExitsWhenConnectionClosed(t *testing.T) {
	udpLn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)

	tr := &NetTransport{
		logger:  log.New(io.Discard, "", 0),
		closeCh: make(chan struct{}),
	}
	tr.wg.Add(1)
	go tr.udpListen(udpLn)

	require.NoError(t, udpLn.Close())

	done := make(chan struct{})
	go func() {
		tr.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("udpListen did not exit after its connection was closed")
	}
}

func TestCodexTCPFallbackReadLoop_ExitsWhenConnectionCloses(t *testing.T) {
	server, client := net.Pipe()
	tr := &NetTransport{
		logger:   log.New(io.Discard, "", 0),
		packetCh: make(chan *Packet, 1),
		closeCh:  make(chan struct{}),
	}
	tr.connWg.Add(1)
	go func() {
		defer tr.connWg.Done()
		tr.readTCPFallbackFrame(bufio.NewReader(server), server)
	}()

	require.NoError(t, client.Close())

	done := make(chan struct{})
	go func() {
		tr.connWg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("TCP fallback read loop did not exit after connection close")
	}
}

func TestCodexCompatibilityAliases(t *testing.T) {
	// Keep package-private spelling aliases exercised for white-box callers.
	require.True(t, newPacketSequence().Accept(uint32(0)))
	require.True(t, newSequenceFilter().Accept(uint32(0)))
	require.True(t, newSequenceTracker().Accept(uint32(0)))

	var window *sequenceWindow = NewSequenceWindow(1)
	require.True(t, window.Accept(uint32(0)))

	var _ *BoundedSendBuffer = NewBoundedSendBuffer(1)
}

func TestCodexTCPStreamChReceivesConnBeforeClientWrites(t *testing.T) {
	tr := newCodexReliabilityTransport(t, nil)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(tr.GetAutoBindPort()))

	client, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	var server net.Conn
	select {
	case server = <-tr.StreamCh():
	case <-time.After(time.Second):
		t.Fatal("StreamCh did not receive connection before client write")
	}

	payload := []byte("normal stream payload")
	_, err = client.Write(payload)
	require.NoError(t, err)

	buf := make([]byte, len(payload))
	_, err = io.ReadFull(server, buf)
	require.NoError(t, err)
	require.Equal(t, payload, buf)
}

func TestCodexPacketSequenceDropsDuplicateAndOutOfOrderUDP(t *testing.T) {
	receiver := newCodexReliabilityTransport(t, func(c *NetTransportConfig) {
		c.EnablePacketSequence = true
		c.TCPFallback = false
	})
	sender := newCodexReliabilityTransport(t, func(c *NetTransportConfig) {
		c.EnablePacketSequence = true
		c.TCPFallback = false
	})
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(receiver.GetAutoBindPort()))
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	require.NoError(t, err)

	_, err = sender.WriteToAddress([]byte("zero"), Address{Addr: addr})
	require.NoError(t, err)
	_, err = sender.WriteToAddress([]byte("one"), Address{Addr: addr})
	require.NoError(t, err)

	require.Equal(t, []byte("zero"), waitCodexPacket(t, receiver.PacketCh()).Buf)
	require.Equal(t, []byte("one"), waitCodexPacket(t, receiver.PacketCh()).Buf)

	// Replay sequence 1, then send a future sequence. Both must be dropped.
	duplicate := append(encodePacketSequence(1), []byte("duplicate")...)
	_, err = sender.udpListeners[0].WriteTo(duplicate, udpAddr)
	require.NoError(t, err)
	future := append(encodePacketSequence(99), []byte("future")...)
	_, err = sender.udpListeners[0].WriteTo(future, udpAddr)
	require.NoError(t, err)

	// The next valid sequence after "one" is still accepted.
	_, err = sender.WriteToAddress([]byte("two"), Address{Addr: addr})
	require.NoError(t, err)
	require.Equal(t, []byte("two"), waitCodexPacket(t, receiver.PacketCh()).Buf)

	select {
	case p := <-receiver.PacketCh():
		t.Fatalf("unexpected packet after sequence drops: %q", p.Buf)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestCodexMemberlist_OversizedBestEffortUsesTCPFallback(t *testing.T) {
	receiverDelegate := &MockDelegate{}
	c1 := testConfig(t)
	c1.Delegate = receiverDelegate
	c1.UDPBufferSize = 256
	c1.Logger = log.New(io.Discard, "", 0)
	m1, err := Create(c1)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m1.Shutdown()) })

	c2 := testConfig(t)
	c2.UDPBufferSize = 256
	c2.Logger = log.New(io.Discard, "", 0)
	m2, err := Create(c2)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, m2.Shutdown()) })

	_, err = m2.Join([]string{c1.Name + "/" + m1.LocalNode().Address()})
	require.NoError(t, err)
	require.Eventually(t, func() bool { return len(m2.Members()) == 2 }, 5*time.Second, 20*time.Millisecond)

	var receiver *Node
	for _, n := range m2.Members() {
		if n.Name == c1.Name {
			receiver = n
		}
	}
	require.NotNil(t, receiver)

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	require.NoError(t, m2.SendBestEffort(receiver, payload))

	require.Eventually(t, func() bool {
		for _, msg := range receiverDelegate.getMessages() {
			if string(msg) == string(payload) {
				return true
			}
		}
		return false
	}, 5*time.Second, 20*time.Millisecond)
}

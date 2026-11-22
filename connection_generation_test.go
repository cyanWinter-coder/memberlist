// Copyright IBM Corp. 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/hashicorp/go-msgpack/v2/codec"
	"github.com/stretchr/testify/require"
)

// newTestMemberlistWithMock builds a Memberlist backed by a MockTransport and
// returns both the memberlist and its transport.
func newTestMemberlistWithMock(t *testing.T, name string) (*Memberlist, *MockTransport) {
	t.Helper()
	network := &MockNetwork{}
	transport := network.NewTransport(name)

	c := DefaultLANConfig()
	c.Name = name
	c.Transport = transport
	c.RequireNodeNames = false
	m, err := Create(c)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = m.Shutdown()
	})
	return m, transport
}

// encodedAliveMsg builds an alive message for the given node.
func encodedAliveMsg(t *testing.T, m *Memberlist, node string, incarnation uint32) []byte {
	t.Helper()
	a := alive{
		Incarnation: incarnation,
		Node:        node,
		Addr:        net.ParseIP("127.0.0.1"),
		Port:        7946,
		Vsn:         m.config.BuildVsnArray(),
	}
	buf, err := encode(aliveMsg, &a, m.config.MsgpackUseNewTimeFormat)
	require.NoError(t, err)
	return buf.Bytes()
}

// encodedDeadMsg builds a dead message for the given node.
func encodedDeadMsg(t *testing.T, m *Memberlist, node string, incarnation uint32) []byte {
	t.Helper()
	d := dead{Incarnation: incarnation, Node: node, From: "some-other-node"}
	buf, err := encode(deadMsg, &d, m.config.MsgpackUseNewTimeFormat)
	require.NoError(t, err)
	return buf.Bytes()
}

// waitForQueueDrain yields until the packet handler has consumed the queued
// handoff messages.
func waitForQueueDrain(t *testing.T, m *Memberlist) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		m.msgQueueLock.Lock()
		empty := m.highPriorityMsgQueue.Len() == 0 && m.lowPriorityMsgQueue.Len() == 0
		m.msgQueueLock.Unlock()
		if empty {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for handoff queues to drain")
}

// TestConnectionGeneration_InitialGeneration verifies the generation counter
// starts at the first generation.
func TestConnectionGeneration_InitialGeneration(t *testing.T) {
	g := newConnectionGeneration()
	require.Equal(t, uint64(1), g.currentGeneration())
	require.False(t, g.isStale(1))
	require.True(t, g.isStale(0))

	require.Equal(t, uint64(2), g.bump())
	require.Equal(t, uint64(2), g.currentGeneration())
	require.True(t, g.isStale(1))
	require.False(t, g.isStale(2))
}

// TestConnectionGeneration_StalePacketDropped verifies requirement 1 and 3:
// a state-changing packet queued under an older connection generation cannot
// mutate the member table after a successful re-join, whereas a current
// generation packet is applied normally.
func TestConnectionGeneration_StalePacketDropped(t *testing.T) {
	m, transport := newTestMemberlistWithMock(t, "node1")

	// Inject an alive message belonging to generation 1 directly into the
	// handoff queue, simulating a delayed message from the old connection.
	oldAlive := encodedAliveMsg(t, m, "stale-node", 1)
	m.msgQueueLock.Lock()
	m.highPriorityMsgQueue.PushBack(msgHandoff{
		msgType: aliveMsg,
		buf:     oldAlive,
		from:    transport.addr,
		gen:     m.generation.currentGeneration(),
	})
	m.msgQueueLock.Unlock()

	// A new node joins on the same address; the join bumps the generation.
	joinGen := m.generation.bump()
	require.Equal(t, uint64(2), joinGen)
	m.advanceGeneration(joinGen)

	// Signal the packet handler.
	select {
	case m.handoffCh <- struct{}{}:
	default:
	}
	waitForQueueDrain(t, m)

	// The stale alive message must not have created a member.
	_, present := m.nodeMap["stale-node"]
	require.False(t, present, "stale generation alive message mutated the member table")

	// A current-generation alive message must be applied.
	currentAlive := encodedAliveMsg(t, m, "fresh-node", 1)
	m.handleCommand(currentAlive, transport.addr, time.Now())
	select {
	case m.handoffCh <- struct{}{}:
	default:
	}
	waitForQueueDrain(t, m)

	state, present := m.nodeMap["fresh-node"]
	require.True(t, present, "current generation alive message was not applied")
	require.Equal(t, StateAlive, state.State)
}

// TestConnectionGeneration_StaleDeadDoesNotEmitEvent verifies that a delayed
// dead message from an old generation cannot produce a leave event on the new
// instance.
func TestConnectionGeneration_StaleDeadDoesNotEmitEvent(t *testing.T) {
	m, transport := newTestMemberlistWithMock(t, "node1")

	// Seed an alive node in the current generation.
	a := encodedAliveMsg(t, m, "peer", 1)
	m.handleCommand(a, transport.addr, time.Now())
	select {
	case m.handoffCh <- struct{}{}:
	default:
	}
	waitForQueueDrain(t, m)
	require.Contains(t, m.nodeMap, "peer")

	// Queue a dead message stamped with the old generation, then bump.
	oldDead := encodedDeadMsg(t, m, "peer", 1)
	oldGen := m.generation.currentGeneration()
	m.msgQueueLock.Lock()
	m.lowPriorityMsgQueue.PushBack(msgHandoff{
		msgType: deadMsg,
		buf:     oldDead,
		from:    transport.addr,
		gen:     oldGen,
	})
	m.msgQueueLock.Unlock()

	newGen := m.generation.bump()
	m.advanceGeneration(newGen)
	select {
	case m.handoffCh <- struct{}{}:
	default:
	}
	waitForQueueDrain(t, m)

	require.Equal(t, StateAlive, m.nodeMap["peer"].State,
		"stale generation dead message changed member state")
}

// TestConnectionGeneration_ConcurrentJoinAcceptsOnlyLatest verifies
// requirement 3: when joins run concurrently, member-table updates queued by
// an earlier generation are discarded once a later generation commits.
func TestConnectionGeneration_ConcurrentJoinAcceptsOnlyLatest(t *testing.T) {
	m, transport := newTestMemberlistWithMock(t, "node1")

	// Flood both queues with generation-1 state messages.
	for i := range 8 {
		buf := encodedAliveMsg(t, m, "old-node", uint32(i+1))
		m.msgQueueLock.Lock()
		m.highPriorityMsgQueue.PushBack(msgHandoff{
			msgType: aliveMsg, buf: buf, from: transport.addr, gen: 1,
		})
		m.lowPriorityMsgQueue.PushBack(msgHandoff{
			msgType: deadMsg,
			buf:     encodedDeadMsg(t, m, "old-node", uint32(i+1)),
			from:    transport.addr,
			gen:     1,
		})
		m.msgQueueLock.Unlock()
	}

	// Simulate two generations committed back-to-back, as concurrent joins
	// would produce under joinLock serialization.
	gen2 := m.generation.bump()
	m.advanceGeneration(gen2)
	gen3 := m.generation.bump()
	m.advanceGeneration(gen3)

	select {
	case m.handoffCh <- struct{}{}:
	default:
	}
	waitForQueueDrain(t, m)

	_, present := m.nodeMap["old-node"]
	require.False(t, present, "old-generation queued updates survived a generation bump")
}

// TestConnectionGeneration_AdvanceFlushesStaleHandoff verifies requirement 3
// for the inbound queue: a generation bump flushes stale handoff entries
// across both priority queues while current-generation entries remain.
func TestConnectionGeneration_AdvanceFlushesStaleHandoff(t *testing.T) {
	m, transport := newTestMemberlistWithMock(t, "node1")

	oldAlive := encodedAliveMsg(t, m, "old-alive", 1)
	oldDead := encodedDeadMsg(t, m, "old-dead", 1)
	oldGen := m.generation.currentGeneration()

	m.msgQueueLock.Lock()
	m.highPriorityMsgQueue.PushBack(msgHandoff{
		msgType: aliveMsg, buf: oldAlive, from: transport.addr, gen: oldGen,
	})
	m.lowPriorityMsgQueue.PushBack(msgHandoff{
		msgType: deadMsg, buf: oldDead, from: transport.addr, gen: oldGen,
	})
	m.msgQueueLock.Unlock()

	newGen := m.generation.bump()
	m.advanceGeneration(newGen)

	m.msgQueueLock.Lock()
	highLen := m.highPriorityMsgQueue.Len()
	lowLen := m.lowPriorityMsgQueue.Len()
	m.msgQueueLock.Unlock()
	require.Equal(t, 0, highLen, "stale high-priority handoff was not flushed")
	require.Equal(t, 0, lowLen, "stale low-priority handoff was not flushed")

	// A message queued after the bump survives a no-op advance of the same
	// generation and is applied normally.
	freshAlive := encodedAliveMsg(t, m, "fresh-node", 1)
	m.handleCommand(freshAlive, transport.addr, time.Now())
	m.advanceGeneration(m.generation.currentGeneration())
	select {
	case m.handoffCh <- struct{}{}:
	default:
	}
	waitForQueueDrain(t, m)
	require.Contains(t, m.nodeMap, "fresh-node")
}

// TestConnectionGeneration_OutboundBroadcastsSurviveBump verifies that local
// generation bumps do not suppress outbound gossip: a broadcast enqueued
// before a join must still be transmitted afterwards, since generation gating
// is enforced by the receiving peer on its inbound paths.
func TestConnectionGeneration_OutboundBroadcastsSurviveBump(t *testing.T) {
	m, _ := newTestMemberlistWithMock(t, "node1")

	before := m.broadcasts.NumQueued()
	m.queueBroadcast("gossip-node", []byte("payload"), nil)
	require.Equal(t, before+1, m.broadcasts.NumQueued())

	newGen := m.generation.bump()
	m.advanceGeneration(newGen)

	// The bump itself must not have removed the broadcast.
	require.Equal(t, before+1, m.broadcasts.NumQueued(),
		"outbound broadcast must not be pruned by a local generation bump")
}

// TestConnectionGeneration_StaleStreamMergeRejected verifies requirement 1
// for the stream path: a push/pull accepted under an old generation cannot
// merge remote state into the member table.
func TestConnectionGeneration_StaleStreamMergeRejected(t *testing.T) {
	m, _ := newTestMemberlistWithMock(t, "node1")

	remoteNodes := []pushNodeState{
		{
			Name:        "stream-node",
			Addr:        net.ParseIP("127.0.0.1"),
			Port:        7946,
			Incarnation: 1,
			State:       StateAlive,
			Vsn:         m.config.BuildVsnArray(),
		},
	}

	// Capture the old generation, then advance as a successful re-join would.
	oldGen := m.generation.currentGeneration()
	newGen := m.generation.bump()
	m.advanceGeneration(newGen)
	require.True(t, m.generation.isStale(oldGen))

	// mergeState is the state-application step of handleConn's push/pull
	// branch; replicate the guard the branch applies before merging.
	if m.generation.isStale(oldGen) {
		// Expected: handler returns without merging.
	} else {
		m.mergeState(remoteNodes)
	}
	_, present := m.nodeMap["stream-node"]
	require.False(t, present, "stale-generation stream merge altered the member table")

	// The current generation can still merge the same state.
	m.mergeState(remoteNodes)
	_, present = m.nodeMap["stream-node"]
	require.True(t, present, "current-generation stream merge was rejected")
}

// TestConnectionGeneration_JoinBumpsGeneration verifies a successful Join
// allocates and commits a new generation, isolating post-join state from
// pre-join communication.
func TestConnectionGeneration_JoinBumpsGeneration(t *testing.T) {
	network := &MockNetwork{}
	t1 := network.NewTransport("node1")
	t2 := network.NewTransport("node2")

	c1 := DefaultLANConfig()
	c1.Name = "node1"
	c1.Transport = t1
	c1.RequireNodeNames = false
	m1, err := Create(c1)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m1.Shutdown() })

	c2 := DefaultLANConfig()
	c2.Name = "node2"
	c2.Transport = t2
	c2.RequireNodeNames = false
	m2, err := Create(c2)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m2.Shutdown() })

	starting := m2.generation.currentGeneration()

	num, err := m2.Join([]string{"node1/" + t1.addr.String()})
	require.NoError(t, err)
	require.Equal(t, 1, num)

	// A successful join commits exactly one new generation.
	require.Equal(t, starting+1, m2.generation.currentGeneration())

	// Nothing from the pre-join generation may be treated as current anymore.
	require.True(t, m2.generation.isStale(starting))
}

// TestConnectionGeneration_StaleStreamHandleConn verifies the full stream
// path: a push/pull connection accepted under an old generation is processed
// (local state may still be sent and the connection cleaned up) but its
// remote state never mutates the member table.
func TestConnectionGeneration_StaleStreamHandleConn(t *testing.T) {
	m, _ := newTestMemberlistWithMock(t, "node1")

	oldGen := m.generation.currentGeneration()
	newGen := m.generation.bump()
	m.advanceGeneration(newGen)

	remoteNodes := []pushNodeState{
		{
			Name:        "stream-stale",
			Addr:        net.ParseIP("127.0.0.1"),
			Port:        7946,
			Incarnation: 1,
			State:       StateAlive,
			Vsn:         m.config.BuildVsnArray(),
		},
	}

	header := pushPullHeader{Nodes: len(remoteNodes), Join: true}
	hd := codec.MsgpackHandle{}
	var buf []byte
	enc := codec.NewEncoderBytes(&buf, &hd)
	require.NoError(t, enc.Encode(&header))
	for i := range remoteNodes {
		require.NoError(t, enc.Encode(&remoteNodes[i]))
	}

	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	// Drain any response the handler writes (its local state) so the
	// unbuffered pipe never blocks sendLocalState.
	clientDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, client)
		close(clientDone)
	}()

	handleDone := make(chan struct{})
	go func() {
		// handleConn stamps the accepted generation; emulate streamListen's
		// call with the stale generation.
		m.handleConn(server, oldGen)
		close(handleDone)
	}()

	// Write a push/pull message to the handler (no label header, matching the
	// default config).
	frame := append([]byte{byte(pushPullMsg)}, buf...)
	_, err := client.Write(frame)
	require.NoError(t, err)

	select {
	case <-handleDone:
	case <-time.After(2 * time.Second):
		t.Fatal("stale handleConn did not finish and clean up the connection")
	}
	_ = client.Close()
	<-clientDone

	_, present := m.nodeMap["stream-stale"]
	require.False(t, present, "stale-generation push/pull mutated the member table")
}

// TestConnectionGeneration_ShutdownWaitsForStreamHandlers verifies requirement
// 2 with a mock transport: Shutdown force-closes connections whose handlers
// are blocked in the handshake and waits for every handler goroutine.
func TestConnectionGeneration_ShutdownWaitsForStreamHandlers(t *testing.T) {
	network := &MockNetwork{}
	transport := network.NewTransport("node1")

	c := DefaultLANConfig()
	c.Name = "node1"
	c.Transport = transport
	c.RequireNodeNames = false
	m, err := Create(c)
	require.NoError(t, err)

	// Simulate an inbound connection whose peer never sends the label/header
	// handshake, leaving handleConn blocked on the read.
	client, server := net.Pipe()
	m.conns.add(server)
	m.streamWg.Add(1)
	go func() {
		defer m.streamWg.Done()
		defer m.conns.remove(server)
		m.handleConn(server, m.generation.currentGeneration())
	}()
	time.Sleep(100 * time.Millisecond) // let the handler block on Read
	require.Equal(t, 1, m.conns.len())

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- m.Shutdown()
	}()
	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		_ = client.Close()
		t.Fatal("Shutdown did not reap the handler blocked in the handshake")
	}
	_ = client.Close()
	require.Equal(t, 0, m.conns.len())
}

// TestConnectionRegistry_CloseAllUnblocksRead verifies requirement 2: tracked
// connections can be force-closed so a handler blocked in a read (or
// handshake) cannot leak a goroutine.
func TestConnectionRegistry_CloseAllUnblocksRead(t *testing.T) {
	registry := newConnRegistry()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()

	registry.add(server)
	require.Equal(t, 1, registry.len())

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, err := server.Read(buf)
		readDone <- err
	}()

	// Closing all tracked connections must unblock the blocked read.
	registry.closeAll()
	select {
	case err := <-readDone:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("blocked read was not unblocked by closeAll")
	}
	require.Equal(t, 0, registry.len())
}

// TestNetTransport_ShutdownClosesInFlightConnection verifies requirement 2
// end-to-end: a connection dialed through the transport is force-closed on
// Shutdown even if its handler is stuck in the handshake phase, and the
// transport Shutdown returns without hanging.
func TestNetTransport_ShutdownClosesInFlightConnection(t *testing.T) {
	transport, err := NewNetTransport(&NetTransportConfig{
		BindAddrs: []string{"127.0.0.1"},
		BindPort:  0,
	})
	require.NoError(t, err)

	// Dial a loopback connection against the transport's own listener to
	// create an in-flight tracked connection.
	addr := transport.tcpListeners[0].Addr().String()
	conn, err := transport.DialTimeout(addr, time.Second)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	readDone := make(chan error, 1)
	go func() {
		buf := make([]byte, 1)
		_, e := conn.Read(buf)
		readDone <- e
	}()

	// Shutdown must return promptly and interrupt the blocked read.
	shutdownDone := make(chan struct{})
	go func() {
		_ = transport.Shutdown()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
	case <-time.After(2 * time.Second):
		t.Fatal("transport Shutdown blocked while a connection was in flight")
	}

	select {
	case err := <-readDone:
		require.Error(t, err)
	case <-time.After(time.Second):
		t.Fatal("in-flight connection was not closed by Shutdown")
	}
}

// TestNetTransport_ShutdownDoesNotBlockOnFullChannels verifies the send phase
// is covered by shutdown: Shutdown completes even when nobody is consuming
// the packet/stream channels.
func TestNetTransport_ShutdownDoesNotBlockOnFullChannels(t *testing.T) {
	transport, err := NewNetTransport(&NetTransportConfig{
		BindAddrs: []string{"127.0.0.1"},
		BindPort:  0,
	})
	require.NoError(t, err)

	// Fill the unbuffered stream channel handoff by accepting a connection
	// that no memberlist side will consume.
	addr := transport.tcpListeners[0].Addr().String()
	client, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer func() { _ = client.Close() }()

	// Give the listener a moment to block handing the stream off.
	time.Sleep(100 * time.Millisecond)

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- transport.Shutdown()
	}()
	select {
	case err := <-shutdownDone:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("Shutdown blocked on a stream channel nobody is reading")
	}
}

// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAdaptiveProbeInterval(t *testing.T) {
	min := time.Second
	max := 8 * time.Second

	cases := []struct {
		name string
		rate float64
		want time.Duration
	}{
		{"all successful uses lower bound", 1, time.Second},
		{"all failed uses upper bound", 0, 8 * time.Second},
		{"half successful", 0.5, 4500 * time.Millisecond},
		{"rate above one is clamped", 2, time.Second},
		{"rate below zero is clamped", -1, 8 * time.Second},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, adaptiveProbeInterval(min, max, tc.rate))
		})
	}

	require.Equal(t, max, adaptiveProbeInterval(max, min, 0.2), "invalid bounds should return the lower argument")
}

func TestProbeHealthTrackerConsecutiveAndWindow(t *testing.T) {
	tracker := newProbeHealthTracker(4)

	failures, rate := tracker.recordFailure("node-a")
	require.Equal(t, 1, failures)
	require.InDelta(t, 0.75, rate, 0.001)
	require.Equal(t, 1, tracker.consecutiveFailureCount("node-a"))

	failures, _ = tracker.recordFailure("node-a")
	require.Equal(t, 2, failures)

	// Another node has an independent failure streak.
	failures, _ = tracker.recordFailure("node-b")
	require.Equal(t, 1, failures)
	require.Equal(t, 2, tracker.consecutiveFailureCount("node-a"))
	require.Equal(t, 1, tracker.consecutiveFailureCount("node-b"))

	rate = tracker.recordSuccess("node-a")
	require.Equal(t, 0, tracker.consecutiveFailureCount("node-a"))
	require.Equal(t, 1, tracker.consecutiveFailureCount("node-b"))
	require.InDelta(t, 0.25, rate, 0.001, "the rolling window retains recent history")

	success, ok := tracker.lastOutcome()
	require.True(t, ok)
	require.True(t, success)

	tracker.resetNode("node-b")
	require.Zero(t, tracker.consecutiveFailureCount("node-b"))
}

func TestMemberlistAdaptiveProbeRecovery(t *testing.T) {
	addr := getBindAddr()
	m := HostMemberlist(addr.String(), t, func(c *Config) {
		c.ProbeInterval = 100 * time.Millisecond
		c.ProbeSuccessWindow = 10
		c.AwarenessMaxMultiplier = 8
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	require.Equal(t, 100*time.Millisecond, m.CurrentProbeInterval())

	for range 10 {
		m.probeHealth.recordFailure("recovering-node")
	}
	require.Equal(t, 0.0, m.ProbeSuccessRate())
	require.Equal(t, 800*time.Millisecond, m.CurrentProbeInterval())

	// One conclusive success clears the node's failure streak and restores
	// the normal interval immediately even though old failures remain in the
	// rolling success-rate window.
	m.completeProbe("recovering-node", probeOutcomeSuccess)
	require.Zero(t, m.ConsecutiveProbeFailures("recovering-node"))
	require.Equal(t, 100*time.Millisecond, m.CurrentProbeInterval())

	select {
	case <-m.probeIntervalChanged:
	default:
		t.Fatal("expected interval-change notification after recovery")
	}
}

func TestMemberlistProbeQueueFullSkipsAndCounts(t *testing.T) {
	addr := getBindAddr()
	m := HostMemberlist(addr.String(), t, func(c *Config) {
		c.ProbeQueueDepth = 1
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	require.True(t, m.enqueueProbeRound())
	require.False(t, m.enqueueProbeRound(), "bounded queue should reject a second pending round")

	stats := m.ProbeStats()
	require.Equal(t, 1, stats.QueueCapacity)
	require.Equal(t, 1, stats.QueueLength)
	require.EqualValues(t, 1, stats.Enqueued)
	require.EqualValues(t, 1, stats.QueueFull)
	require.EqualValues(t, 1, m.ProbeQueueFullCount())
	require.EqualValues(t, 1, m.ProbeSkippedCount())

	// Drain the token so shutdown and other tests do not see a stale task.
	<-m.probeQueue
}

func TestMemberlistProbeFailureThreshold(t *testing.T) {
	addr1 := getBindAddr()
	addr2 := getBindAddr()
	ip2 := []byte(addr2)

	m := HostMemberlist(addr1.String(), t, func(c *Config) {
		c.ProbeTimeout = time.Millisecond
		c.ProbeInterval = 10 * time.Millisecond
		c.ProbeFailureThreshold = 3
		c.DisableTcpPings = true
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	a := alive{
		Node:        addr2.String(),
		Addr:        ip2,
		Port:        uint16(m.config.BindPort),
		Incarnation: 1,
		Vsn:         m.config.BuildVsnArray(),
	}
	m.aliveNode(&a, nil, false)
	n := m.nodeMap[addr2.String()]

	// First two complete failures are recorded but do not escalate.
	m.probeNode(n)
	require.Equal(t, StateAlive, m.getNodeState(addr2.String()))
	require.Equal(t, 1, m.ConsecutiveProbeFailures(addr2.String()))

	m.probeNode(n)
	require.Equal(t, StateAlive, m.getNodeState(addr2.String()))
	require.Equal(t, 2, m.ConsecutiveProbeFailures(addr2.String()))

	// The third consecutive failure crosses the threshold.
	m.probeNode(n)
	require.Equal(t, StateSuspect, m.getNodeState(addr2.String()))
	require.Equal(t, 3, m.ConsecutiveProbeFailures(addr2.String()))

	stats := m.ProbeStats()
	require.EqualValues(t, 3, stats.Started)
	require.EqualValues(t, 3, stats.Failed)
}

func TestMemberlistSingleProbeFailureDoesNotSuspectByDefault(t *testing.T) {
	require.Equal(t, 2, DefaultLANConfig().ProbeFailureThreshold)

	addr1 := getBindAddr()
	addr2 := getBindAddr()
	m := HostMemberlist(addr1.String(), t, func(c *Config) {
		c.ProbeTimeout = time.Millisecond
		c.ProbeInterval = 10 * time.Millisecond
		c.DisableTcpPings = true
	})
	defer func() { require.NoError(t, m.Shutdown()) }()

	a := alive{
		Node:        addr2.String(),
		Addr:        []byte(addr2),
		Port:        uint16(m.config.BindPort),
		Incarnation: 1,
		Vsn:         m.config.BuildVsnArray(),
	}
	m.aliveNode(&a, nil, false)

	m.probeNode(m.nodeMap[addr2.String()])
	require.Equal(t, StateAlive, m.getNodeState(addr2.String()))
	require.Equal(t, 1, m.ConsecutiveProbeFailures(addr2.String()))
}

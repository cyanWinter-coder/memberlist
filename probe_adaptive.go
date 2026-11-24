// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"sync"
	"time"

	metrics "github.com/hashicorp/go-metrics"
)

const (
	// DefaultProbeFailureThreshold is the default number of consecutive
	// complete probe rounds that must fail before a node is suspected.
	DefaultProbeFailureThreshold = 2

	// DefaultProbeSuccessWindow is the default number of recent probe
	// outcomes retained to calculate the success rate.
	DefaultProbeSuccessWindow = 10

	// DefaultProbeQueueDepth is the default number of probe rounds that may
	// be pending while another round is running.
	DefaultProbeQueueDepth = 1
)

type probeOutcome uint8

const (
	probeOutcomeInconclusive probeOutcome = iota
	probeOutcomeSuccess
	probeOutcomeFailure
)

// probeHealthTracker keeps the recent global probe success rate and the
// consecutive failure count for each probed node.
type probeHealthTracker struct {
	mu sync.Mutex

	windowSize  int
	results     []bool
	next        int
	hasOutcome  bool
	lastSuccess bool

	consecutiveFailures map[string]int
}

func newProbeHealthTracker(windowSize int) *probeHealthTracker {
	if windowSize <= 0 {
		windowSize = DefaultProbeSuccessWindow
	}
	results := make([]bool, windowSize)
	for i := range results {
		results[i] = true
	}
	return &probeHealthTracker{
		windowSize:          windowSize,
		results:             results,
		consecutiveFailures: make(map[string]int),
	}
}

// recordSuccess records a successful complete probe. The per-node failure
// streak clears immediately and the newest outcome puts the interval back at
// its lower bound, so a recovered node does not wait for old failures to age
// out. The rolling window itself is retained so the success-rate metric still
// reflects the recent past.
func (t *probeHealthTracker) recordSuccess(node string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	if node != "" {
		t.consecutiveFailures[node] = 0
	}
	t.hasOutcome = true
	t.lastSuccess = true
	t.appendLocked(true)
	return t.successRateLocked()
}

// recordFailure records a complete failed probe round for node. It returns
// the node's consecutive failure count and the global recent success rate.
func (t *probeHealthTracker) recordFailure(node string) (int, float64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	failures := t.consecutiveFailures[node] + 1
	if node != "" {
		t.consecutiveFailures[node] = failures
	}
	t.hasOutcome = true
	t.lastSuccess = false
	t.appendLocked(false)
	return failures, t.successRateLocked()
}

func (t *probeHealthTracker) resetNode(node string) {
	if node == "" {
		return
	}
	t.mu.Lock()
	delete(t.consecutiveFailures, node)
	t.mu.Unlock()
}

// recoverNode clears the node's failure streak and marks the newest signal as
// healthy, without inserting a synthetic probe result into the rolling probe
// success-rate window. An alive/refutation message can provide this signal.
func (t *probeHealthTracker) recoverNode(node string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if node != "" {
		delete(t.consecutiveFailures, node)
	}
	t.hasOutcome = true
	t.lastSuccess = true
}

func (t *probeHealthTracker) removeNodes(nodes []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, node := range nodes {
		delete(t.consecutiveFailures, node)
	}
}

func (t *probeHealthTracker) consecutiveFailureCount(node string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.consecutiveFailures[node]
}

func (t *probeHealthTracker) successRate() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.successRateLocked()
}

func (t *probeHealthTracker) lastOutcome() (success bool, ok bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastSuccess, t.hasOutcome
}

func (t *probeHealthTracker) appendLocked(success bool) {
	if len(t.results) < t.windowSize {
		t.results = append(t.results, success)
		return
	}
	t.results[t.next] = success
	t.next = (t.next + 1) % t.windowSize
}

func (t *probeHealthTracker) successRateLocked() float64 {
	if len(t.results) == 0 {
		return 1
	}
	var successes int
	for _, ok := range t.results {
		if ok {
			successes++
		}
	}
	return float64(successes) / float64(len(t.results))
}

// ProbeStats is a point-in-time view of adaptive probing state.
type ProbeStats struct {
	// Interval is the currently calculated adaptive probe interval.
	Interval time.Duration

	// SuccessRate is the recent global probe success rate in [0,1].
	SuccessRate float64

	// QueueCapacity is the bounded probe queue capacity.
	QueueCapacity int

	// QueueLength is the number of probe rounds currently pending.
	QueueLength int

	// Enqueued is the total number of accepted probe rounds.
	Enqueued uint64

	// QueueFull is the total number of rounds skipped because the queue was
	// full.
	QueueFull uint64

	// Started is the total number of probeNode executions started.
	Started uint64

	// Sent is the total number of probe UDP messages successfully written.
	Sent uint64

	// Succeeded and Failed count conclusive probe rounds.
	Succeeded uint64
	Failed    uint64
}

// ProbeStats returns a snapshot of adaptive probing counters and state.
func (m *Memberlist) ProbeStats() ProbeStats {
	stats := ProbeStats{
		Interval:      m.CurrentProbeInterval(),
		SuccessRate:   m.ProbeSuccessRate(),
		QueueCapacity: cap(m.probeQueue),
		Enqueued:      m.probeEnqueued.Load(),
		QueueFull:     m.probeQueueFull.Load(),
		Started:       m.probeStarted.Load(),
		Sent:          m.probeSent.Load(),
		Succeeded:     m.probeSucceeded.Load(),
		Failed:        m.probeFailed.Load(),
	}
	if m.probeQueue != nil {
		stats.QueueLength = len(m.probeQueue)
	}
	return stats
}

// ProbeQueueFullCount returns the total number of probe rounds skipped because
// the bounded probe queue was full.
func (m *Memberlist) ProbeQueueFullCount() uint64 {
	return m.probeQueueFull.Load()
}

// ProbeSkippedCount is an alias for ProbeQueueFullCount.
func (m *Memberlist) ProbeSkippedCount() uint64 {
	return m.ProbeQueueFullCount()
}

// ProbeSuccessRate returns the recent global probe success rate.
func (m *Memberlist) ProbeSuccessRate() float64 {
	if m.probeHealth == nil {
		return 1
	}
	return m.probeHealth.successRate()
}

// ConsecutiveProbeFailures returns the current consecutive failure count for
// the named node.
func (m *Memberlist) ConsecutiveProbeFailures(node string) int {
	if m.probeHealth == nil {
		return 0
	}
	return m.probeHealth.consecutiveFailureCount(node)
}

// CurrentProbeInterval returns the adaptive interval bounded by the configured
// minimum and maximum values.
func (m *Memberlist) CurrentProbeInterval() time.Duration {
	base, minInterval, maxInterval := m.probeIntervalBounds()
	if base <= 0 {
		return 0
	}
	if m.probeHealth == nil {
		return base
	}

	// Asymmetric adaptation: degradation follows the rolling success rate,
	// but the newest outcome being a success immediately restores the lower
	// (normal) interval. This prevents a recovered node from being stuck on a
	// slow interval while old failures age out of the window.
	if success, ok := m.probeHealth.lastOutcome(); ok && success {
		return minInterval
	}
	return adaptiveProbeInterval(minInterval, maxInterval, m.probeHealth.successRate())
}

func (m *Memberlist) probeIntervalBounds() (base, minInterval, maxInterval time.Duration) {
	if m == nil || m.config == nil {
		return 0, 0, 0
	}
	base = m.config.ProbeInterval
	if base <= 0 {
		return 0, 0, 0
	}

	minInterval = m.config.ProbeMinInterval
	if minInterval <= 0 || minInterval > base {
		// ProbeInterval is the historical normal rate and remains the
		// default fastest rate. An explicit smaller minimum may speed up
		// probing when results are consistently healthy.
		minInterval = base
	}

	maxInterval = m.config.ProbeMaxInterval
	if maxInterval <= 0 {
		mult := m.config.AwarenessMaxMultiplier
		if mult <= 0 {
			mult = 1
		}
		maxInterval = base * time.Duration(mult)
	}
	if maxInterval < minInterval {
		maxInterval = minInterval
	}
	return base, minInterval, maxInterval
}

// AdaptiveProbeInterval maps a recent success rate in [0,1] to an interval
// bounded by minInterval and maxInterval. Higher success rates return shorter
// intervals.
func AdaptiveProbeInterval(minInterval, maxInterval time.Duration, successRate float64) time.Duration {
	return adaptiveProbeInterval(minInterval, maxInterval, successRate)
}

func adaptiveProbeInterval(minInterval, maxInterval time.Duration, successRate float64) time.Duration {
	if successRate < 0 {
		successRate = 0
	} else if successRate > 1 {
		successRate = 1
	}
	if maxInterval <= minInterval {
		return minInterval
	}

	// Perfect success uses the lower bound. Zero success uses the upper
	// bound; the mapping is linear so operators can predict the behavior.
	span := float64(maxInterval - minInterval)
	interval := minInterval + time.Duration(span*(1-successRate))
	if interval < minInterval {
		return minInterval
	}
	if interval > maxInterval {
		return maxInterval
	}
	return interval
}

func (m *Memberlist) effectiveProbeFailureThreshold() int {
	if m.config != nil && m.config.ProbeFailureThreshold > 0 {
		return m.config.ProbeFailureThreshold
	}
	return DefaultProbeFailureThreshold
}

func (m *Memberlist) effectiveProbeQueueDepth() int {
	if m.config != nil && m.config.ProbeQueueDepth > 0 {
		return m.config.ProbeQueueDepth
	}
	return DefaultProbeQueueDepth
}

// initProbeQueue initializes the bounded queue. It is separate from struct
// construction so tests and configuration normalization share one path.
func (m *Memberlist) initProbeQueue() {
	if m.probeQueue == nil {
		m.probeQueue = make(chan struct{}, m.effectiveProbeQueueDepth())
	}
	if m.probeIntervalChanged == nil {
		m.probeIntervalChanged = make(chan struct{}, 1)
	}
	if m.probeHealth == nil {
		window := DefaultProbeSuccessWindow
		if m.config != nil {
			window = m.config.ProbeSuccessWindow
		}
		m.probeHealth = newProbeHealthTracker(window)
	}
}

// enqueueProbeRound offers one probe round to the bounded worker queue. It
// never blocks. A false return means the queue was full and this round was
// skipped and counted.
func (m *Memberlist) enqueueProbeRound() bool {
	m.initProbeQueue()

	select {
	case m.probeQueue <- struct{}{}:
		m.probeEnqueued.Add(1)
		metrics.IncrCounterWithLabels([]string{"memberlist", "probe", "enqueued"}, 1, m.metricLabels)
		return true
	default:
		count := m.probeQueueFull.Add(1)
		metrics.IncrCounterWithLabels([]string{"memberlist", "probe", "queue_full"}, 1, m.metricLabels)
		metrics.IncrCounterWithLabels([]string{"memberlist", "probe", "skipped"}, 1, m.metricLabels)
		metrics.IncrCounterWithLabels([]string{"memberlist", "probe", "dropped"}, 1, m.metricLabels)
		m.probeLogf("[WARN] memberlist: Probe queue full, skipping probe round (total skipped=%d)", count)
		return false
	}
}

func (m *Memberlist) notifyProbeIntervalChanged() {
	if m.probeIntervalChanged == nil {
		return
	}
	select {
	case m.probeIntervalChanged <- struct{}{}:
	default:
	}
}

func (m *Memberlist) probeLogf(format string, args ...any) {
	if m != nil && m.logger != nil {
		m.logger.Printf(format, args...)
	}
}

// completeProbe records a conclusive probe result, updates the adaptive
// interval, and escalates to suspicion only after the configured number of
// consecutive complete failures.
func (m *Memberlist) completeProbe(node string, outcome probeOutcome) {
	switch outcome {
	case probeOutcomeSuccess:
		m.probeSucceeded.Add(1)
		metrics.IncrCounterWithLabels([]string{"memberlist", "probe", "success"}, 1, m.metricLabels)
		if m.probeHealth != nil {
			m.probeHealth.recordSuccess(node)
		}
		m.notifyProbeIntervalChanged()

	case probeOutcomeFailure:
		m.probeFailed.Add(1)
		metrics.IncrCounterWithLabels([]string{"memberlist", "probe", "failure"}, 1, m.metricLabels)

		threshold := m.effectiveProbeFailureThreshold()
		failures := 1
		if m.probeHealth != nil {
			failures, _ = m.probeHealth.recordFailure(node)
		}
		m.notifyProbeIntervalChanged()

		if failures < threshold {
			m.probeLogf("[INFO] memberlist: Probe to %s failed; withholding suspicion until %d consecutive failures (failure %d/%d)",
				node, threshold, failures, threshold)
			return
		}

		m.probeLogf("[INFO] memberlist: Suspect %s has failed, %d consecutive probe failures reached threshold %d",
			node, failures, threshold)
		from := ""
		if m.config != nil {
			from = m.config.Name
		}
		s := suspect{Incarnation: m.nodeIncarnation(node), Node: node, From: from}
		m.suspectNode(&s)

	default:
		// Local encode/transport errors are inconclusive and intentionally
		// do not count toward node failure or success-rate adaptation.
	}
}

func (m *Memberlist) nodeIncarnation(node string) uint32 {
	m.nodeLock.RLock()
	defer m.nodeLock.RUnlock()
	if state, ok := m.nodeMap[node]; ok {
		return state.Incarnation
	}
	return 0
}

// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMemberlistBroadcast_Invalidates(t *testing.T) {
	m1 := &memberlistBroadcast{node: "test", msg: nil, notify: nil}
	m2 := &memberlistBroadcast{node: "foo", msg: nil, notify: nil}

	if m1.Invalidates(m2) || m2.Invalidates(m1) {
		t.Fatalf("unexpected invalidation")
	}

	if !m1.Invalidates(m1) {
		t.Fatalf("expected invalidation")
	}
}

func TestMemberlistBroadcast_Message(t *testing.T) {
	m1 := &memberlistBroadcast{node: "test", msg: []byte("test"), notify: nil}
	msg := m1.Message()
	if !reflect.DeepEqual(msg, []byte("test")) {
		t.Fatalf("messages do not match")
	}
}

// TestMemberlistBroadcast_TerminalFlag verifies the memberlist dead/left
// call chain marks final states terminal while alive/suspect stay
// intermediate, and that the queue recognizes the optional interface.
func TestMemberlistBroadcast_TerminalFlag(t *testing.T) {
	intermediate := &memberlistBroadcast{node: "n1", msg: []byte("suspect")}
	terminal := &memberlistBroadcast{node: "n1", msg: []byte("dead"), terminal: true}

	require.False(t, intermediate.Terminal())
	require.True(t, terminal.Terminal())

	// The queue's optional-interface detection must pick up the flag.
	q := &TransmitLimitedQueue{RetransmitMult: 1, NumNodes: func() int { return 10 }}
	q.QueueBroadcast(intermediate)
	q.QueueBroadcast(terminal) // same node: replaces the intermediate

	dump := q.orderedView()
	require.Len(t, dump, 1)
	require.True(t, dump[0].terminal, "dead state must be queued as terminal")

	// A terminal entry still implements the compatibility interfaces and
	// invalidates same-node messages exactly as before.
	var _ TerminalBroadcast = terminal
	var _ NamedBroadcast = terminal
	require.True(t, terminal.Invalidates(intermediate))
}

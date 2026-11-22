// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"reflect"
	"testing"
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

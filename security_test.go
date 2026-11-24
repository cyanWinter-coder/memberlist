// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestPKCS7(t *testing.T) {
	for i := 0; i <= 255; i++ {
		// Make a buffer of size i
		buf := []byte{}
		for j := 0; j < i; j++ {
			buf = append(buf, byte(i))
		}

		// Copy to bytes buffer
		inp := bytes.NewBuffer(nil)
		inp.Write(buf)

		// Pad this out
		pkcs7encode(inp, 0, 16)

		// Unpad
		dec := pkcs7decode(inp.Bytes(), 16)

		// Ensure equivilence
		if !reflect.DeepEqual(buf, dec) {
			t.Fatalf("mismatch: %v %v", buf, dec)
		}
	}

}

func TestEncryptDecrypt_V0(t *testing.T) {
	encryptDecryptVersioned(0, t)
}

func TestEncryptDecrypt_V1(t *testing.T) {
	encryptDecryptVersioned(1, t)
}

func encryptDecryptVersioned(vsn encryptionVersion, t *testing.T) {
	k1 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	plaintext := []byte("this is a plain text message")
	extra := []byte("random data")

	var buf bytes.Buffer
	err := encryptPayload(vsn, k1, plaintext, extra, &buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	expLen := encryptedLength(vsn, len(plaintext))
	if buf.Len() != expLen {
		t.Fatalf("output length is unexpected %d %d %d", len(plaintext), buf.Len(), expLen)
	}

	msg, err := decryptPayload([][]byte{k1}, buf.Bytes(), extra)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	cmp := bytes.Compare(msg, plaintext)
	if cmp != 0 {
		t.Errorf("len %d %v", len(msg), msg)
		t.Errorf("len %d %v", len(plaintext), plaintext)
		t.Fatalf("encrypt/decrypt failed! %d '%s' '%s'", cmp, msg, plaintext)
	}
}

func TestDecryptPayload_RotationWindow(t *testing.T) {
	// During a rotation both the outgoing key and the incoming key are
	// installed. Messages from either generation must decrypt, and the
	// order of keys on the ring must not matter for decryption.
	plaintext := []byte("rotation window message")
	extra := []byte("auth data")

	oldKey, newKey := TestKeys[0], TestKeys[1]
	ring := [][]byte{newKey, oldKey}

	for name, key := range map[string][]byte{"old": oldKey, "new": newKey} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := encryptPayload(1, key, plaintext, extra, &buf); err != nil {
				t.Fatalf("err: %v", err)
			}
			plain, err := decryptPayload(ring, buf.Bytes(), extra)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !bytes.Equal(plain, plaintext) {
				t.Fatalf("bad: %v", plain)
			}
		})
	}

	// Once the old key is retired, only the new generation decrypts. Old
	// messages must now fail with an identifiable mismatch error.
	if _, err := decryptPayload([][]byte{newKey}, mustEncrypt(t, oldKey, plaintext, extra), extra); err == nil {
		t.Fatalf("expected old key to be rejected")
	}
}

func TestDecryptPayload_KeyMismatchError(t *testing.T) {
	plaintext := []byte("hello")
	extra := []byte("auth")

	// A key that is not installed on the decrypting side.
	senderKey := TestKeys[2]
	installed := [][]byte{TestKeys[0], TestKeys[1]}

	msg := mustEncrypt(t, senderKey, plaintext, extra)
	_, err := decryptPayload(installed, msg, extra)
	if err == nil {
		t.Fatalf("expected key mismatch error")
	}

	// The error is identifiable without string matching.
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected errors.Is(err, ErrKeyMismatch), got: %v", err)
	}

	var mismatch *KeyMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("expected *KeyMismatchError, got %T", err)
	}

	// It names the key generations that were tried, in order.
	wantTried := []KeyID{KeyIDForKey(TestKeys[0]), KeyIDForKey(TestKeys[1])}
	if !reflect.DeepEqual(mismatch.TriedKeyIDs, wantTried) {
		t.Fatalf("tried ids %v, want %v", mismatch.TriedKeyIDs, wantTried)
	}
	for _, id := range wantTried {
		if !strings.Contains(err.Error(), id.String()) {
			t.Fatalf("error %q does not name tried key id %s", err, id)
		}
	}

	// It must never carry key material.
	for _, key := range append(installed, senderKey) {
		if bytes.Contains([]byte(err.Error()), key) {
			t.Fatalf("error leaks key material: %v", err)
		}
	}
}

func TestDecryptPayload_KeyMismatchEmptyRing(t *testing.T) {
	msg := mustEncrypt(t, TestKeys[0], []byte("hello"), nil)

	_, err := decryptPayload(nil, msg, nil)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected ErrKeyMismatch, got: %v", err)
	}
	if !strings.Contains(err.Error(), "no keys are installed") {
		t.Fatalf("expected empty-ring explanation, got: %v", err)
	}
}

func TestDecryptPayload_TamperedPayloadIsKeyMismatch(t *testing.T) {
	// A corrupted tag is indistinguishable from a wrong key for the
	// receiver, and must be reported the same identifiable way.
	msg := mustEncrypt(t, TestKeys[0], []byte("hello"), nil)
	msg[len(msg)-1] ^= 0xff

	_, err := decryptPayload(TestKeys, msg, nil)
	if !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("expected ErrKeyMismatch, got: %v", err)
	}
}

func TestKeyIDForKey(t *testing.T) {
	// Identifiers are derived deterministically from the key, so every node
	// computes the same value, and distinct keys get distinct identifiers.
	id := KeyIDForKey(TestKeys[0])
	if id != KeyIDForKey(TestKeys[0]) {
		t.Fatalf("key id is not deterministic")
	}
	if id == KeyIDForKey(TestKeys[1]) {
		t.Fatalf("distinct keys share a key id")
	}
	if len(id.String()) != 2*keyIDSize {
		t.Fatalf("unexpected key id rendering %q", id.String())
	}
}

// mustEncrypt encrypts with the current (version 1) wire format and returns
// the payload, failing the test on encryption errors.
func mustEncrypt(t *testing.T, key, plaintext, extra []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := encryptPayload(1, key, plaintext, extra, &buf); err != nil {
		t.Fatalf("err: %v", err)
	}
	return buf.Bytes()
}

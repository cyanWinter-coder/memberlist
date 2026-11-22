// Copyright IBM Corp. 2013, 2025
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bytes"
	"reflect"
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

func TestEncryptDecrypt_V2(t *testing.T) {
	encryptDecryptVersioned(2, t)
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

// encryptV2 is a helper that encrypts a message in the version-2 format.
func encryptV2(t *testing.T, key, plaintext, extra []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := encryptPayload(2, key, plaintext, extra, &buf); err != nil {
		t.Fatalf("err: %v", err)
	}
	return buf.Bytes()
}

func TestEncryptPayload_V2_HeaderLayout(t *testing.T) {
	key := TestKeys[0]
	msg := encryptV2(t, key, []byte("hello"), nil)

	if encryptionVersion(msg[0]) != 2 {
		t.Fatalf("expected version 2, got %d", msg[0])
	}
	var id KeyID
	copy(id[:], msg[versionSize:headerSize(2)])
	if id != KeyIDForKey(key) {
		t.Fatalf("message carries key id %s, want %s", id, KeyIDForKey(key))
	}
	if len(msg) != encryptedLength(2, len("hello")) {
		t.Fatalf("unexpected length %d", len(msg))
	}
	if encryptOverhead(2) != encryptedLength(2, 0) {
		t.Fatalf("overhead %d != empty message length %d", encryptOverhead(2), encryptedLength(2, 0))
	}
}

func TestDecryptPayload_UnsupportedVersion(t *testing.T) {
	msg := encryptV2(t, TestKeys[0], []byte("hello"), nil)
	msg[0] = byte(maxEncryptionVersion + 1)

	_, err := decryptPayload(TestKeys, msg, nil)
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("unsupported encryption version")) {
		t.Fatalf("expected explicit unsupported version error, got: %v", err)
	}
}

func TestDecryptPayload_V2_UnknownKeyID(t *testing.T) {
	// Message encrypted with a key that is not installed on the ring.
	msg := encryptV2(t, TestKeys[2], []byte("hello"), nil)

	_, err := decryptPayload(TestKeys[:2], msg, nil)
	if err == nil {
		t.Fatalf("expected error for unknown key id")
	}

	// The error must name the missing key generation so an operator can
	// tell which key a node is missing...
	want := "no installed key matches key id " + KeyIDForKey(TestKeys[2]).String()
	if !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Fatalf("error %q does not name the missing key id, want %q", err, want)
	}

	// ...but it must never leak key material.
	if bytes.Contains([]byte(err.Error()), TestKeys[2]) {
		t.Fatalf("error leaks key material: %v", err)
	}
}

func TestDecryptPayload_V2_AuthenticationFailure(t *testing.T) {
	msg := encryptV2(t, TestKeys[0], []byte("hello"), nil)

	// Corrupt the ciphertext; the named key is installed but the GCM tag
	// must fail to verify.
	msg[len(msg)-1] ^= 0xff

	_, err := decryptPayload(TestKeys, msg, nil)
	want := "message authentication failed for key id " + KeyIDForKey(TestKeys[0]).String()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Fatalf("expected explicit authentication error, got: %v", err)
	}
}

func TestDecryptPayload_V2_RotationWindow(t *testing.T) {
	plaintext := []byte("rotation window message")
	extra := []byte("auth data")

	oldKey, newKey := TestKeys[0], TestKeys[1]

	// Rotation window: both the old and the new primary are installed.
	// Messages from either generation must decrypt.
	keyring, err := NewKeyring([][]byte{oldKey}, newKey)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	oldMsg := encryptV2(t, oldKey, plaintext, extra)
	newMsg := encryptV2(t, newKey, plaintext, extra)

	for i, msg := range [][]byte{oldMsg, newMsg} {
		plain, err := decryptPayload(keyring.GetKeys(), msg, extra)
		if err != nil {
			t.Fatalf("msg %d: err: %v", i, err)
		}
		if !bytes.Equal(plain, plaintext) {
			t.Fatalf("msg %d: bad: %v", i, plain)
		}
	}

	// Writes always use the current primary key: encrypting with the key
	// the ring reports as primary must produce the new key's id.
	written := encryptV2(t, keyring.GetPrimaryKey(), plaintext, extra)
	var id KeyID
	copy(id[:], written[versionSize:headerSize(2)])
	if id != KeyIDForKey(newKey) {
		t.Fatalf("write used key id %s, want primary %s", id, KeyIDForKey(newKey))
	}

	// End of the window: the old key is removed. Old-generation messages
	// now fail with an explicit error naming the retired key id, while
	// new-generation messages keep flowing.
	if err := keyring.RemoveKey(oldKey); err != nil {
		t.Fatalf("err: %v", err)
	}
	if _, err := decryptPayload(keyring.GetKeys(), oldMsg, extra); err == nil {
		t.Fatalf("expected explicit error for retired key id")
	}
	plain, err := decryptPayload(keyring.GetKeys(), newMsg, extra)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(plain, plaintext) {
		t.Fatalf("bad: %v", plain)
	}
}

func TestDecryptPayload_V2_LegacyFormatsStillAccepted(t *testing.T) {
	// A node that sends versioned messages must still accept legacy
	// version 0/1 traffic from peers that have not been upgraded yet.
	plaintext := []byte("legacy interop")
	extra := []byte("extra")

	for vsn := encryptionVersion(0); vsn <= 1; vsn++ {
		var buf bytes.Buffer
		if err := encryptPayload(vsn, TestKeys[1], plaintext, extra, &buf); err != nil {
			t.Fatalf("vsn %d: err: %v", vsn, err)
		}
		plain, err := decryptPayload(TestKeys, buf.Bytes(), extra)
		if err != nil {
			t.Fatalf("vsn %d: err: %v", vsn, err)
		}
		if !bytes.Equal(plain, plaintext) {
			t.Fatalf("vsn %d: bad: %v", vsn, plain)
		}
	}
}

func TestEncryptionVersionSelection(t *testing.T) {
	cases := []struct {
		name     string
		protocol uint8
		disable  bool
		want     encryptionVersion
	}{
		{"protocol 1 keeps padded legacy format", 1, false, 0},
		{"protocol 1 ignores the compat flag", 1, true, 0},
		{"modern protocol uses key-versioned format", 2, false, 2},
		{"compat flag forces legacy format for old peers", 2, true, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &Memberlist{config: &Config{
				ProtocolVersion:         tc.protocol,
				DisableKeyVersionHeader: tc.disable,
			}}
			if got := m.encryptionVersion(); got != tc.want {
				t.Fatalf("got version %d, want %d", got, tc.want)
			}
		})
	}
}

// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bytes"
	"sync"
	"testing"
)

var TestKeys [][]byte = [][]byte{
	[]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	[]byte{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	[]byte{8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7},
}

func TestKeyring_EmptyRing(t *testing.T) {
	// Keyrings can be created with no encryption keys (disabled encryption)
	keyring, err := NewKeyring(nil, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	keys := keyring.GetKeys()
	if len(keys) != 0 {
		t.Fatalf("Expected 0 keys but have %d", len(keys))
	}
}

func TestKeyring_PrimaryOnly(t *testing.T) {
	// Keyrings can be created using only a primary key
	keyring, err := NewKeyring(nil, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	keys := keyring.GetKeys()
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key but have %d", len(keys))
	}
}

func TestKeyring_GetPrimaryKey(t *testing.T) {
	keyring, err := NewKeyring(TestKeys, TestKeys[1])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// GetPrimaryKey returns correct key
	primaryKey := keyring.GetPrimaryKey()
	if !bytes.Equal(primaryKey, TestKeys[1]) {
		t.Fatalf("Unexpected primary key: %v", primaryKey)
	}
}

func TestKeyring_AddRemoveUse(t *testing.T) {
	keyring, err := NewKeyring(nil, TestKeys[1])
	if err != nil {
		t.Fatalf("err :%s", err)
	}

	// Use non-existent key throws error
	if err := keyring.UseKey(TestKeys[2]); err == nil {
		t.Fatalf("Expected key not installed error")
	}

	// Add key to ring
	if err := keyring.AddKey(TestKeys[2]); err != nil {
		t.Fatalf("err: %s", err)
	}

	keys := keyring.GetKeys()
	if !bytes.Equal(keys[0], TestKeys[1]) {
		t.Fatalf("Unexpected primary key change")
	}

	if len(keys) != 2 {
		t.Fatalf("Expected 2 keys but have %d", len(keys))
	}

	// Use key that exists should succeed
	if err := keyring.UseKey(TestKeys[2]); err != nil {
		t.Fatalf("err: %s", err)
	}

	primaryKey := keyring.GetPrimaryKey()
	if !bytes.Equal(primaryKey, TestKeys[2]) {
		t.Fatalf("Unexpected primary key: %v", primaryKey)
	}

	// Removing primary key should fail
	if err := keyring.RemoveKey(TestKeys[2]); err == nil {
		t.Fatalf("Expected primary key removal error")
	}

	// Removing non-primary key should succeed
	if err := keyring.RemoveKey(TestKeys[1]); err != nil {
		t.Fatalf("err: %s", err)
	}

	keys = keyring.GetKeys()
	if len(keys) != 1 {
		t.Fatalf("Expected 1 key but have %d", len(keys))
	}
}

func TestKeyRing_MultiKeyEncryptDecrypt(t *testing.T) {
	plaintext := []byte("this is a plain text message")
	extra := []byte("random data")

	keyring, err := NewKeyring(TestKeys, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// First encrypt using the primary key and make sure we can decrypt
	var buf bytes.Buffer
	err = encryptPayload(1, TestKeys[0], plaintext, extra, &buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	msg, err := decryptPayload(keyring.GetKeys(), buf.Bytes(), extra)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatalf("bad: %v", msg)
	}

	// Now encrypt with a secondary key and try decrypting again.
	buf.Reset()
	err = encryptPayload(1, TestKeys[2], plaintext, extra, &buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	msg, err = decryptPayload(keyring.GetKeys(), buf.Bytes(), extra)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Fatalf("bad: %v", msg)
	}

	// Remove a key from the ring, and then try decrypting again
	if err := keyring.RemoveKey(TestKeys[2]); err != nil {
		t.Fatalf("err: %s", err)
	}

	_, err = decryptPayload(keyring.GetKeys(), buf.Bytes(), extra)
	if err == nil {
		t.Fatalf("Expected no keys to decrypt message")
	}
}

func TestKeyring_AddConcurrentKeys(t *testing.T) {
	keyring, err := NewKeyring(nil, TestKeys[0])
	if err != nil {
		t.Fatalf("err :%s", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error)
	wg.Add(2)
	go func() {
		defer wg.Done()
		errs <- keyring.AddKey(TestKeys[1])
	}()
	go func() {
		defer wg.Done()
		errs <- keyring.AddKey(TestKeys[2])
	}()

	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestKeyring_KeyIDs(t *testing.T) {
	keyring, err := NewKeyring(TestKeys, TestKeys[1])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	ids := keyring.GetKeyIDs()
	keys := keyring.GetKeys()
	if len(ids) != len(keys) {
		t.Fatalf("have %d ids for %d keys", len(ids), len(keys))
	}
	for i := range keys {
		if ids[i] != KeyIDForKey(keys[i]) {
			t.Fatalf("id %d mismatch: %s != %s", i, ids[i], KeyIDForKey(keys[i]))
		}
	}

	// The primary key id is reported and comes first.
	primaryID, ok := keyring.GetPrimaryKeyID()
	if !ok {
		t.Fatalf("expected a primary key id")
	}
	if primaryID != KeyIDForKey(TestKeys[1]) || ids[0] != primaryID {
		t.Fatalf("unexpected primary key id: %s", primaryID)
	}

	// IDs are distinct per key and stable across calls.
	seen := map[KeyID]bool{}
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate key id %s", id)
		}
		seen[id] = true
	}
}

func TestKeyring_GetKeyByID(t *testing.T) {
	keyring, err := NewKeyring(TestKeys, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	key, ok := keyring.GetKeyByID(KeyIDForKey(TestKeys[2]))
	if !ok || !bytes.Equal(key, TestKeys[2]) {
		t.Fatalf("expected to find key by id")
	}

	unknown := KeyIDForKey([]byte("not-installed-16"))
	if _, ok := keyring.GetKeyByID(unknown); ok {
		t.Fatalf("unexpected hit for unknown key id")
	}
}

func TestKeyring_GetKeysReturnsSnapshot(t *testing.T) {
	keyring, err := NewKeyring(TestKeys, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Mutating the returned slice must not affect the ring.
	snapshot := keyring.GetKeys()
	snapshot[0] = []byte("attacker-controlled")
	if bytes.Equal(keyring.GetKeys()[0], []byte("attacker-controlled")) {
		t.Fatalf("ring was mutated through the returned snapshot")
	}

	// A snapshot taken before a rotation must remain a faithful copy of
	// the old ring afterwards (copy-on-write).
	before := keyring.GetKeys()
	if err := keyring.RemoveKey(TestKeys[2]); err != nil {
		t.Fatalf("err: %s", err)
	}
	if err := keyring.AddKey([]byte("brand-new-key-16")); err != nil {
		t.Fatalf("err: %s", err)
	}
	if len(before) != len(TestKeys) {
		t.Fatalf("snapshot length changed: %d", len(before))
	}
	for i := range TestKeys {
		if !bytes.Equal(before[i], TestKeys[i]) {
			t.Fatalf("snapshot element %d changed after rotation", i)
		}
	}
}

func TestKeyring_FailedUpdateKeepsOldRing(t *testing.T) {
	keyring, err := NewKeyring(nil, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	before := keyring.GetKeys()

	// Invalid key material: rejected, ring unchanged, safe to retry.
	if err := keyring.AddKey([]byte("too-short")); err == nil {
		t.Fatalf("expected invalid key error")
	}
	// Unknown key: rejected, primary unchanged.
	if err := keyring.UseKey(TestKeys[1]); err == nil {
		t.Fatalf("expected key not installed error")
	}
	// Removing the primary: rejected, ring unchanged.
	if err := keyring.RemoveKey(TestKeys[0]); err == nil {
		t.Fatalf("expected primary key removal error")
	}

	after := keyring.GetKeys()
	if len(after) != len(before) || !bytes.Equal(after[0], before[0]) {
		t.Fatalf("ring changed after failed updates: %v -> %v", before, after)
	}

	// The same operations with valid input succeed on retry.
	if err := keyring.AddKey(TestKeys[1]); err != nil {
		t.Fatalf("err: %s", err)
	}
	if err := keyring.UseKey(TestKeys[1]); err != nil {
		t.Fatalf("err: %s", err)
	}
	if !bytes.Equal(keyring.GetPrimaryKey(), TestKeys[1]) {
		t.Fatalf("retry did not take effect")
	}
}

// TestKeyring_ConcurrentRotationDecrypt hammers the keyring with rotations
// while other goroutines take snapshots and decrypt traffic from both key
// generations. Run with -race. Decryption must either succeed or fail with
// an explicit key-id error; it must never corrupt a snapshot or panic.
func TestKeyring_ConcurrentRotationDecrypt(t *testing.T) {
	keyring, err := NewKeyring(nil, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	plaintext := []byte("concurrent rotation traffic")
	extra := []byte("auth")

	// Pre-encrypt one message per key generation.
	msgs := make([][]byte, len(TestKeys))
	for i, key := range TestKeys {
		var buf bytes.Buffer
		if err := encryptPayload(2, key, plaintext, extra, &buf); err != nil {
			t.Fatalf("err: %v", err)
		}
		msgs[i] = buf.Bytes()
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writers: rotate keys through the ring.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			key := TestKeys[i%len(TestKeys)]
			_ = keyring.AddKey(key)
			_ = keyring.UseKey(key)
			if i%3 == 0 {
				_ = keyring.RemoveKey(TestKeys[(i+2)%len(TestKeys)])
			}
		}
	}()

	// Readers: snapshot the ring and decrypt both generations.
	wg.Add(4)
	for r := 0; r < 4; r++ {
		go func(r int) {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				keys := keyring.GetKeys()
				_ = keyring.GetKeyIDs()
				_, _ = keyring.GetPrimaryKeyID()
				msg := msgs[r%len(msgs)]
				plain, err := decryptPayload(keys, msg, extra)
				if err == nil && !bytes.Equal(plain, plaintext) {
					t.Errorf("decrypted to wrong plaintext: %v", plain)
					return
				}
			}
		}(r)
	}

	// Let the writers and readers overlap, then stop.
	for i := 0; i < 1000; i++ {
		_ = keyring.GetKeys()
	}
	close(stop)
	wg.Wait()
}

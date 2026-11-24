// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bytes"
	"errors"
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

func TestKeyring_GetKeyIDs(t *testing.T) {
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

	primaryID, ok := keyring.GetPrimaryKeyID()
	if !ok || primaryID != KeyIDForKey(TestKeys[1]) || ids[0] != primaryID {
		t.Fatalf("unexpected primary key id: %s", primaryID)
	}

	// An empty ring reports no primary key id.
	empty, err := NewKeyring(nil, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if _, ok := empty.GetPrimaryKeyID(); ok {
		t.Fatalf("empty ring reported a primary key id")
	}
}

func TestKeyring_RotationSequence(t *testing.T) {
	// Walk a ring through the full rotation: install next key, promote it,
	// then retire the previous one. At every step encryption uses the
	// primary and decryption accepts every installed generation.
	oldKey, newKey := TestKeys[0], TestKeys[1]
	keyring, err := NewKeyring(nil, oldKey)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	plaintext := []byte("rotation traffic")
	extra := []byte("auth")

	around := func(msg []byte) bool {
		_, err := decryptPayload(keyring.GetKeys(), msg, extra)
		return err == nil
	}

	oldMsg := mustEncrypt(t, oldKey, plaintext, extra)

	// Before the rotation only the old generation decrypts.
	if !around(oldMsg) {
		t.Fatalf("old generation should decrypt before rotation")
	}

	// Install the next key; the primary does not change yet, so writes
	// still use the old key and both generations decrypt.
	if err := keyring.AddKey(newKey); err != nil {
		t.Fatalf("err: %s", err)
	}
	if !bytes.Equal(keyring.GetPrimaryKey(), oldKey) {
		t.Fatalf("AddKey changed the primary key")
	}
	if !around(oldMsg) || !around(mustEncrypt(t, newKey, plaintext, extra)) {
		t.Fatalf("both generations should decrypt during the window")
	}

	// Promote the new key. Writes now use it, while old traffic keeps
	// decrypting during the rollout.
	if err := keyring.UseKey(newKey); err != nil {
		t.Fatalf("err: %s", err)
	}
	if !bytes.Equal(keyring.GetPrimaryKey(), newKey) {
		t.Fatalf("UseKey did not promote the new key")
	}
	if !around(oldMsg) || !around(mustEncrypt(t, newKey, plaintext, extra)) {
		t.Fatalf("both generations should decrypt after promotion")
	}

	// Retire the old key once every node writes with the new one.
	if err := keyring.RemoveKey(oldKey); err != nil {
		t.Fatalf("err: %s", err)
	}
	if around(oldMsg) {
		t.Fatalf("retired generation should no longer decrypt")
	}
	if !around(mustEncrypt(t, newKey, plaintext, extra)) {
		t.Fatalf("new generation should still decrypt")
	}

	ids := keyring.GetKeyIDs()
	if len(ids) != 1 || ids[0] != KeyIDForKey(newKey) {
		t.Fatalf("unexpected ring after rotation: %v", ids)
	}
}

func TestKeyring_RemoveMissingKey(t *testing.T) {
	keyring, err := NewKeyring(nil, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// Removing an absent key is a no-op, and must not remove anything else
	// or panic on an empty ring.
	if err := keyring.RemoveKey(TestKeys[1]); err != nil {
		t.Fatalf("err: %s", err)
	}
	if len(keyring.GetKeys()) != 1 {
		t.Fatalf("ring changed by removing an absent key")
	}

	empty, err := NewKeyring(nil, nil)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	if err := empty.RemoveKey(TestKeys[0]); err == nil {
		t.Fatalf("expected error removing from an empty ring")
	}
}

// TestKeyring_ConcurrentRotationDecrypt rotates the ring while other
// goroutines decrypt traffic from both generations. Run with -race. Every
// decryption must either succeed with the right plaintext or fail as an
// identifiable key mismatch; it must never panic or see a mutilated ring.
func TestKeyring_ConcurrentRotationDecrypt(t *testing.T) {
	keyring, err := NewKeyring(nil, TestKeys[0])
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	plaintext := []byte("concurrent rotation traffic")
	extra := []byte("auth")

	msgs := make([][]byte, len(TestKeys))
	for i, key := range TestKeys {
		msgs[i] = mustEncrypt(t, key, plaintext, extra)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Writer: keep every key installed and rotate the primary.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			for _, key := range TestKeys {
				if err := keyring.AddKey(key); err != nil {
					t.Errorf("AddKey: %v", err)
					return
				}
			}
			if err := keyring.UseKey(TestKeys[i%len(TestKeys)]); err != nil {
				t.Errorf("UseKey: %v", err)
				return
			}
		}
	}()

	// Readers: snapshot the ring and decrypt every generation.
	wg.Add(4)
	for r := range 4 {
		go func(r int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				keys := keyring.GetKeys()
				_ = keyring.GetKeyIDs()

				plain, err := decryptPayload(keys, msgs[(r+i)%len(msgs)], extra)
				if err != nil {
					if !errors.Is(err, ErrKeyMismatch) {
						t.Errorf("unexpected decrypt error: %v", err)
						return
					}
					continue
				}
				if !bytes.Equal(plain, plaintext) {
					t.Errorf("decrypted to wrong plaintext: %v", plain)
					return
				}
			}
		}(r)
	}

	// Let writers and readers overlap for a while, then stop.
	for i := range 2000 {
		if err := keyring.AddKey(TestKeys[i%len(TestKeys)]); err != nil {
			t.Fatalf("err: %s", err)
		}
	}
	close(stop)
	wg.Wait()

	// All keys were kept installed: every generation still decrypts.
	for i, msg := range msgs {
		if _, err := decryptPayload(keyring.GetKeys(), msg, extra); err != nil {
			t.Fatalf("generation %d no longer decrypts: %v", i, err)
		}
	}
}

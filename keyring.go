// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bytes"
	"fmt"
	"sync"
)

type Keyring struct {
	// Keys stores the key data used during encryption and decryption. It is
	// ordered in such a way where the first key (index 0) is the primary key,
	// which is used for encrypting messages, and is the first key tried during
	// message decryption.
	//
	// The slice is replaced wholesale on every update (copy-on-write) and
	// never mutated in place, so a snapshot obtained via GetKeys stays
	// consistent and usable while a rotation is in progress: readers finish
	// decrypting with the old generation while writers install the new one.
	keys [][]byte

	// The keyring lock is used while performing IO operations on the keyring.
	l sync.Mutex
}

// Init allocates substructures
func (k *Keyring) init() {
	k.keys = make([][]byte, 0)
}

// NewKeyring constructs a new container for a set of encryption keys. The
// keyring contains all key data used internally by memberlist.
//
// While creating a new keyring, you must do one of:
//   - Omit keys and primary key, effectively disabling encryption
//   - Pass a set of keys plus the primary key
//   - Pass only a primary key
//
// If only a primary key is passed, then it will be automatically added to the
// keyring. If creating a keyring with multiple keys, one key must be designated
// primary by passing it as the primaryKey. If the primaryKey does not exist in
// the list of secondary keys, it will be automatically added at position 0.
//
// A key should be either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
func NewKeyring(keys [][]byte, primaryKey []byte) (*Keyring, error) {
	keyring := &Keyring{}
	keyring.init()

	if len(keys) > 0 || len(primaryKey) > 0 {
		if len(primaryKey) == 0 {
			return nil, fmt.Errorf("empty primary key not allowed")
		}
		if err := keyring.AddKey(primaryKey); err != nil {
			return nil, err
		}
		for _, key := range keys {
			if err := keyring.AddKey(key); err != nil {
				return nil, err
			}
		}
	}

	return keyring, nil
}

// ValidateKey will check to see if the key is valid and returns an error if not.
//
// key should be either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
func ValidateKey(key []byte) error {
	if l := len(key); l != 16 && l != 24 && l != 32 {
		return fmt.Errorf("key size must be 16, 24 or 32 bytes")
	}
	return nil
}

// AddKey will install a new key on the ring. Adding a key to the ring will make
// it available for use in decryption. If the key already exists on the ring,
// this function will just return noop.
//
// key should be either 16, 24, or 32 bytes to select AES-128,
// AES-192, or AES-256.
func (k *Keyring) AddKey(key []byte) error {
	if err := ValidateKey(key); err != nil {
		return err
	}

	k.l.Lock()
	defer k.l.Unlock()

	// No-op if key is already installed
	for _, installedKey := range k.keys {
		if bytes.Equal(installedKey, key) {
			return nil
		}
	}

	// Build the new ring in a fresh slice; the old ring must stay untouched
	// so that in-flight decryption snapshots are not corrupted. The update
	// only becomes visible when installKeysLocked swaps the slice, so a
	// failure anywhere before that point leaves the old ring in effect and
	// the operation can simply be retried.
	keys := make([][]byte, 0, len(k.keys)+1)
	keys = append(keys, k.keys...)
	keys = append(keys, key)
	primaryKey := k.getPrimaryKeyLocked()
	if primaryKey == nil {
		primaryKey = key
	}
	k.installKeysLocked(keys, primaryKey)
	return nil
}

// UseKey changes the key used to encrypt messages. This is the only key used to
// encrypt messages, so peers should know this key before this method is called.
func (k *Keyring) UseKey(key []byte) error {
	k.l.Lock()
	defer k.l.Unlock()
	for _, installedKey := range k.keys {
		if bytes.Equal(key, installedKey) {
			k.installKeysLocked(k.keys, key)
			return nil
		}
	}
	return fmt.Errorf("requested key is not in the keyring")
}

// RemoveKey drops a key from the keyring. This will return an error if the key
// requested for removal is currently at position 0 (primary key).
func (k *Keyring) RemoveKey(key []byte) error {
	k.l.Lock()
	defer k.l.Unlock()

	if bytes.Equal(key, k.keys[0]) {
		return fmt.Errorf("removing the primary key is not allowed")
	}
	for i, installedKey := range k.keys {
		if bytes.Equal(key, installedKey) {
			// Copy everything but the removed key into a fresh slice.
			// Mutating k.keys in place here would corrupt snapshots that
			// concurrent readers obtained via GetKeys.
			keys := make([][]byte, 0, len(k.keys)-1)
			keys = append(keys, k.keys[:i]...)
			keys = append(keys, k.keys[i+1:]...)
			k.installKeysLocked(keys, k.keys[0])
		}
	}
	return nil
}

// installKeysLocked will take out a lock on the keyring, and replace the keys with a
// new set of keys. The key indicated by primaryKey will be installed as the new
// primary key. The caller must be holding the lock.
func (k *Keyring) installKeysLocked(keys [][]byte, primaryKey []byte) {
	newKeys := [][]byte{primaryKey}
	for _, key := range keys {
		if !bytes.Equal(key, primaryKey) {
			newKeys = append(newKeys, key)
		}
	}
	k.keys = newKeys
}

// GetKeys returns the current set of keys on the ring. The returned slice
// is a snapshot: it is a copy of the ring as of this call, it is not
// affected by later rotations, and mutating it does not affect the ring.
func (k *Keyring) GetKeys() [][]byte {
	k.l.Lock()
	defer k.l.Unlock()

	keys := make([][]byte, len(k.keys))
	copy(keys, k.keys)
	return keys
}

// GetPrimaryKey returns the key on the ring at position 0. This is the key used
// for encrypting messages, and is the first key tried for decrypting messages.
func (k *Keyring) GetPrimaryKey() (key []byte) {
	k.l.Lock()
	defer k.l.Unlock()
	return k.getPrimaryKeyLocked()
}

// getPrimaryKeyLocked must be called while holding the mutex
func (k *Keyring) getPrimaryKeyLocked() (key []byte) {
	if len(k.keys) > 0 {
		key = k.keys[0]
	}
	return
}

// GetKeyIDs returns the identifiers of the keys on the ring, in the same
// order as GetKeys: index 0 is the primary key. Identifiers are safe to
// log and are what version-2 messages carry to name their encrypting key,
// which makes key generations visible while troubleshooting a rotation.
func (k *Keyring) GetKeyIDs() []KeyID {
	k.l.Lock()
	defer k.l.Unlock()

	ids := make([]KeyID, len(k.keys))
	for i, key := range k.keys {
		ids[i] = KeyIDForKey(key)
	}
	return ids
}

// GetPrimaryKeyID returns the identifier of the primary key, and false if
// the ring is empty (encryption disabled).
func (k *Keyring) GetPrimaryKeyID() (KeyID, bool) {
	k.l.Lock()
	defer k.l.Unlock()

	if len(k.keys) == 0 {
		return KeyID{}, false
	}
	return KeyIDForKey(k.keys[0]), true
}

// GetKeyByID returns the installed key with the given identifier, and false
// if no installed key matches. It is used to select the exact key named by
// an incoming version-2 message.
func (k *Keyring) GetKeyByID(id KeyID) ([]byte, bool) {
	k.l.Lock()
	defer k.l.Unlock()

	for _, key := range k.keys {
		if KeyIDForKey(key) == id {
			return key, true
		}
	}
	return nil, false
}

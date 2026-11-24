// Copyright IBM Corp. 2013, 2026
// SPDX-License-Identifier: MPL-2.0

package memberlist

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

/*
Encrypted messages are prefixed with an encryptionVersion byte
that is used for us to be able to properly encode/decode. We
currently support the following versions:

	0 - AES-GCM 128, using PKCS7 padding
	1 - AES-GCM 128, no padding. Padding not needed, caused bloat.

The version byte is the only key-related information on the wire: a message
never carries key material or a key name, so the format is unchanged by the
introduction of key identifiers below. A receiver tries every installed key
(see Keyring) and decrypts whichever generation the sender used.
*/
type encryptionVersion uint8

const (
	minEncryptionVersion encryptionVersion = 0
	maxEncryptionVersion encryptionVersion = 1
)

const (
	versionSize    = 1
	nonceSize      = 12
	tagSize        = 16
	maxPadOverhead = 16
	blockSize      = aes.BlockSize

	// keyIDSize is the number of SHA-256 bytes kept as a key identifier.
	keyIDSize = 8
)

// KeyID is a short, non-secret identifier for an encryption key. It is the
// leading bytes of the key's SHA-256 digest, so every node derives the same
// identifier for the same key without coordination, while the identifier
// itself does not reveal the key.
//
// Key identifiers are used only for observability and diagnostics: they are
// logged at startup and are included in key mismatch errors, which lets an
// operator compare the key generations installed on two nodes that cannot
// talk to each other. They are never sent on the wire, so the packet format
// remains compatible with nodes that predate them.
type KeyID [keyIDSize]byte

// KeyIDForKey returns the identifier for the given key. The key should be
// validated with ValidateKey first.
func KeyIDForKey(key []byte) KeyID {
	sum := sha256.Sum256(key)
	var id KeyID
	copy(id[:], sum[:keyIDSize])
	return id
}

// String renders the identifier as hex, which is the form used in logs and
// error messages.
func (id KeyID) String() string {
	return hex.EncodeToString(id[:])
}

// ErrKeyMismatch is returned when a received payload cannot be decrypted and
// authenticated with any of the keys currently installed. The concrete error
// is a *KeyMismatchError, which names the key identifiers that were tried so
// the mismatch can be diagnosed without logging key material.
var ErrKeyMismatch = errors.New("encryption key mismatch")

// KeyMismatchError reports that a payload could not be decrypted with any key
// on the local keyring. TriedKeyIDs lists the identifiers of the keys that
// were attempted, in order. It carries no key material.
type KeyMismatchError struct {
	TriedKeyIDs []KeyID
}

func (e *KeyMismatchError) Error() string {
	ids := make([]string, len(e.TriedKeyIDs))
	for i, id := range e.TriedKeyIDs {
		ids[i] = id.String()
	}
	if len(ids) == 0 {
		return ErrKeyMismatch.Error() + ": no keys are installed"
	}
	return fmt.Sprintf("%s: payload could not be decrypted with any installed key (tried key ids: %s)",
		ErrKeyMismatch.Error(), strings.Join(ids, ", "))
}

// Unwrap allows errors.Is(err, ErrKeyMismatch) to identify this error.
func (e *KeyMismatchError) Unwrap() error { return ErrKeyMismatch }

// pkcs7encode is used to pad a byte buffer to a specific block size using
// the PKCS7 algorithm. "Ignores" some bytes to compensate for IV
func pkcs7encode(buf *bytes.Buffer, ignore, blockSize int) {
	n := buf.Len() - ignore
	more := blockSize - (n % blockSize)
	for range more {
		buf.WriteByte(byte(more))
	}
}

// pkcs7decode is used to decode a buffer that has been padded
func pkcs7decode(buf []byte, _ int) []byte {
	if len(buf) == 0 {
		panic("Cannot decode a PKCS7 buffer of zero length")
	}
	n := len(buf)
	last := buf[n-1]
	n -= int(last)
	return buf[:n]
}

// encryptOverhead returns the maximum possible overhead of encryption by version
func encryptOverhead(vsn encryptionVersion) int {
	switch vsn {
	case 0:
		return 45 // Version: 1, IV: 12, Padding: 16, Tag: 16
	case 1:
		return 29 // Version: 1, IV: 12, Tag: 16
	default:
		panic("unsupported version")
	}
}

// encryptedLength is used to compute the buffer size needed
// for a message of given length
func encryptedLength(vsn encryptionVersion, inp int) int {
	// If we are on version 1, there is no padding
	if vsn >= 1 {
		return versionSize + nonceSize + inp + tagSize
	}

	// Determine the padding size
	padding := blockSize - (inp % blockSize)

	// Sum the extra parts to get total size
	return versionSize + nonceSize + inp + padding + tagSize
}

// encryptPayload is used to encrypt a message with a given key.
// We make use of AES-128 in GCM mode. New byte buffer is the version,
// nonce, ciphertext and tag
func encryptPayload(vsn encryptionVersion, key []byte, msg []byte, data []byte, dst *bytes.Buffer) error {
	// Get the AES block cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	// Get the GCM cipher mode
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return err
	}

	// Grow the buffer to make room for everything
	offset := dst.Len()
	dst.Grow(encryptedLength(vsn, len(msg)))

	// Write the encryption version
	dst.WriteByte(byte(vsn))

	// Add a random nonce
	_, err = io.CopyN(dst, rand.Reader, nonceSize)
	if err != nil {
		return err
	}
	afterNonce := dst.Len()

	// Ensure we are correctly padded (only version 0)
	if vsn == 0 {
		_, _ = io.Copy(dst, bytes.NewReader(msg))
		pkcs7encode(dst, offset+versionSize+nonceSize, aes.BlockSize)
	}

	// Encrypt message using GCM
	slice := dst.Bytes()[offset:]
	nonce := slice[versionSize : versionSize+nonceSize]

	// Message source depends on the encryption version.
	// Version 0 uses padding, version 1 does not
	var src []byte
	if vsn == 0 {
		src = slice[versionSize+nonceSize:]
	} else {
		src = msg
	}
	out := gcm.Seal(nil, nonce, src, data)

	// Truncate the plaintext, and write the cipher text
	dst.Truncate(afterNonce)
	dst.Write(out)
	return nil
}

// decryptMessage performs the actual decryption of ciphertext. This is in its
// own function to allow it to be called on all keys easily.
func decryptMessage(key, msg []byte, data []byte) ([]byte, error) {
	// Get the AES block cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Get the GCM cipher mode
	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}

	// Decrypt the message
	nonce := msg[versionSize : versionSize+nonceSize]
	ciphertext := msg[versionSize+nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, data)
	if err != nil {
		return nil, err
	}

	// Success!
	return plain, nil
}

// decryptPayload is used to decrypt a message with a given key,
// and verify it's contents. Any padding will be removed, and a
// slice to the plaintext is returned. Decryption is done IN PLACE!
//
// During a key rotation the keyring holds both the old and the new key, so
// messages from either generation are accepted here while senders encrypt
// with the current primary key only. Keys are tried in ring order. If none of
// them can authenticate the payload, a *KeyMismatchError is returned that
// lists the key identifiers that were tried; use errors.Is(err,
// ErrKeyMismatch) to detect this case.
func decryptPayload(keys [][]byte, msg []byte, data []byte) ([]byte, error) {
	// Ensure we have at least one byte
	if len(msg) == 0 {
		return nil, fmt.Errorf("cannot decrypt empty payload")
	}

	// Verify the version
	vsn := encryptionVersion(msg[0])
	if vsn > maxEncryptionVersion {
		return nil, fmt.Errorf("unsupported encryption version %d", msg[0])
	}

	// Ensure the length is sane
	if len(msg) < encryptedLength(vsn, 0) {
		return nil, fmt.Errorf("payload is too small to decrypt: %d", len(msg))
	}

	for _, key := range keys {
		plain, err := decryptMessage(key, msg, data)
		if err == nil {
			// Remove the PKCS7 padding for vsn 0
			if vsn == 0 {
				return pkcs7decode(plain, aes.BlockSize), nil
			} else {
				return plain, nil
			}
		}
	}

	tried := make([]KeyID, len(keys))
	for i, key := range keys {
		tried[i] = KeyIDForKey(key)
	}
	return nil, &KeyMismatchError{TriedKeyIDs: tried}
}

func appendBytes(first []byte, second []byte) []byte {
	hasFirst := len(first) > 0
	hasSecond := len(second) > 0

	switch {
	case hasFirst && hasSecond:
		out := make([]byte, 0, len(first)+len(second))
		out = append(out, first...)
		out = append(out, second...)
		return out
	case hasFirst:
		return first
	case hasSecond:
		return second
	default:
		return nil
	}
}

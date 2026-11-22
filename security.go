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
	"fmt"
	"io"
)

/*
Encrypted messages are prefixed with an encryptionVersion byte
that is used for us to be able to properly encode/decode. We
currently support the following versions:

	0 - AES-GCM 128, using PKCS7 padding
	1 - AES-GCM 128, no padding. Padding not needed, caused bloat.
	2 - AES-GCM 128, no padding, key identifier included. The
	    identifier names the key generation that encrypted the
	    message, so a receiver can select exactly one key during
	    rotation and report a precise error when it is unknown.
*/
type encryptionVersion uint8

const (
	minEncryptionVersion encryptionVersion = 0
	maxEncryptionVersion encryptionVersion = 2
)

const (
	versionSize    = 1
	keyIDSize      = 4
	nonceSize      = 12
	tagSize        = 16
	maxPadOverhead = 16
	blockSize      = aes.BlockSize
)

// KeyID is a short, non-secret identifier for an encryption key. It is
// derived from the key material with SHA-256, so every node computes the
// same identifier for the same key without any coordination, while the
// identifier itself reveals nothing about the key. Messages encrypted with
// encryptionVersion 2 carry the KeyID of the encrypting key, which allows
// receivers to select exactly that key and to log which key generation a
// message belongs to when troubleshooting key rotation.
type KeyID [keyIDSize]byte

// KeyIDForKey returns the identifier of the given key. The key should
// first be validated with ValidateKey.
func KeyIDForKey(key []byte) KeyID {
	sum := sha256.Sum256(key)
	var id KeyID
	copy(id[:], sum[:keyIDSize])
	return id
}

// String renders the identifier in hex for logs and error messages.
func (id KeyID) String() string {
	return hex.EncodeToString(id[:])
}

// headerSize returns the number of bytes preceding the nonce for a given
// encryption version: the version byte plus, for version 2 and up, the
// key identifier.
func headerSize(vsn encryptionVersion) int {
	if vsn >= 2 {
		return versionSize + keyIDSize
	}
	return versionSize
}

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
	case 2:
		return 33 // Version: 1, KeyID: 4, IV: 12, Tag: 16
	default:
		panic("unsupported version")
	}
}

// encryptedLength is used to compute the buffer size needed
// for a message of given length
func encryptedLength(vsn encryptionVersion, inp int) int {
	// If we are on version 1 or later, there is no padding
	if vsn >= 1 {
		return headerSize(vsn) + nonceSize + inp + tagSize
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

	// Version 2 and up carry the identifier of the encrypting key, so the
	// receiver can select exactly that key instead of scanning its ring.
	if vsn >= 2 {
		id := KeyIDForKey(key)
		dst.Write(id[:])
	}

	// Add a random nonce
	_, err = io.CopyN(dst, rand.Reader, nonceSize)
	if err != nil {
		return err
	}
	afterNonce := dst.Len()

	// Ensure we are correctly padded (only version 0)
	if vsn == 0 {
		_, _ = io.Copy(dst, bytes.NewReader(msg))
		pkcs7encode(dst, offset+headerSize(vsn)+nonceSize, aes.BlockSize)
	}

	// Encrypt message using GCM
	slice := dst.Bytes()[offset:]
	hdrSize := headerSize(vsn)
	nonce := slice[hdrSize : hdrSize+nonceSize]

	// Message source depends on the encryption version.
	// Version 0 uses padding, version 1 and up do not
	var src []byte
	if vsn == 0 {
		src = slice[hdrSize+nonceSize:]
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
func decryptMessage(vsn encryptionVersion, key, msg []byte, data []byte) ([]byte, error) {
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
	hdrSize := headerSize(vsn)
	nonce := msg[hdrSize : hdrSize+nonceSize]
	ciphertext := msg[hdrSize+nonceSize:]
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
// During a key rotation the keyring holds both the old and the new
// primary key, so messages from either generation are accepted here
// while senders encrypt with the current primary key only. Version 2
// messages name their encrypting key: the named key is used, and a
// precise error is returned when it is not installed or the message
// fails authentication. Older versions are tried against every key on
// the ring for backwards compatibility.
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

	// Version 2 and up name the key the message was encrypted with. Honor
	// that binding: use exactly the named key, and fail loudly rather than
	// trying other keys, so a message can never be accepted under a key
	// generation its sender did not intend.
	if vsn >= 2 {
		var id KeyID
		copy(id[:], msg[versionSize:headerSize(vsn)])
		for _, key := range keys {
			if KeyIDForKey(key) != id {
				continue
			}
			plain, err := decryptMessage(vsn, key, msg, data)
			if err != nil {
				return nil, fmt.Errorf("message authentication failed for key id %s", id)
			}
			return plain, nil
		}
		return nil, fmt.Errorf("no installed key matches key id %s", id)
	}

	for _, key := range keys {
		plain, err := decryptMessage(vsn, key, msg, data)
		if err == nil {
			// Remove the PKCS7 padding for vsn 0
			if vsn == 0 {
				return pkcs7decode(plain, aes.BlockSize), nil
			} else {
				return plain, nil
			}
		}
	}

	return nil, fmt.Errorf("no installed keys could decrypt the message")
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

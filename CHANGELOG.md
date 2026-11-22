## Unreleased

### Improvements

* Encrypted messages now carry a non-secret key identifier (encryption version 2), so receivers select exactly the key generation a message was encrypted with and report explicit, key-id-naming errors (`no installed key matches key id ...`, `message authentication failed for key id ...`) instead of a generic decryption failure. Legacy version 0/1 messages are still accepted; set `Config.DisableKeyVersionHeader` while rolling a cluster with nodes too old to parse version 2.
* `Keyring` gained `GetKeyIDs`, `GetPrimaryKeyID`, and `GetKeyByID` so key generations are observable while troubleshooting a rotation, and the installed key ids are logged at startup.

### Changes

### Fixed

* `Keyring` updates are now copy-on-write: `GetKeys` returns a snapshot, and `AddKey`/`RemoveKey` no longer mutate a slice that concurrent readers may hold during decryption.

### Security


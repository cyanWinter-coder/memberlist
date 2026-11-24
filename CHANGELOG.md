## Unreleased

### Improvements

* Gossip keys can now be rotated without downtime through configuration: `Config.SecretKey` remains the primary (encrypting) key and the new `Config.SecretKeys` lists additional keys that are accepted for decryption only. During a rotation every node carries both the old and the new key, then the retired key is dropped. Outgoing messages always use the primary key and incoming messages decrypt with any installed key, in ring order.
* Added `KeyID`/`KeyIDForKey`, `Keyring.GetKeyIDs`, and `Keyring.GetPrimaryKeyID`: short, non-secret key identifiers derived from the key material. Installed key ids are logged at startup so a rotation in progress is observable.
* Decryption failures caused by a key mismatch are now identifiable with `errors.Is(err, ErrKeyMismatch)` and report the key identifiers that were tried (`*KeyMismatchError`) instead of a generic message, so a rolling restart with a mismatched key is diagnosable from the logs without exposing key material. `Join` now wraps the underlying error with `%w` so callers can detect it.
* The wire format is unchanged: key identifiers are never sent over the network, and encryption versions 0 and 1 keep working as before.

### Changes

### Fixed

* `Keyring.AddKey`/`RemoveKey` no longer mutate a key slice that concurrent decryption may be holding. Updates are copy-on-write, so a rotation cannot corrupt a snapshot taken by an in-flight message.

### Security

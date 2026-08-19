# Kryptic Encryption Engine - Security Architecture

This document describes the complete cryptographic design of the Kryptic platform's
encryption engine: what is derived from what, where each key lives, and the exact
boundary of what the Kryptic server can and cannot see. It is written so a security
reviewer can evaluate the architecture before reading a line of code
(Kerckhoffs's principle: the design is public; security depends only on the keys).

This file is identical across the three runtime repositories:

- [Kryptic.Encryption.Dotnet](https://github.com/dev-kryptic/Kryptic.Encryption.Dotnet) (.NET, this repo)
- [Kryptic.Encryption.NPM](https://github.com/dev-kryptic/Kryptic.Encryption.NPM) (TypeScript / WebCrypto)
- [Kryptic.Encryption.Go](https://github.com/dev-kryptic/Kryptic.Encryption.Go) (Go)

## Primitives

The engine composes established implementations only. There are **no custom primitives**.

| Operation | Algorithm | Implementation |
| --- | --- | --- |
| Secret encryption | AES-256-GCM, 96-bit random nonce, 128-bit tag | `System.Security.Cryptography.AesGcm` (.NET platform) |
| Key delivery (sealed box) | P-256 ECDH + HKDF-SHA256 + AES-256-GCM (ECIES construction) | `System.Security.Cryptography.ECDiffieHellman` / WebCrypto `ECDH` / Go `crypto/ecdh` |
| Key derivation / password hashing | Argon2id (64 MiB, 3 iterations, parallelism 4 - parameter set v1) | `Konscious.Security.Cryptography.Argon2` / `hash-wasm` (browser) / `golang.org/x/crypto/argon2` |
| Randomness | OS CSPRNG | `System.Security.Cryptography.RandomNumberGenerator` |
| Constant-time comparison | - | `CryptographicOperations.FixedTimeEquals` |

Cross-runtime consistency (C#, browser WebCrypto, Go) is locked by committed
known-answer interop vectors (`interop-vectors/`): the same inputs must produce or
open the same bytes in every implementation.

## The envelope format

Every ciphertext the platform stores or transmits is a **secret envelope**:

```
v1.<keyId>.<base64url nonce>.<base64url ciphertext||tag>
```

- `v1` - format version. Layout or parameter changes bump the version; old data keeps
  parsing under its original rules.
- `keyId` - identifies which key produced the ciphertext (`[a-zA-Z0-9_-]`, ≤ 64 chars).
  This is what makes key rotation possible without rewriting history blindly.
- `nonce` - 12 bytes, generated fresh from the CSPRNG for every encryption. The API
  offers no way for a caller to supply a nonce, so nonce reuse by misuse is not possible.
- `ciphertext||tag` - the AES-256-GCM output with the 16-byte authentication tag appended.

The envelope contains no key material and no plaintext; it is safe to store, index, and log.

### Context binding (associated data)

Secret values are encrypted with GCM *associated data* set to a context string:

```
secret:<secretDefinitionId>:env:<environmentId>
```

Decryption fails unless the same context is presented. An attacker with raw database
access therefore cannot swap ciphertexts between rows (e.g. move the production
`DATABASE_URL` ciphertext into a development row a low-privilege user may reveal) -
the authentication tag will not verify.

## The sealed box (key delivery)

The org key is delivered to authorized parties as a **sealed box** - ECIES over P-256:

```
sbx.v1.<recipientKeyId>.<base64url ephemeralPub>.<base64url nonce>.<base64url ciphertext||tag>
```

A fresh ephemeral P-256 key pair is generated per message; ECDH against the
recipient's public key is expanded with HKDF-SHA256 (info binds both public keys)
into a 32-byte AES key and a 12-byte nonce, then AES-256-GCM seals the payload.
The nonce is derived, not random: the per-message ephemeral key guarantees key
uniqueness, and a deterministic seal enables byte-exact cross-runtime
known-answer tests. Only the holder of the recipient private key can open the box.

## Key hierarchy (end-to-end)

Secret values are end-to-end encrypted. The org key exists only on clients; the
server stores ciphertext it cannot open.

```
   User vault passphrase ── Argon2id ──┐            (browser)
   Machine client secret ── Argon2id ──┤ unwraps the party's private key
   Device key pair (generated at login)┘            (daemon)
                              │
                 ┌────────────▼────────────┐
                 │  Party P-256 key pair    │  private key: client-side only
                 └────────────┬────────────┘
                              │ opens the party's sealed-box grant
                 ┌────────────▼────────────┐
                 │  Org key (32 bytes)      │  exists in plaintext ONLY on clients
                 └────────────┬────────────┘
                              │ encrypts (AES-256-GCM with context binding)
                 ┌────────────▼────────────┐
                 │  Secret values           │  stored ONLY as envelopes (ciphertext)
                 └─────────────────────────┘
```

- **The org key** is 32 random bytes generated in the initializing admin's browser.
  The server stores it only inside sealed boxes ("grants"), one per authorized
  party: each enrolled user, each approved daemon device, each machine identity,
  and the recovery key.
- **User keys** are P-256 key pairs generated in the browser; the private key is
  wrapped by an Argon2id key derived from the user's vault passphrase (which is
  never sent to the server).
- **Device keys** are generated by the daemon at login and stored in the OS
  credential store; the public key is registered during the device flow, and an
  admin's browser seals the org key to it on approval.
- **Machine keys** (CI) are generated in the admin's browser at identity creation;
  the private key is wrapped by Argon2id(client secret), and the server stores
  only a hash of that secret.
- **Recovery**: a high-entropy recovery code (shown once, stored by the customer)
  wraps a recovery key pair, whose grant can restore org-key access if every
  admin loses their passphrase.

Separately, the platform holds a server-side **org data key** used only for
operational ciphertexts the server itself must read - e.g. SSO IdP client
secrets. It never encrypts customer secret values.

### Where each key lives

| Key | At rest | In memory | Ever at the server? |
| --- | --- | --- | --- |
| Vault passphrase / recovery code / machine client secret | Nowhere (customer-held) | Client only, during derivation | **No** (server stores a hash of machine secrets) |
| Party private keys (user/device/machine/recovery) | Database or OS credential store, **wrapped/client-side only** | Client only | Only in wrapped form it cannot open |
| Org key | Database, **sealed-box grants only** | Browser / daemon / CI process | Only sealed to recipients |
| Secret plaintext | Never | Client memory + requesting process | **Never** |
| Server org data key (operational only) | Database, wrapped under the platform master key | Server during SSO operations | Yes - but it cannot open secret values |

### Key rotation

- **Org-key rotation** is a client-side ceremony: an admin's browser generates a
  fresh org key, decrypts and re-encrypts every current secret value locally,
  seals new grants to every active recipient and a new recovery key, and submits
  the whole change atomically. Old grants are revoked and old version history is
  purged (it is ciphertext under the retired key). Recommended after removing a
  member, since revoking a grant cannot erase a key the member already held.
- **Server data-key rotation** re-encrypts the operational ciphertexts (IdP
  secrets) under a fresh server-side key. It never touches secret values.
- **Master-key rotation** rewraps server data keys under a new platform master
  key; ciphertexts are untouched.

## Password hashing

Local credentials use Argon2id in the format:

```
argon2id.<parameterSetVersion>.<base64url salt (16 bytes)>.<base64url hash (32 bytes)>
```

- Parameter set v1: 64 MiB memory, 3 iterations, parallelism 4.
- The parameter version is embedded per-hash, so parameters can be raised for new hashes
  while existing ones keep verifying; verification is constant-time.

## What the server can and cannot see

The server **can** see: envelope metadata (version, key id, nonce, ciphertext
length), secret *keys* (names like `DATABASE_URL`), project/environment structure,
grant recipients, and audit metadata.

The server **cannot** see: secret values, the org key, any party's private key,
vault passphrases, recovery codes, or machine client secrets (stored hashed).
There is no server-side code path that decrypts a secret value - the endpoints
that would need one do not exist.

Transport is TLS 1.3, and daemon↔SDK delivery happens over a local OS socket
that never crosses a network.

The practical consequence: if you lose your vault passphrase, your recovery
code, and every enrolled device, Kryptic cannot restore your secret values.
That is the design working as intended.

## Test vectors

Deterministic test coverage lives in `Kryptic.Encryption.Tests` (this repo), the
TypeScript tests in `Kryptic.Encryption.NPM`, and the Go tests in
`Kryptic.Encryption.Go`. The C# suite includes: round-trip,
tamper detection (flipped ciphertext/nonce bytes), wrong-key rejection, wrong-context
rejection, envelope fuzzing (truncation, wrong version, malformed base64), Argon2id
determinism per salt/parameter set, and wrap/unwrap round-trips. AES-256-GCM and Argon2id
correctness against published vectors is delegated to the underlying implementations
(.NET platform crypto is FIPS-validated in supported configurations).

## Reporting a vulnerability

Email **security@kryptic.dev**. We operate a responsible disclosure program and a CVE
coordination process for critical findings. Please do not open public issues for
vulnerabilities.

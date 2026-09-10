# Changelog

Notes for each release. The publish workflow copies the matching section into
the GitHub Release.

## Unreleased

## 1.1.0

### Changed

- BREAKING: `createMachineMaterial` generates a `ksm2_`-prefixed client
  secret and its upload carries `clientAuthSecret`, a derived value (locked
  by `interop-vectors/machine-auth.json`), instead of `clientSecret`. New
  exports: `machineAuthSecretForToken` and `MACHINE_SECRET_V2_PREFIX` for
  CI clients.
- Base64url decoding is strict: standard-alphabet and padded inputs are
  rejected, matching the Go implementation.

### Security

- Internal hardening around sensitive key material handling.

## 1.0.8

Release 1.0.8.

## 1.0.7

### Added

- `rewrapPrivateKey` re-wraps an unlocked key pair under a new vault
  passphrase. The public key is unchanged, so existing grants stay valid.

## 1.0.2

Initial public release.

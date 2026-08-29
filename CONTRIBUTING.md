# Contributing

This repository is one of three byte-compatible implementations of the Kryptic
encryption engine (.NET, TypeScript/WebCrypto, Go). A format change to the
envelope, sealed box, or Argon2id parameters must land in all three
repositories in the same release. The committed files in `interop-vectors/`
are the contract.

Read [SECURITY.md](SECURITY.md) before changing crypto code.

## What we accept

- Bug fixes that preserve existing wire formats
- Tests, including new interop vectors when a format is intentionally added
- Documentation and comment corrections
- Runtime-specific implementation fixes that do not change bytes on the wire

## What we do not accept

- Custom cryptographic primitives (use the platform / standard library)
- Caller-supplied nonces for secret envelopes
- Public GitHub issues for vulnerabilities (email security@kryptic.dev)
- A format change in only one of the three runtimes

## Development

```bash
npm test
```

If you add or change a vector in `interop-vectors/`, the same bytes must be
committed in
[Kryptic.Encryption.Net](https://github.com/dev-kryptic/Kryptic.Encryption.Net),
[Kryptic.Encryption.NPM](https://github.com/dev-kryptic/Kryptic.Encryption.NPM),
and
[Kryptic.Encryption.Go](https://github.com/dev-kryptic/Kryptic.Encryption.Go).

## Licensing of contributions

This repository is Apache-2.0. By opening a pull request you confirm the
contribution is your own work (or you have the right to submit it) and you
license it under Apache-2.0. There is no CLA.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

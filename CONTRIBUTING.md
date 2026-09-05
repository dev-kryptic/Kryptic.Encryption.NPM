# Contributing

This repository is the TypeScript / WebCrypto encryption engine for Kryptic
(`@krypticdev/encryption`).

## What we accept

- Bug fixes and test coverage
- Documentation corrections
- Compatibility fixes
- Interop vector updates when wire formats change (must land in all three
  encryption repositories in the same release)

## What we do not accept

- Custom cryptographic primitives
- Wire format changes in only one encryption runtime
- Public GitHub issues for vulnerabilities (email security@kryptic.dev)

## Development

```bash
npm test
```

Read [SECURITY.md](SECURITY.md) before changing crypto code. Sibling runtimes:
[Kryptic.Encryption.Net](https://github.com/dev-kryptic/Kryptic.Encryption.Net)
and [Kryptic.Encryption.Go](https://github.com/dev-kryptic/Kryptic.Encryption.Go).

## Releasing

Merges to `main` run tests only. Publish by pushing a `vX.Y.Z` tag (or
re-running the workflow with that tag). The tag is the version: npm, the
GitHub Release, and notes all use it. Leave release-worthy notes under
**Unreleased**. The publish job creates the `## X.Y.Z` section from that body
if it is missing (or a one-line fallback). Format changes must ship in
all three encryption repositories in the same release.

## Licensing of contributions

This repository is Apache-2.0. By opening a pull request you confirm the
contribution is your own work (or you have the right to submit it) and you
license it under Apache-2.0. There is no CLA.

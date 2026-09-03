# Kryptic.Encryption (TypeScript / WebCrypto)

The browser implementation of Kryptic's open-source (Apache-2.0) encryption engine.
This is the package the **Management dashboard** uses to enroll vaults, seal org
keys to devices, and encrypt secret values before they ever leave the tab.

**npm package:** `@krypticdev/encryption`. This GitHub repository is named
`Kryptic.Encryption.NPM` so auditors can tell the three runtimes apart.

Sibling implementations of the same wire formats:

| Repository | Runtime | Consumed by |
| --- | --- | --- |
| [Kryptic.Encryption.Dotnet](https://github.com/dev-kryptic/Kryptic.Encryption.Dotnet) | .NET (`Kryptic.Encryption` on nuget.org) | Kryptic Platform |
| [Kryptic.Encryption.NPM](https://github.com/dev-kryptic/Kryptic.Encryption.NPM) | TypeScript / WebCrypto (this package) | Management dashboard |
| [Kryptic.Encryption.Go](https://github.com/dev-kryptic/Kryptic.Encryption.Go) | Go | Daemon, CLI, Kubernetes operator |

A format change (envelope, sealed box, Argon2id parameters) must land in all three
repositories in the same release. The committed files in `interop-vectors/` are the
contract: every runtime must open and, where the test is deterministic, reproduce
those bytes.

**No custom primitives.** WebCrypto for AES-256-GCM, P-256 ECDH, and HKDF-SHA256;
Argon2id via `hash-wasm`. Read [SECURITY.md](SECURITY.md) before reading code.

## Install

```
npm install @krypticdev/encryption
```

Works in modern browsers (WebCrypto) and in Node 20+ (used by the test suite).

## What's in the box

| Module | Purpose |
| --- | --- |
| `sealedbox` | P-256 ECDH sealed box (`sbx.v1...`) for delivering the org key |
| `envelope` | AES-256-GCM secret envelope (`v1.<keyId>...`) |
| `argon2` | Argon2id passphrase -> 256-bit key (parameter set v1) |
| `vault` | Enrollment, unlock, recovery kit, machine-identity material |
| `secrets` | Context-bound encrypt/decrypt of secret values, plus .env parse/format |

## Usage

### Encrypt a secret value (what the dashboard sends to the API)

```ts
import { encryptSecretValue, decryptSecretValue } from '@krypticdev/encryption';

const envelope = await encryptSecretValue(
  orgKey, orgKeyId, definitionId, environmentId, 'postgres://…',
);
const plaintext = await decryptSecretValue(
  orgKey, definitionId, environmentId, envelope,
);
```

The associated data is `secret:{definitionId}:env:{environmentId}` (lowercase
GUIDs). Moving a ciphertext to another row fails decryption.

### Enroll a vault and unwrap the org key

```ts
import {
  createEnrollment,
  unlockPrivateKey,
  unwrapOrgKey,
  wrapOrgKeyTo,
} from '@krypticdev/encryption';

const { upload, keyPair } = await createEnrollment(passphrase);
// POST upload to /api/encryption/enroll  (public key + wrapped private key only)

const orgKey = await unwrapOrgKey(keyPair, wrappedOrgKeyFromGrant);
const grant = await wrapOrgKeyTo(memberPublicKey, orgKeyId, orgKey);
```

The passphrase never leaves the client. The server stores only ciphertext and
public keys.

## Build & test

```
npm install
npm test
npm run build
```

## Publishing (maintainers)

CI lives in [`.github/workflows/publish.yml`](.github/workflows/publish.yml). Pull
requests only run tests. A publish on `main` (or `workflow_dispatch`) commits the
version bump, pushes it as the Kryptic Release Bot, publishes the package, then
tags `vX.Y.Z` and opens a GitHub Release.

### GitHub Actions secrets

Add these at the org or on the GitHub repo (`Settings` > `Secrets and variables` > `Actions`):

| Secret | What it is | Where to get it |
| --- | --- | --- |
| `RELEASE_BOT_APP_ID` | App ID of **Kryptic Release Bot** | GitHub App settings |
| `RELEASE_BOT_PRIVATE_KEY` | Private key `.pem` of that app | GitHub App settings > Generate a private key |
| `NPM_TOKEN` | npm automation token with publish access to the [`krypticdev` org](https://www.npmjs.com/settings/krypticdev/packages) | [npmjs.com](https://www.npmjs.com/) > Access Tokens > Generate new token (classic, **Automation** type) **or** a granular token with `read-and-write` on `@krypticdev/encryption`. Store the token value as `NPM_TOKEN`. |

One-time npm side:

1. Confirm you can publish under the [`krypticdev` npm org](https://www.npmjs.com/settings/krypticdev/packages).
2. Add the publishing user as an owner/publisher of that org.
3. The first publish creates `@krypticdev/encryption` as a public package
   (`publishConfig.access` is `public`).

Optional, recommended later: switch the workflow to npm
[trusted publishing](https://docs.npmjs.com/trusted-publishers) (OIDC) and drop
`NPM_TOKEN`. Until then, the automation token is the secret that must exist.

No other secrets are required for git. The Release Bot is a ruleset bypass
actor and commits `package.json`, the `vX.Y.Z` tag, and the GitHub Release.

### First publish

1. Create the public GitHub repository `dev-kryptic/Kryptic.Encryption.NPM`.
2. Add `NPM_TOKEN` as a GitHub Actions secret on that repo.
3. Push `main`. The workflow publishes `@krypticdev/encryption@1.0.0` on the
   first run (package not yet on npm).

### Versioning

Patch versions auto-increment from the latest npm release when major.minor is
unchanged. To ship `1.1.0` or `2.0.0`, set `"version"` in `package.json` (or
pass it to `workflow_dispatch`) and the workflow publishes that version as-is.

## Reporting vulnerabilities

Please report security issues to **security@kryptic.dev**. See
[SECURITY.md](SECURITY.md). Do not open public issues for vulnerabilities.

## License

[Apache-2.0](LICENSE)

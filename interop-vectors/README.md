# Interop vectors

Known-answer tests shared by the three Kryptic encryption implementations.

These files are the wire-format contract. Changing a vector is a format break:
update C#, TypeScript, and Go in the same release, and bump the format version
(`v1` / `sbx.v1`) rather than silently changing bytes.

| File | What it locks |
| --- | --- |
| `sealed-box-p256.json` | P-256 sealed box: Open yields the plaintext; Seal with the fixed ephemeral key reproduces `sealed` |
| `argon2id.json` | Argon2id parameter set v1 (64 MiB, 3 passes, 4 lanes, 32-byte output) |

Canonical copies live in:

- `Kryptic.Encryption.Dotnet/interop-vectors/`
- `Kryptic.Encryption.NPM/interop-vectors/`
- `Kryptic.Encryption.Go/interop-vectors/`

Keep them identical.

/**
 * Secret-value encryption, byte-compatible with the C# engine and the Go
 * package: AES-256-GCM envelopes bound to their row via associated
 * data `secret:{definitionId}:env:{environmentId}` so ciphertexts cannot be
 * swapped in storage undetected. GUIDs are the lowercase JSON form, which matches
 * C#'s Guid.ToString().
 */

import { decryptEnvelope, encryptEnvelope } from './envelope';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function secretContext(definitionId: string, environmentId: string): Uint8Array {
  return encoder.encode(`secret:${definitionId.toLowerCase()}:env:${environmentId.toLowerCase()}`);
}

export async function encryptSecretValue(
  orgKey: Uint8Array,
  orgKeyId: string,
  definitionId: string,
  environmentId: string,
  plaintext: string,
): Promise<string> {
  return encryptEnvelope(
    orgKey,
    orgKeyId,
    encoder.encode(plaintext),
    secretContext(definitionId, environmentId),
  );
}

export async function decryptSecretValue(
  orgKey: Uint8Array,
  definitionId: string,
  environmentId: string,
  envelope: string,
): Promise<string> {
  const plaintext = await decryptEnvelope(orgKey, envelope, secretContext(definitionId, environmentId));
  return decoder.decode(plaintext);
}

// ----- Minimal .env handling for client-side import/export -----

const KEY_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

export interface DotEnvEntry {
  key: string;
  value: string;
}

/** Parses KEY=value lines; comments and blanks are ignored; quotes are stripped. */
export function parseDotEnv(content: string): DotEnvEntry[] {
  const entries: DotEnvEntry[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line === '' || line.startsWith('#')) continue;

    const eq = line.indexOf('=');
    if (eq <= 0) continue;

    const key = line.slice(0, eq).trim().replace(/^export\s+/, '');
    if (!KEY_PATTERN.test(key)) continue;

    let value = line.slice(eq + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1).replace(/\\(["\\])/g, '$1');
    } else if (value.startsWith("'") && value.endsWith("'") && value.length >= 2) {
      value = value.slice(1, -1);
    }

    entries.push({ key: key.toUpperCase(), value });
  }
  return entries;
}

/** Formats entries as .env text, quoting values that need it. */
export function formatDotEnv(entries: DotEnvEntry[]): string {
  return entries
    .map(({ key, value }) => {
      const needsQuotes = /[\s#"'`$\\]/.test(value) || value === '';
      return needsQuotes ? `${key}="${value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"` : `${key}=${value}`;
    })
    .join('\n');
}

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { ARGON2_V1, deriveKeyFromPassphrase } from '../src/argon2';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'interop-vectors');
const vector = JSON.parse(readFileSync(join(vectorsDir, 'argon2id.json'), 'utf8'));

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

describe('Argon2id interop vector (must match C# and Go V1)', () => {
  it('derives the expected key for parameter set V1', async () => {
    expect(ARGON2_V1.memoryKibibytes).toBe(vector.memoryKibibytes);
    expect(ARGON2_V1.iterations).toBe(vector.iterations);
    expect(ARGON2_V1.parallelism).toBe(vector.parallelism);

    const derived = await deriveKeyFromPassphrase(vector.passphrase, fromHex(vector.saltHex));

    expect(toHex(derived)).toBe(vector.derivedKeyHex);
  });
});

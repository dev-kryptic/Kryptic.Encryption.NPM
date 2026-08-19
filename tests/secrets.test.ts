import { describe, expect, it } from 'vitest';
import { decryptSecretValue, encryptSecretValue, formatDotEnv, parseDotEnv } from '../src/secrets';

const ORG_KEY = new Uint8Array(32).fill(7);
const ORG_KEY_ID = 'test-org-key';
const DEFINITION_ID = '11111111-2222-3333-4444-555555555555';
const ENVIRONMENT_ID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';

describe('secret value envelopes', () => {
  it('round-trips a value', async () => {
    const envelope = await encryptSecretValue(ORG_KEY, ORG_KEY_ID, DEFINITION_ID, ENVIRONMENT_ID, 'postgres://user:pass@host/db');
    const value = await decryptSecretValue(ORG_KEY, DEFINITION_ID, ENVIRONMENT_ID, envelope);
    expect(value).toBe('postgres://user:pass@host/db');
  });

  it('binds the ciphertext to its definition and environment', async () => {
    const envelope = await encryptSecretValue(ORG_KEY, ORG_KEY_ID, DEFINITION_ID, ENVIRONMENT_ID, 'value');
    await expect(
      decryptSecretValue(ORG_KEY, DEFINITION_ID, '99999999-9999-9999-9999-999999999999', envelope),
    ).rejects.toThrow();
  });

  it('is case-insensitive on GUID casing (matches C# lowercase form)', async () => {
    const envelope = await encryptSecretValue(ORG_KEY, ORG_KEY_ID, DEFINITION_ID.toUpperCase(), ENVIRONMENT_ID, 'v');
    const value = await decryptSecretValue(ORG_KEY, DEFINITION_ID, ENVIRONMENT_ID.toUpperCase(), envelope);
    expect(value).toBe('v');
  });
});

describe('dotenv handling', () => {
  it('parses keys, ignores comments and blanks, strips quotes', () => {
    const entries = parseDotEnv([
      '# comment',
      '',
      'DATABASE_URL=postgres://x',
      "REDIS_URL='redis://y'",
      'API_KEY="abc def"',
      'export NODE_ENV=production',
      'lowercase_key=ok',
      'not a line',
      '=nokey',
    ].join('\n'));

    expect(entries).toEqual([
      { key: 'DATABASE_URL', value: 'postgres://x' },
      { key: 'REDIS_URL', value: 'redis://y' },
      { key: 'API_KEY', value: 'abc def' },
      { key: 'NODE_ENV', value: 'production' },
      { key: 'LOWERCASE_KEY', value: 'ok' },
    ]);
  });

  it('formats values, quoting when needed, and round-trips', () => {
    const entries = [
      { key: 'PLAIN', value: 'simple' },
      { key: 'SPACED', value: 'a b' },
      { key: 'QUOTED', value: 'say "hi"' },
      { key: 'EMPTY', value: '' },
    ];
    const text = formatDotEnv(entries);
    expect(text).toContain('PLAIN=simple');
    expect(text).toContain('SPACED="a b"');
    expect(parseDotEnv(text)).toEqual(entries);
  });
});

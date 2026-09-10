import { describe, expect, it } from 'vitest';
import { decryptEnvelope, encryptEnvelope, parseEnvelope } from '../src/envelope';

describe('secret envelopes', () => {
  it('round-trips with associated data', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const ad = new TextEncoder().encode('secret:a:env:b');
    const serialized = await encryptEnvelope(key, 'key_test000001', new TextEncoder().encode('hello'), ad);
    const opened = await decryptEnvelope(key, serialized, ad);
    expect(new TextDecoder().decode(opened)).toBe('hello');
    expect(parseEnvelope(serialized).keyId).toBe('key_test000001');
  });

  it('rejects a non-canonical "v01" version on an otherwise valid envelope', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const serialized = await encryptEnvelope(key, 'key_test000003', new TextEncoder().encode('x'));
    const nonCanonical = 'v01' + serialized.slice(2);

    expect(() => parseEnvelope(serialized)).not.toThrow();
    expect(() => parseEnvelope(nonCanonical)).toThrow();
  });

  it('rejects envelope segments that use the standard base64 alphabet', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    // 1-byte plaintext -> 17-byte ciphertext+tag, which always pads with '='
    // in standard base64, so the re-encoded segment is always non-canonical.
    const serialized = await encryptEnvelope(key, 'key_test000004', new TextEncoder().encode('x'));
    const parts = serialized.split('.');
    const ciphertext = Buffer.from(parts[3].replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    parts[3] = ciphertext.toString('base64');

    expect(parts[3]).toContain('=');
    expect(() => parseEnvelope(parts.join('.'))).toThrow();
  });

  it('rejects the wrong associated data', async () => {
    const key = crypto.getRandomValues(new Uint8Array(32));
    const serialized = await encryptEnvelope(
      key,
      'key_test000002',
      new TextEncoder().encode('hello'),
      new TextEncoder().encode('right'),
    );
    await expect(
      decryptEnvelope(key, serialized, new TextEncoder().encode('wrong')),
    ).rejects.toThrow();
  });
});

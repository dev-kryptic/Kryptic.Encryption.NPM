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

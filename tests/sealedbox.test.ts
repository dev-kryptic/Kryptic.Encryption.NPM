import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  fromBase64Url,
  generateKeyPair,
  open,
  parseSealedKey,
  seal,
  sealWithEphemeralKey,
  serializeSealedKey,
  toBase64Url,
} from '../src/sealedbox';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'interop-vectors');
const vector = JSON.parse(readFileSync(join(vectorsDir, 'sealed-box-p256.json'), 'utf8'));

function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

describe('sealed box interop vector (must match C# and Go)', () => {
  it('opens the C#-generated sealed box to the expected plaintext', async () => {
    const recipient = {
      publicKey: fromHex(vector.recipientPublicKeyHex),
      privateKey: fromHex(vector.recipientPrivateKeyHex),
    };

    const opened = await open(recipient, parseSealedKey(vector.sealed));

    expect(toHex(opened)).toBe(vector.plaintextHex);
  });

  it('reproduces the sealed box byte-for-byte with the fixed ephemeral key', async () => {
    const ephemeralPublicKey = fromHex(vector.ephemeralPublicKeyHex);
    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: toBase64Url(ephemeralPublicKey.slice(1, 33)),
      y: toBase64Url(ephemeralPublicKey.slice(33, 65)),
      d: toBase64Url(fromHex(vector.ephemeralPrivateKeyHex)),
    };
    const ephemeralPrivateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    );

    const box = await sealWithEphemeralKey(
      ephemeralPrivateKey,
      ephemeralPublicKey,
      fromHex(vector.recipientPublicKeyHex),
      vector.recipientKeyId,
      fromHex(vector.plaintextHex),
    );

    expect(serializeSealedKey(box)).toBe(vector.sealed);
  });
});

describe('sealed box behavior', () => {
  it('round-trips through seal, serialize, parse, open', async () => {
    const recipient = await generateKeyPair();
    const plaintext = crypto.getRandomValues(new Uint8Array(32));

    const serialized = serializeSealedKey(await seal(recipient.publicKey, 'ukey_js0000001', plaintext));
    const opened = await open(recipient, parseSealedKey(serialized));

    expect(toHex(opened)).toBe(toHex(plaintext));
  });

  it('rejects opening with the wrong recipient', async () => {
    const recipient = await generateKeyPair();
    const attacker = await generateKeyPair();
    const box = await seal(recipient.publicKey, 'ukey_js0000002', new Uint8Array(32));

    await expect(open(attacker, box)).rejects.toThrow();
  });

  it('rejects tampered ciphertext', async () => {
    const recipient = await generateKeyPair();
    const box = await seal(recipient.publicKey, 'ukey_js0000003', new Uint8Array(32));
    box.ciphertextWithTag[0] ^= 0x01;

    await expect(open(recipient, box)).rejects.toThrow();
  });

  it.each(['', 'not-a-sealed-box', 'sbx.v2.key.AA.BB.CC', 'env.v1.key.AA.BB.CC'])(
    'rejects malformed input %j',
    (value) => {
      expect(() => parseSealedKey(value)).toThrow();
    },
  );

  it('base64url helpers round-trip', () => {
    const bytes = crypto.getRandomValues(new Uint8Array(37));
    expect(toHex(fromBase64Url(toBase64Url(bytes)))).toBe(toHex(bytes));
  });
});

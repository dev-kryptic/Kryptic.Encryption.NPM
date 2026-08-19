/**
 * The Kryptic secret envelope (WebCrypto implementation), byte-compatible with
 * Kryptic.Encryption's SecretEnvelope on nuget.org: `v1.<keyId>.<nonce>.<ciphertext+tag>`
 * (base64url, no padding). AES-256-GCM, 12-byte random nonce, 16-byte tag.
 * Associated data binds a ciphertext to its context (e.g. secret id +
 * environment id) exactly like the server-side engine.
 */

import { fromBase64Url, toBase64Url } from './sealedbox';

export const ENVELOPE_FORMAT_VERSION = 1;

const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const KEY_SIZE = 32;

const KEY_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

export interface Envelope {
  keyId: string;
  nonce: Uint8Array;
  ciphertextWithTag: Uint8Array;
}

export async function encryptEnvelope(
  key: Uint8Array,
  keyId: string,
  plaintext: Uint8Array,
  associatedData?: Uint8Array,
): Promise<string> {
  if (key.length !== KEY_SIZE) throw new Error('Key must be 32 bytes (AES-256).');
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new Error('Key id must be non-empty and contain only [a-zA-Z0-9_-].');
  }

  const aesKey = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, [
    'encrypt',
  ]);
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const ciphertextWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: nonce as BufferSource,
        tagLength: TAG_SIZE * 8,
        ...(associatedData ? { additionalData: associatedData as BufferSource } : {}),
      },
      aesKey,
      plaintext as BufferSource,
    ),
  );

  return serializeEnvelope({ keyId, nonce, ciphertextWithTag });
}

export async function decryptEnvelope(
  key: Uint8Array,
  serialized: string,
  associatedData?: Uint8Array,
): Promise<Uint8Array> {
  if (key.length !== KEY_SIZE) throw new Error('Key must be 32 bytes (AES-256).');
  const envelope = parseEnvelope(serialized);

  const aesKey = await crypto.subtle.importKey('raw', key as BufferSource, 'AES-GCM', false, [
    'decrypt',
  ]);
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: envelope.nonce as BufferSource,
      tagLength: TAG_SIZE * 8,
      ...(associatedData ? { additionalData: associatedData as BufferSource } : {}),
    },
    aesKey,
    envelope.ciphertextWithTag as BufferSource,
  );
  return new Uint8Array(plaintext);
}

export function serializeEnvelope(envelope: Envelope): string {
  return [
    `v${ENVELOPE_FORMAT_VERSION}`,
    envelope.keyId,
    toBase64Url(envelope.nonce),
    toBase64Url(envelope.ciphertextWithTag),
  ].join('.');
}

export function parseEnvelope(value: string): Envelope {
  const parts = value.split('.');
  if (parts.length !== 4 || parts[0] !== `v${ENVELOPE_FORMAT_VERSION}` || !KEY_ID_PATTERN.test(parts[1])) {
    throw new Error('Value is not a valid Kryptic secret envelope.');
  }
  const nonce = fromBase64Url(parts[2]);
  const ciphertextWithTag = fromBase64Url(parts[3]);
  if (nonce.length !== NONCE_SIZE) throw new Error('Envelope nonce must be 12 bytes.');
  if (ciphertextWithTag.length < TAG_SIZE) {
    throw new Error('Envelope ciphertext is shorter than the authentication tag.');
  }
  return { keyId: parts[1], nonce, ciphertextWithTag };
}

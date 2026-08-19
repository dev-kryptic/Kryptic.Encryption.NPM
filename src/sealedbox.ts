/**
 * Kryptic P-256 ECDH sealed box (WebCrypto implementation).
 *
 * Encrypts a value to a recipient's public key so only the holder of the
 * matching private key can open it. This is the asymmetric layer the
 * blind store uses to deliver the org key to each recipient. The wire
 * format and derivation are locked by the interop vectors in
 * interop-vectors/sealed-box-p256.json and must stay byte-compatible with the
 * C# (Kryptic.Encryption.Dotnet) and Go (Kryptic.Encryption.Go) implementations.
 *
 * Construction (ECIES): fresh ephemeral P-256 key pair per message, ECDH against
 * the recipient public key, HKDF-SHA256 expanded to a 32-byte AES key and a
 * 12-byte nonce (derived, not random - the per-message key makes it safe and the
 * seal reproducible), then AES-256-GCM. WebCrypto primitives only.
 */

export const SEALED_BOX_FORMAT_VERSION = 1;

/** Uncompressed SEC1 P-256 point: 0x04 || X(32) || Y(32). */
export const PUBLIC_KEY_SIZE = 65;

const NONCE_SIZE = 12;
const TAG_SIZE = 16;
const AES_KEY_SIZE = 32;

const HKDF_LABEL = new TextEncoder().encode('kryptic-sealed-box-v1');

const EC_PARAMS: EcKeyImportParams = { name: 'ECDH', namedCurve: 'P-256' };

export interface KeyPairBytes {
  /** 65-byte uncompressed SEC1 point. */
  publicKey: Uint8Array;
  /** 32-byte big-endian scalar. */
  privateKey: Uint8Array;
}

export interface SealedKey {
  recipientKeyId: string;
  ephemeralPublicKey: Uint8Array;
  nonce: Uint8Array;
  ciphertextWithTag: Uint8Array;
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

const KEY_ID_PATTERN = /^[a-zA-Z0-9_-]{1,64}$/;

/** Generates a fresh P-256 key pair in the portable byte encodings. */
export async function generateKeyPair(): Promise<KeyPairBytes> {
  const pair = await crypto.subtle.generateKey(EC_PARAMS, true, ['deriveBits']);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  return { publicKey, privateKey: fromBase64Url(jwk.d!) };
}

/** Seals plaintext to the recipient public key with a fresh ephemeral key. */
export async function seal(
  recipientPublicKey: Uint8Array,
  recipientKeyId: string,
  plaintext: Uint8Array,
): Promise<SealedKey> {
  const ephemeral = await crypto.subtle.generateKey(EC_PARAMS, true, ['deriveBits']);
  const ephemeralPublicKey = new Uint8Array(
    await crypto.subtle.exportKey('raw', ephemeral.publicKey),
  );
  return sealWithEphemeralKey(
    ephemeral.privateKey,
    ephemeralPublicKey,
    recipientPublicKey,
    recipientKeyId,
    plaintext,
  );
}

/** Opens a sealed box with the recipient key pair. Throws on any tampering. */
export async function open(recipient: KeyPairBytes, box: SealedKey): Promise<Uint8Array> {
  validatePublicKey(recipient.publicKey);
  const privateKey = await importPrivateKey(recipient);
  const ephemeralPublic = await crypto.subtle.importKey(
    'raw',
    box.ephemeralPublicKey as BufferSource,
    EC_PARAMS,
    false,
    [],
  );

  const shared = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: ephemeralPublic },
    privateKey,
    256,
  );
  const { aesKey } = await deriveKeyAndNonce(
    new Uint8Array(shared),
    box.ephemeralPublicKey,
    recipient.publicKey,
  );

  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: box.nonce as BufferSource, tagLength: TAG_SIZE * 8 },
    aesKey,
    box.ciphertextWithTag as BufferSource,
  );
  return new Uint8Array(plaintext);
}

/**
 * Deterministic seal with a caller-supplied ephemeral key. Exported for the
 * interop known-answer tests only - production code uses {@link seal}.
 */
export async function sealWithEphemeralKey(
  ephemeralPrivateKey: CryptoKey,
  ephemeralPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
  recipientKeyId: string,
  plaintext: Uint8Array,
): Promise<SealedKey> {
  validatePublicKey(recipientPublicKey);
  if (!KEY_ID_PATTERN.test(recipientKeyId)) {
    throw new Error('Recipient key id must be non-empty and contain only [a-zA-Z0-9_-].');
  }

  const recipientKey = await crypto.subtle.importKey(
    'raw',
    recipientPublicKey as BufferSource,
    EC_PARAMS,
    false,
    [],
  );
  const shared = await crypto.subtle.deriveBits(
    { name: 'ECDH', public: recipientKey },
    ephemeralPrivateKey,
    256,
  );
  const { aesKey, nonce } = await deriveKeyAndNonce(
    new Uint8Array(shared),
    ephemeralPublicKey,
    recipientPublicKey,
  );

  const ciphertextWithTag = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, tagLength: TAG_SIZE * 8 },
    aesKey,
    plaintext as BufferSource,
  );

  return {
    recipientKeyId,
    ephemeralPublicKey,
    nonce,
    ciphertextWithTag: new Uint8Array(ciphertextWithTag),
  };
}

/** Builds a WebCrypto ECDH private key from the portable byte encodings via JWK. */
async function importPrivateKey(pair: KeyPairBytes): Promise<CryptoKey> {
  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: toBase64Url(pair.publicKey.slice(1, 33)),
    y: toBase64Url(pair.publicKey.slice(33, 65)),
    d: toBase64Url(pair.privateKey),
  };
  return crypto.subtle.importKey('jwk', jwk, EC_PARAMS, false, ['deriveBits']);
}

/**
 * HKDF-SHA256 over the ECDH shared secret (the x-coordinate), expanded to
 * 44 bytes = 32-byte AES key || 12-byte nonce, bound to both public keys.
 */
async function deriveKeyAndNonce(
  shared: Uint8Array,
  ephemeralPublicKey: Uint8Array,
  recipientPublicKey: Uint8Array,
): Promise<{ aesKey: CryptoKey; nonce: Uint8Array }> {
  const info = new Uint8Array(
    HKDF_LABEL.length + ephemeralPublicKey.length + recipientPublicKey.length,
  );
  info.set(HKDF_LABEL, 0);
  info.set(ephemeralPublicKey, HKDF_LABEL.length);
  info.set(recipientPublicKey, HKDF_LABEL.length + ephemeralPublicKey.length);

  const hkdfKey = await crypto.subtle.importKey('raw', shared as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const okm = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0) as BufferSource,
        info: info as BufferSource,
      },
      hkdfKey,
      (AES_KEY_SIZE + NONCE_SIZE) * 8,
    ),
  );

  const aesKey = await crypto.subtle.importKey(
    'raw',
    okm.slice(0, AES_KEY_SIZE) as BufferSource,
    'AES-GCM',
    false,
    ['encrypt', 'decrypt'],
  );
  return { aesKey, nonce: okm.slice(AES_KEY_SIZE) };
}

/**
 * Serializes to the canonical wire form:
 * `sbx.v1.<recipientKeyId>.<ephemeralPub>.<nonce>.<ciphertext+tag>` (base64url, no padding).
 */
export function serializeSealedKey(box: SealedKey): string {
  return [
    `sbx.v${SEALED_BOX_FORMAT_VERSION}`,
    box.recipientKeyId,
    toBase64Url(box.ephemeralPublicKey),
    toBase64Url(box.nonce),
    toBase64Url(box.ciphertextWithTag),
  ].join('.');
}

/** Parses the canonical wire form. Throws on malformed input. */
export function parseSealedKey(value: string): SealedKey {
  const parts = value.split('.');
  if (
    parts.length !== 6 ||
    parts[0] !== 'sbx' ||
    parts[1] !== `v${SEALED_BOX_FORMAT_VERSION}` ||
    !KEY_ID_PATTERN.test(parts[2])
  ) {
    throw new Error('Value is not a valid Kryptic sealed box.');
  }

  const ephemeralPublicKey = fromBase64Url(parts[3]);
  const nonce = fromBase64Url(parts[4]);
  const ciphertextWithTag = fromBase64Url(parts[5]);

  if (ephemeralPublicKey.length !== PUBLIC_KEY_SIZE || ephemeralPublicKey[0] !== 0x04) {
    throw new Error('Ephemeral public key must be a 65-byte uncompressed SEC1 point.');
  }
  if (nonce.length !== NONCE_SIZE) {
    throw new Error('Sealed box nonce must be 12 bytes.');
  }
  if (ciphertextWithTag.length < TAG_SIZE) {
    throw new Error('Sealed box ciphertext is shorter than the authentication tag.');
  }

  return { recipientKeyId: parts[2], ephemeralPublicKey, nonce, ciphertextWithTag };
}

function validatePublicKey(publicKey: Uint8Array): void {
  if (publicKey.length !== PUBLIC_KEY_SIZE || publicKey[0] !== 0x04) {
    throw new Error('Public key must be a 65-byte uncompressed SEC1 P-256 point.');
  }
}

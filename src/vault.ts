/**
 * High-level vault operations for the end-to-end blind store. Pure crypto
 * orchestration - no React, no HTTP. Everything here runs client-side; no
 * function in this module ever returns key material to a network call except
 * as ciphertext (wrapped keys, sealed boxes) or public keys.
 */

import { ARGON2_V1, deriveKeyFromPassphrase, generateArgon2Salt } from './argon2';
import { decryptEnvelope, encryptEnvelope } from './envelope';
import {
  fromBase64Url,
  generateKeyPair,
  open,
  parseSealedKey,
  seal,
  serializeSealedKey,
  toBase64Url,
  type KeyPairBytes,
} from './sealedbox';

/** Key-id labels for the wrapping envelopes (informational, part of the format). */
const PASSPHRASE_WRAP_KEY_ID = 'vaultpass_v1';
const RECOVERY_WRAP_KEY_ID = 'recovery_v1';
const MACHINE_SECRET_WRAP_KEY_ID = 'machinesecret_v1';

export interface EnrollmentMaterial {
  algorithm: 'P-256';
  publicKey: string;
  wrappedPrivateKey: string;
  kdfSalt: string;
  kdfParametersVersion: number;
}

export interface RecoveryKit {
  /** Show this to the user exactly once. It is never sent anywhere. */
  recoveryCode: string;
  upload: {
    algorithm: 'P-256';
    publicKey: string;
    wrappedPrivateKey: string;
    kdfSalt: string;
    kdfParametersVersion: number;
  };
  /** The recovery key pair, kept only long enough to seal the org key to it. */
  keyPair: KeyPairBytes;
}

/** "key_" + 12 lowercase hex chars, matching the engine's DataKeys.GenerateKeyId. */
export function generateOrgKeyId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return 'key_' + [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A fresh 256-bit org data key. Exists only in client memory until sealed. */
export function generateOrgKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

/**
 * Generates the user key pair and wraps the private key under the vault
 * passphrase. Returns the enrollment payload plus the live key pair so the
 * caller can continue without re-deriving.
 */
export async function createEnrollment(
  passphrase: string,
): Promise<{ upload: EnrollmentMaterial; keyPair: KeyPairBytes }> {
  const keyPair = await generateKeyPair();
  const salt = generateArgon2Salt();
  const passphraseKey = await deriveKeyFromPassphrase(passphrase, salt);
  let wrappedPrivateKey: string;
  try {
    wrappedPrivateKey = await encryptEnvelope(
      passphraseKey,
      PASSPHRASE_WRAP_KEY_ID,
      keyPair.privateKey,
    );
  } finally {
    passphraseKey.fill(0);
  }

  return {
    upload: {
      algorithm: 'P-256',
      publicKey: toBase64Url(keyPair.publicKey),
      wrappedPrivateKey,
      kdfSalt: toBase64Url(salt),
      kdfParametersVersion: ARGON2_V1.version,
    },
    keyPair,
  };
}

/**
 * Re-wraps an already unlocked key pair under a new vault passphrase.
 * The public key is unchanged, so existing org-key grants stay valid.
 */
export async function rewrapPrivateKey(
  keyPair: KeyPairBytes,
  passphrase: string,
): Promise<EnrollmentMaterial> {
  const salt = generateArgon2Salt();
  const passphraseKey = await deriveKeyFromPassphrase(passphrase, salt);
  let wrappedPrivateKey: string;
  try {
    wrappedPrivateKey = await encryptEnvelope(
      passphraseKey,
      PASSPHRASE_WRAP_KEY_ID,
      keyPair.privateKey,
    );
  } finally {
    passphraseKey.fill(0);
  }

  return {
    algorithm: 'P-256',
    publicKey: toBase64Url(keyPair.publicKey),
    wrappedPrivateKey,
    kdfSalt: toBase64Url(salt),
    kdfParametersVersion: ARGON2_V1.version,
  };
}

/**
 * Recovers the user key pair from the passphrase and the server-stored record.
 * Throws if the passphrase is wrong (GCM authentication fails).
 */
export async function unlockPrivateKey(
  passphrase: string,
  record: { publicKey: string; wrappedPrivateKey: string; kdfSalt: string; kdfParametersVersion: number },
): Promise<KeyPairBytes> {
  if (record.kdfParametersVersion !== ARGON2_V1.version) {
    throw new Error(`Unknown KDF parameter set version '${record.kdfParametersVersion}'.`);
  }
  const passphraseKey = await deriveKeyFromPassphrase(passphrase, fromBase64Url(record.kdfSalt));
  let privateKey: Uint8Array;
  try {
    privateKey = await decryptEnvelope(passphraseKey, record.wrappedPrivateKey);
  } finally {
    passphraseKey.fill(0);
  }
  return { publicKey: fromBase64Url(record.publicKey), privateKey };
}

/** Opens the caller's sealed org-key grant with their unlocked key pair. */
export async function unwrapOrgKey(keyPair: KeyPairBytes, wrappedOrgKey: string): Promise<Uint8Array> {
  return open(keyPair, parseSealedKey(wrappedOrgKey));
}

/**
 * The recovery path: the recovery code unwraps the recovery private key, which
 * opens the recovery grant. Throws if the code is wrong (GCM auth failure).
 */
export async function recoverOrgKey(
  recoveryCode: string,
  kit: {
    publicKey: string;
    wrappedPrivateKey: string;
    kdfSalt: string;
    kdfParametersVersion: number;
    wrappedOrgKey: string;
  },
): Promise<Uint8Array> {
  if (kit.kdfParametersVersion !== ARGON2_V1.version) {
    throw new Error(`Unknown KDF parameter set version '${kit.kdfParametersVersion}'.`);
  }
  const code = normalizeRecoveryCode(recoveryCode);
  const recoveryWrapKey = await deriveKeyFromPassphrase(code, fromBase64Url(kit.kdfSalt));
  let recoveryPrivateKey: Uint8Array;
  try {
    recoveryPrivateKey = await decryptEnvelope(recoveryWrapKey, kit.wrappedPrivateKey);
  } finally {
    recoveryWrapKey.fill(0);
  }
  const recoveryPair: KeyPairBytes = {
    publicKey: fromBase64Url(kit.publicKey),
    privateKey: recoveryPrivateKey,
  };
  const orgKey = await open(recoveryPair, parseSealedKey(kit.wrappedOrgKey));
  recoveryPrivateKey.fill(0);
  return orgKey;
}

/** Seals the org key to a recipient public key (member, device, machine, recovery). */
export async function wrapOrgKeyTo(
  recipientPublicKeyBase64Url: string,
  recipientKeyId: string,
  orgKey: Uint8Array,
): Promise<string> {
  const box = await seal(fromBase64Url(recipientPublicKeyBase64Url), recipientKeyId, orgKey);
  return serializeSealedKey(box);
}

/**
 * Generates the Emergency Kit: a recovery key pair whose private key is wrapped
 * by a key derived from a high-entropy recovery code. The code is displayed
 * once and never stored or transmitted.
 */
export async function createRecoveryKit(): Promise<RecoveryKit> {
  const recoveryCode = generateRecoveryCode();
  const keyPair = await generateKeyPair();
  const salt = generateArgon2Salt();
  const recoveryKey = await deriveKeyFromPassphrase(recoveryCode, salt);
  let wrappedPrivateKey: string;
  try {
    wrappedPrivateKey = await encryptEnvelope(recoveryKey, RECOVERY_WRAP_KEY_ID, keyPair.privateKey);
  } finally {
    recoveryKey.fill(0);
  }

  return {
    recoveryCode,
    upload: {
      algorithm: 'P-256',
      publicKey: toBase64Url(keyPair.publicKey),
      wrappedPrivateKey,
      kdfSalt: toBase64Url(salt),
      kdfParametersVersion: ARGON2_V1.version,
    },
    keyPair,
  };
}

/**
 * Marks v2 machine client secrets. A "ksm2_" secret never goes on the wire:
 * the machine presents machineAuthSecretForToken(secret) at token exchange
 * and uses the full secret only locally, to unwrap its private key, so the
 * server never sees anything that can derive the wrap key.
 */
export const MACHINE_SECRET_V2_PREFIX = 'ksm2_';

const MACHINE_AUTH_SALT = new TextEncoder().encode('kryptic.machine.auth.v2');
const MACHINE_AUTH_INFO = new TextEncoder().encode('auth');

/**
 * The value a machine presents at token exchange: for v2 secrets,
 * base64url(HKDF-SHA256(secret, salt, info, 32)), locked by
 * interop-vectors/machine-auth.json. Legacy secrets (no prefix) pass through
 * unchanged so machines created before v2 keep working until rotated.
 */
export async function machineAuthSecretForToken(clientSecret: string): Promise<string> {
  if (!clientSecret.startsWith(MACHINE_SECRET_V2_PREFIX)) return clientSecret;

  const ikm = new TextEncoder().encode(clientSecret);
  const hkdfKey = await crypto.subtle.importKey('raw', ikm as BufferSource, 'HKDF', false, [
    'deriveBits',
  ]);
  const derived = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: MACHINE_AUTH_SALT as BufferSource,
      info: MACHINE_AUTH_INFO as BufferSource,
    },
    hkdfKey,
    256,
  );
  return toBase64Url(new Uint8Array(derived));
}

export interface MachineMaterial {
  /**
   * Show once, then it exists nowhere but with the operator. Only the derived
   * clientAuthSecret (and its hash) ever exists server-side.
   */
  clientSecret: string;
  upload: {
    clientAuthSecret: string;
    publicKey: string;
    wrappedPrivateKey: string;
    kdfSalt: string;
    kdfParametersVersion: number;
    orgKeyId: string;
    wrappedOrgKey: string;
  };
}

/**
 * The machine-identity crypto ceremony (creation and rotation): generates the
 * "ksm2_" client secret and the machine key pair, wraps the private key under
 * an Argon2id key derived from the full secret, and seals the unlocked org key
 * to the machine public key. Only the domain-separated auth secret is uploaded;
 * the raw secret never leaves the browser except to the operator's clipboard.
 * The CI client later reverses this with nothing but its clientId/clientSecret.
 */
export async function createMachineMaterial(
  orgKey: Uint8Array,
  orgKeyId: string,
): Promise<MachineMaterial> {
  // 32 random bytes base64url behind the version prefix - same entropy as
  // server-issued opaque tokens.
  const clientSecret =
    MACHINE_SECRET_V2_PREFIX + toBase64Url(crypto.getRandomValues(new Uint8Array(32)));

  const keyPair = await generateKeyPair();
  const salt = generateArgon2Salt();
  const secretKey = await deriveKeyFromPassphrase(clientSecret, salt);
  let wrappedPrivateKey: string;
  try {
    wrappedPrivateKey = await encryptEnvelope(
      secretKey,
      MACHINE_SECRET_WRAP_KEY_ID,
      keyPair.privateKey,
    );
  } finally {
    secretKey.fill(0);
  }
  const publicKey = toBase64Url(keyPair.publicKey);
  const wrappedOrgKey = await wrapOrgKeyTo(publicKey, orgKeyId, orgKey);
  keyPair.privateKey.fill(0);

  return {
    clientSecret,
    upload: {
      clientAuthSecret: await machineAuthSecretForToken(clientSecret),
      publicKey,
      wrappedPrivateKey,
      kdfSalt: toBase64Url(salt),
      kdfParametersVersion: ARGON2_V1.version,
      orgKeyId,
      wrappedOrgKey,
    },
  };
}

/**
 * 160 bits rendered as 8 groups of 4 (Crockford base32, no ambiguous chars),
 * e.g. "MZK4-9DQ2-...". Grouped for transcription; normalized before derivation.
 */
export function generateRecoveryCode(): string {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  let code = '';
  for (let i = 0; i < 32; i++) {
    // 5 bits per character from a 160-bit pool (uses the first 32*5=160 bits).
    const bitIndex = i * 5;
    const byteIndex = bitIndex >> 3;
    const shift = bitIndex & 7;
    const value = ((bytes[byteIndex] << 8) | (bytes[byteIndex + 1] ?? 0)) >> (11 - shift);
    code += alphabet[value & 31];
    if (i % 4 === 3 && i !== 31) code += '-';
  }
  return code;
}

/** Normalizes a typed recovery code (case, separators) before derivation. */
export function normalizeRecoveryCode(code: string): string {
  const cleaned = code.toUpperCase().replace(/[^0-9A-Z]/g, '');
  return cleaned.replace(/(.{4})(?=.)/g, '$1-');
}

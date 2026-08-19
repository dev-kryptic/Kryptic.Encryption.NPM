/**
 * Argon2id key derivation for the browser (hash-wasm), matching the engine's
 * versioned parameter sets. The derived key wraps the user's vault private key -
 * the passphrase and derived key never leave the client.
 *
 * Parameter set V1 mirrors the C# Argon2Parameters.V1 and is locked by
 * interop-vectors/argon2id.json.
 */
import { argon2id } from 'hash-wasm';

export interface Argon2Parameters {
  version: number;
  memoryKibibytes: number;
  iterations: number;
  parallelism: number;
}

export const ARGON2_V1: Argon2Parameters = {
  version: 1,
  memoryKibibytes: 64 * 1024,
  iterations: 3,
  parallelism: 4,
};

export const ARGON2_SALT_SIZE = 16;
export const ARGON2_KEY_SIZE = 32;

export function argon2ParametersForVersion(version: number): Argon2Parameters {
  if (version === 1) return ARGON2_V1;
  throw new Error(`Unknown Argon2 parameter set version '${version}'.`);
}

export function generateArgon2Salt(): Uint8Array {
  const salt = new Uint8Array(ARGON2_SALT_SIZE);
  crypto.getRandomValues(salt);
  return salt;
}

/** Derives a 256-bit key from a passphrase. Blocking work happens inside WASM. */
export async function deriveKeyFromPassphrase(
  passphrase: string,
  salt: Uint8Array,
  parameters: Argon2Parameters = ARGON2_V1,
): Promise<Uint8Array> {
  if (salt.length !== ARGON2_SALT_SIZE) {
    throw new Error(`Salt must be ${ARGON2_SALT_SIZE} bytes.`);
  }

  return argon2id({
    password: passphrase,
    salt,
    memorySize: parameters.memoryKibibytes,
    iterations: parameters.iterations,
    parallelism: parameters.parallelism,
    hashLength: ARGON2_KEY_SIZE,
    outputType: 'binary',
  });
}

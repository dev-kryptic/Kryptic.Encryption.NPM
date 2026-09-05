import { describe, expect, it } from 'vitest';
import { createEnrollment, rewrapPrivateKey, unlockPrivateKey } from '../src/vault';

describe('vault passphrase wrap', () => {
  it('rewraps the same key pair under a new passphrase', async () => {
    const { upload, keyPair } = await createEnrollment('old-passphrase-long');
    const rewrapped = await rewrapPrivateKey(keyPair, 'new-passphrase-long');

    expect(rewrapped.publicKey).toBe(upload.publicKey);
    expect(rewrapped.kdfSalt).not.toBe(upload.kdfSalt);
    expect(rewrapped.wrappedPrivateKey).not.toBe(upload.wrappedPrivateKey);

    const opened = await unlockPrivateKey('new-passphrase-long', rewrapped);
    expect(opened.publicKey).toEqual(keyPair.publicKey);
    expect(opened.privateKey).toEqual(keyPair.privateKey);

    await expect(unlockPrivateKey('old-passphrase-long', rewrapped)).rejects.toThrow();
  });
});

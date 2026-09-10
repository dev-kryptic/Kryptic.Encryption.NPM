import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import {
  MACHINE_SECRET_V2_PREFIX,
  createMachineMaterial,
  generateOrgKey,
  generateOrgKeyId,
  machineAuthSecretForToken,
} from '../src/vault';

const vectorsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'interop-vectors');
const vector = JSON.parse(readFileSync(join(vectorsDir, 'machine-auth.json'), 'utf8'));

describe('machine auth derivation (must match C# and Go)', () => {
  it('reproduces the interop vector', async () => {
    expect(await machineAuthSecretForToken(vector.clientSecret)).toBe(vector.authSecret);
  });

  it('passes legacy secrets through unchanged', async () => {
    const legacy = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    expect(await machineAuthSecretForToken(legacy)).toBe(legacy);
  });
});

describe('machine material ceremony', () => {
  it('never uploads the raw client secret', async () => {
    const material = await createMachineMaterial(generateOrgKey(), generateOrgKeyId());

    expect(material.clientSecret.startsWith(MACHINE_SECRET_V2_PREFIX)).toBe(true);
    expect(material.upload.clientAuthSecret).not.toBe(material.clientSecret);
    expect(material.upload.clientAuthSecret).toBe(
      await machineAuthSecretForToken(material.clientSecret),
    );
    expect(JSON.stringify(material.upload)).not.toContain(material.clientSecret);
  });
});

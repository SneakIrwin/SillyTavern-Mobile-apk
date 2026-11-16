import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export function verifyApkSigner(output, expected) {
  const observed = [...new Set([...output.matchAll(/^Signer\b[^\r\n]*certificate SHA-256 digest:\s*([0-9a-f]{64})\s*$/gim)]
    .map((match) => match[1].toLowerCase()))];
  if (observed.length !== 1 || observed[0] !== expected.toLowerCase()) {
    throw new Error(`APK upgrade signer mismatch: expected ${expected}; observed ${JSON.stringify(observed)}`);
  }
  return observed[0];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const policy = JSON.parse(readFileSync(new URL('./release-signing.json', import.meta.url), 'utf8'));
  const output = readFileSync(process.argv[2], 'utf8');
  try { console.log(`Verified APK upgrade signer: ${verifyApkSigner(output, policy.certificateSha256)}`); }
  catch (error) { console.error(output); throw error; }
}

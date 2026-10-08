'use strict';
// Roster key handling for provision.yml (Node built-ins only; no dependencies).
//
// The server seals each student's { github, name, email } to this repo's roster PUBLIC key, so the server
// (and its queue and database) can never read it. The private key lives only in this repo's Actions secret
// CLASSREPO_ROSTER_PRIVATE_KEY. Format (matches server/src/lib/seal.js in class-repo-site):
//   v1.<keyId>.<RSA-OAEP(SHA-256) wrapped AES key>.<iv>.<AES-256-GCM ciphertext+tag>     (base64url parts)

const crypto = require('crypto');

const AAD = Buffer.from('classrepo-roster-v1');

/** Generates a new 3072-bit RSA pair. publicKeyB64 is base64 SPKI DER; privateKeyPem is PKCS#8 PEM. */
function generateRosterKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKeyB64: publicKey.toString('base64'), privateKeyPem: privateKey };
}

/** First 8 bytes of SHA-256 over the SPKI DER, as hex. The server computes the same value. */
function keyId(publicKeyB64) {
  return crypto.createHash('sha256').update(Buffer.from(publicKeyB64, 'base64')).digest().subarray(0, 8).toString('hex');
}

/** Opens one sealed record. Throws if it was sealed to a different key or has been tampered with. */
function openSealed(sealed, privateKeyPem) {
  const [version, , wrapped, iv, ciphertext] = String(sealed).split('.');
  if (version !== 'v1' || !wrapped || !iv || !ciphertext) throw new Error('Unrecognised sealed record');
  const aesKey = crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(wrapped, 'base64url'));
  const data = Buffer.from(ciphertext, 'base64url');
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(iv, 'base64url'));
  decipher.setAAD(AAD);
  decipher.setAuthTag(data.subarray(data.length - 16));
  const plain = Buffer.concat([decipher.update(data.subarray(0, data.length - 16)), decipher.final()]);
  return JSON.parse(plain.toString('utf8'));
}

module.exports = { generateRosterKeyPair, keyId, openSealed };

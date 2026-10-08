'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const vector = require('./vector.json');
const { generateRosterKeyPair, keyId, openSealed } = require('../scripts/roster-crypto');

test('opens a record sealed by the ClassRepo server (interop vector)', () => {
  // vector.json is produced by server/src/lib/seal.js in class-repo-site. If either side changes the format, this fails.
  assert.deepEqual(openSealed(vector.sealed, vector.privateKeyPem), vector.record);
});

test('key id matches the one the server computed', () => {
  assert.equal(keyId(vector.publicKeyB64), vector.keyId);
  assert.equal(vector.sealed.split('.')[1], vector.keyId);
});

test('rejects a record sealed to a different key', () => {
  const other = generateRosterKeyPair();
  assert.throws(() => openSealed(vector.sealed, other.privateKeyPem));
});

test('rejects tampered or malformed records', () => {
  const parts = vector.sealed.split('.');
  const bytes = Buffer.from(parts[4], 'base64url');
  bytes[0] ^= 1;
  parts[4] = bytes.toString('base64url');
  assert.throws(() => openSealed(parts.join('.'), vector.privateKeyPem));
  assert.throws(() => openSealed('nonsense', vector.privateKeyPem));
  assert.throws(() => openSealed(vector.sealed.replace(/^v1/, 'v2'), vector.privateKeyPem));
});

test('generates a usable 3072-bit pair', () => {
  const { publicKeyB64, privateKeyPem } = generateRosterKeyPair();
  const key = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
  assert.equal(key.asymmetricKeyDetails.modulusLength, 3072);
  assert.match(privateKeyPem, /BEGIN PRIVATE KEY/);
});

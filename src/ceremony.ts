import crypto from 'node:crypto';
import { PrivateKey, PublicKey, Signature, Field } from 'o1js';
import { splitKey, combineShares } from './mina-shamir.js';

// Type tag for raw share payloads
const TAG_SHARE = 0x01;
// Type tag for (share, nonce) pair payloads
const TAG_PAIR = 0x02;

// RFC8410 DER prefixes for X25519 keys
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const X25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b656e04220420', 'hex');

function rawToPublicKey(raw: Uint8Array): crypto.KeyObject {
  return crypto.createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

function rawToPrivateKey(raw: Uint8Array): crypto.KeyObject {
  return crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
}

function publicKeyToRaw(key: crypto.KeyObject): Uint8Array {
  const der = key.export({ format: 'der', type: 'spki' });
  return new Uint8Array(der.subarray(X25519_SPKI_PREFIX.length));
}

function privateKeyToRaw(key: crypto.KeyObject): Uint8Array {
  const der = key.export({ format: 'der', type: 'pkcs8' });
  return new Uint8Array(der.subarray(X25519_PKCS8_PREFIX.length));
}

/**
 * ECIES seal: encrypt plaintext for a recipient's X25519 public key
 * Wire format: eph_pk(32) || iv(12) || tag(16) || ciphertext
 */
function sealBox(plaintext: Uint8Array, recipientPkRaw: Uint8Array): Uint8Array {
  const recipientPk = rawToPublicKey(recipientPkRaw);

  const ephemeral = crypto.generateKeyPairSync('x25519');
  const ephPkRaw = publicKeyToRaw(ephemeral.publicKey);

  const sharedSecret = crypto.diffieHellman({
    privateKey: ephemeral.privateKey,
    publicKey: recipientPk,
  });

  const info = Buffer.concat([
    Buffer.from('sealed-box'),
    ephPkRaw,
    recipientPkRaw,
  ]);
  const derivedKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), info, 32);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(derivedKey), iv);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // eph_pk(32) || iv(12) || tag(16) || ciphertext
  const result = new Uint8Array(32 + 12 + 16 + encrypted.length);
  result.set(ephPkRaw, 0);
  result.set(iv, 32);
  result.set(tag, 44);
  result.set(encrypted, 60);
  return result;
}

/**
 * ECIES open: decrypt sealed box with recipient's X25519 private key.
 * Derives the public key internally, no need for the caller to provide it.
 */
function openBox(sealed: Uint8Array, recipientSkRaw: Uint8Array): Uint8Array {
  const recipientSk = rawToPrivateKey(recipientSkRaw);
  const recipientPk = crypto.createPublicKey(recipientSk);
  const recipientPkRaw = publicKeyToRaw(recipientPk);

  const ephPkRaw = sealed.subarray(0, 32);
  const iv = sealed.subarray(32, 44);
  const tag = sealed.subarray(44, 60);
  const ciphertext = sealed.subarray(60);

  const ephPk = rawToPublicKey(ephPkRaw);

  const sharedSecret = crypto.diffieHellman({
    privateKey: recipientSk,
    publicKey: ephPk,
  });

  const info = Buffer.concat([
    Buffer.from('sealed-box'),
    ephPkRaw,
    recipientPkRaw,
  ]);
  const derivedKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(0), info, 32);

  const decipher = crypto.createDecipheriv('aes-256-gcm', Buffer.from(derivedKey), iv);
  decipher.setAuthTag(tag);
  return new Uint8Array(Buffer.concat([decipher.update(ciphertext), decipher.final()]));
}

/**
 * Convert a message to an array of Fields (one Field per byte).
 * Needed for Mina signature creation and verification.
 */
export function messageToFields(message: Uint8Array): Field[] {
  return Array.from(message, (b) => Field(b));
}

/**
 * Generate an X25519 keypair for share encryption.
 * Keys are 32 bytes each.
 */
export function generateSecretKey(): {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
} {
  const kp = crypto.generateKeyPairSync('x25519');
  return {
    publicKey: publicKeyToRaw(kp.publicKey),
    privateKey: privateKeyToRaw(kp.privateKey),
  };
}

/**
 * Generate a Mina private key, sign a message, and distribute encrypted shares to participants.
 *
 * @param threshold - Minimum shares needed to reconstruct (>= 2)
 * @param publicKeys - X25519 public keys of all participants
 * @param message - Message to sign (non-empty)
 * @returns Signature, encrypted shares (one per participant) and the Mina public key
 */
export async function generateAndSign(
  threshold: number,
  publicKeys: Uint8Array[],
  message: Uint8Array
): Promise<{
  signature: Signature;
  encryptedShares: string[];
  publicKey: PublicKey;
}> {
  if (threshold < 2) throw new Error('Threshold must be at least 2');
  if (publicKeys.length < 2)
    throw new Error('Need at least 2 participants');
  if (threshold > publicKeys.length)
    throw new Error('Threshold cannot exceed number of participants');
  if (message.length < 1) throw new Error('Message must not be empty');

  const skMina = PrivateKey.random();
  const pkMina = skMina.toPublicKey();

  const signature = Signature.create(skMina, messageToFields(message));

  const hexShares = await splitKey(skMina, publicKeys.length, threshold);

  const encryptedShares = hexShares.map((hex, i) => {
    const shareBytes = new Uint8Array(Buffer.from(hex, 'hex'));
    const tagged = new Uint8Array(1 + shareBytes.length);
    tagged[0] = TAG_SHARE;
    tagged.set(shareBytes, 1);
    const ciphertext = sealBox(tagged, publicKeys[i]);
    return Buffer.from(ciphertext).toString('hex');
  });

  return { signature, encryptedShares, publicKey: pkMina };
}

/**
 * Recode an encrypted share for a coordinator.
 *
 * Decrypts the share with the participant's key, pairs it with a nonce and re-encrypts for the coordinator.
 *
 * @param encodedShare - Hex-encoded encrypted share
 * @param recipientPk - Coordinator's X25519 public key
 * @param originalSk - Participant's X25519 secret key
 * @param nonce - Session nonce (must match what coordinator expects)
 * @returns Hex-encoded encrypted (share, nonce) pair
 */
export function recodeShare(
  encodedShare: string,
  recipientPk: Uint8Array,
  originalSk: Uint8Array,
  nonce: bigint
): string {
  const ciphertext = new Uint8Array(Buffer.from(encodedShare, 'hex'));
  const tagged = openBox(ciphertext, originalSk);

  if (tagged[0] !== TAG_SHARE) {
    throw new Error(
      `Expected share tag (0x${TAG_SHARE.toString(16)}), got 0x${tagged[0].toString(16)}`
    );
  }
  const shareBytes = tagged.slice(1);
  const shareHex = Buffer.from(shareBytes).toString('hex');

  const pairJson = JSON.stringify({
    v: 1,
    share: shareHex,
    nonce: nonce.toString(),
  });
  const pairBytes = new TextEncoder().encode(pairJson);
  const taggedPair = new Uint8Array(1 + pairBytes.length);
  taggedPair[0] = TAG_PAIR;
  taggedPair.set(pairBytes, 1);

  const encrypted = sealBox(taggedPair, recipientPk);
  return Buffer.from(encrypted).toString('hex');
}

/**
 * Reconstruct the Mina private key from recoded shares and sign a message.
 *
 * @param sk - Coordinator's X25519 secret key
 * @param encodedShares - Hex-encoded recoded shares
 * @param message - Message to sign (non-empty)
 * @param nonce - Expected session nonce
 * @param expectedPublicKey - Expected Mina public key (integrity check)
 * @returns Mina Signature
 */
export async function sign(
  sk: Uint8Array,
  encodedShares: string[],
  message: Uint8Array,
  nonce: bigint,
  expectedPublicKey: PublicKey
): Promise<Signature> {
  if (encodedShares.length < 2)
    throw new Error('Need at least 2 shares');

  const hexShares: string[] = [];

  for (const encoded of encodedShares) {
    const ciphertext = new Uint8Array(Buffer.from(encoded, 'hex'));
    const tagged = openBox(ciphertext, sk);

    if (tagged[0] !== TAG_PAIR) {
      throw new Error(
        `Expected pair tag (0x${TAG_PAIR.toString(16)}), got 0x${tagged[0].toString(16)}`
      );
    }
    const pairBytes = tagged.slice(1);
    const pairJson = new TextDecoder().decode(pairBytes);
    const pair = JSON.parse(pairJson) as {
      v: number;
      share: string;
      nonce: string;
    };

    if (BigInt(pair.nonce) !== nonce) {
      throw new Error('Nonce mismatch');
    }

    hexShares.push(pair.share);
  }

  const skMina = await combineShares(hexShares);

  if (skMina.toPublicKey().toBase58() !== expectedPublicKey.toBase58()) {
    throw new Error(
      'Reconstructed key does not match expected public key'
    );
  }

  return Signature.create(skMina, messageToFields(message));
}

# Shamir's Secret Sharing for Mina Keypairs

Split a Mina private key into `n` shares so that any `t` can reconstruct it, with a ceremony protocol for threshold signing between participants. Built on [Privy's audited `shamir-secret-sharing` library](https://github.com/privy-io/shamir-secret-sharing) (audited by Cure53 and Zellic).

## Quick Start

```bash
npm install
npm run build
npm test
```

## Ceremony Protocol

The ceremony lets a group of participants collectively hold a Mina private key and produce signatures without any single party ever seeing the full key. It runs in three phases:

1. Generate: create a Mina keypair, sign a message, split the key into encrypted shares (one per participant)
2. Recode: each participant decrypts their share and re-encrypts it for the coordinator
3. Sign: the coordinator reconstructs the key from recoded shares, signs a message, and the key is discarded

### `generateSecretKey()`

Generate an X25519 keypair for share encryption. Each participant needs one.

```typescript
import { generateSecretKey } from 'o1js-privkey-sss';

const { publicKey, privateKey } = generateSecretKey();
// publicKey:  Uint8Array (32 bytes)
// privateKey: Uint8Array (32 bytes)
```

### `generateAndSign(threshold, publicKeys, message)`

Phase 1. Creates a Mina keypair, signs the message, splits the private key into shares encrypted to each participant's X25519 public key.

```typescript
import { generateAndSign } from 'o1js-privkey-sss';

const { signature, encryptedShares, publicKey } = await generateAndSign(
  2,                    // threshold: need 2-of-3 to reconstruct
  [pk1, pk2, pk3],      // X25519 public keys of all participants
  message               // Uint8Array, non-empty
);
// signature:       Signature (Mina)
// encryptedShares: string[] (hex, one per participant)
// publicKey:       PublicKey (Mina)
```

### `recodeShare(encodedShare, recipientPk, originalSk, nonce)`

Phase 2. A participant decrypts their share and re-encrypts it for the coordinator, bundled with a session nonce.

```typescript
import { recodeShare } from 'o1js-privkey-sss';

const recodedShare = recodeShare(
  encryptedShares[0],     // hex-encoded encrypted share
  coordinator.publicKey,  // coordinator's X25519 public key
  participants[0].privateKey, // this participant's X25519 secret key
  nonce                   // bigint, must match what coordinator expects
);
// recodedShare: string (hex)
```

### `sign(sk, encodedShares, message, nonce, expectedPublicKey)`

Phase 3. The coordinator decrypts the recoded shares, reconstructs the Mina private key, verifies it matches the expected public key, and signs.

```typescript
import { sign } from 'o1js-privkey-sss';

const signature = await sign(
  coordinator.privateKey,  // coordinator's X25519 secret key
  [recodedShare0, recodedShare1], // hex-encoded recoded shares (>= threshold)
  message,                 // same message as phase 1
  nonce,                   // same nonce participants used
  expectedPublicKey        // PublicKey from phase 1 (integrity check)
);
// signature: Signature (Mina)
```

### `messageToFields(message)`

Converts a `Uint8Array` message to `Field[]` (one Field per byte). Use this to verify signatures returned by the ceremony.

```typescript
import { messageToFields } from 'o1js-privkey-sss';

const valid = signature.verify(publicKey, messageToFields(message)).toBoolean();
```

### Full example

A complete 2-of-3 ceremony:

```typescript
import {
  generateSecretKey,
  generateAndSign,
  recodeShare,
  sign,
  messageToFields,
} from 'o1js-privkey-sss';

const message = new TextEncoder().encode('hello mina');

// Each participant generates an X25519 keypair
const alice = generateSecretKey();
const bob = generateSecretKey();
const carol = generateSecretKey();

// Phase 1: generate key, sign, distribute encrypted shares
const { signature: sig1, encryptedShares, publicKey: pkMina } =
  await generateAndSign(2, [alice.publicKey, bob.publicKey, carol.publicKey], message);

// Phase 2: participants recode their shares for the coordinator
const coordinator = generateSecretKey();
const nonce = BigInt(Date.now());

const recodedAlice = recodeShare(
  encryptedShares[0], coordinator.publicKey, alice.privateKey, nonce
);
const recodedBob = recodeShare(
  encryptedShares[1], coordinator.publicKey, bob.privateKey, nonce
);

// Phase 3: coordinator reconstructs and signs (only needs 2 of 3)
const sig2 = await sign(
  coordinator.privateKey,
  [recodedAlice, recodedBob],
  message,
  nonce,
  pkMina
);

// Both signatures verify against the same Mina public key
sig1.verify(pkMina, messageToFields(message)).toBoolean(); // true
sig2.verify(pkMina, messageToFields(message)).toBoolean(); // true
```

## Share Encryption

Shares are encrypted using an ECIES construction built entirely on Node.js `crypto`, no external dependencies for encryption. The scheme uses X25519 for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for authenticated encryption. Wire format: `ephemeral_pk(32) || iv(12) || tag(16) || ciphertext`.

## Low-level API

If you just want splitting and reconstruction without the ceremony protocol:

### `splitKey(privateKey, totalShares, threshold): Promise<string[]>`

Splits a Mina `PrivateKey` into `totalShares` shares, requiring `threshold` to reconstruct. Returns an array of hex-encoded share strings.

```typescript
import { PrivateKey } from 'o1js';
import { splitKey } from 'o1js-privkey-sss';

const key = PrivateKey.random();
const shares = await splitKey(key, 3, 2); // 2-of-3 scheme
// shares = ['a1b2c3...', 'd4e5f6...', '789abc...']
```

### `combineShares(shares): Promise<PrivateKey>`

Recovers the original `PrivateKey` from a threshold number of hex-encoded shares.

```typescript
import { combineShares } from 'o1js-privkey-sss';

const recovered = await combineShares([shares[0], shares[2]]);
// recovered.toBase58() === key.toBase58()
```

## How It Works

```
Split:   PrivateKey -> Base58 string -> UTF-8 bytes -> SSS split() -> hex strings
Combine: hex strings -> byte arrays -> SSS combine() -> UTF-8 decode -> PrivateKey.fromBase58()
```

The key is serialized to its Base58 representation (plain ASCII) before splitting. This avoids any dependency on o1js internal Field representation and gives a free validity check on reconstruction via `PrivateKey.fromBase58()`.

Shares are output as hex strings so it's portable.

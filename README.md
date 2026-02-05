# Shamir's Secret Sharing for Mina Keypairs

Split a Mina private key into `n` shares so that any `t` of them can reconstruct the original key. Built on [Privy's audited `shamir-secret-sharing` library](https://github.com/privy-io/shamir-secret-sharing) (audited by Cure53 and Zellic).

## Quick Start

```bash
npm install
npm run build
npm test
```

## API

### `splitKey(privateKey, totalShares, threshold): Promise<string[]>`

Splits a Mina `PrivateKey` into `totalShares` shares, requiring `threshold` to reconstruct. Returns an array of hex-encoded share strings.

```typescript
import { PrivateKey } from 'o1js';
import { splitKey } from './src/mina-shamir.js';

const key = PrivateKey.random();
const shares = await splitKey(key, 3, 2); // 2-of-3 scheme
// shares = ['a1b2c3...', 'd4e5f6...', '789abc...']
```

### `combineShares(shares): Promise<PrivateKey>`

Recovers the original `PrivateKey` from a threshold number of hex-encoded shares.

```typescript
import { combineShares } from './src/mina-shamir.js';

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
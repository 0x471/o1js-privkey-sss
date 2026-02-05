import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PrivateKey } from 'o1js';
import { splitKey, combineShares } from './mina-shamir.js';

describe('mina-shamir', () => {
  it('roundtrip 2-of-3', async () => {
    const key = PrivateKey.random();
    const shares = await splitKey(key, 3, 2);
    assert.equal(shares.length, 3);

    const recovered = await combineShares([shares[0], shares[1]]);
    assert.equal(recovered.toBase58(), key.toBase58());
  });

  it('roundtrip 3-of-5', async () => {
    const key = PrivateKey.random();
    const shares = await splitKey(key, 5, 3);
    assert.equal(shares.length, 5);

    const recovered = await combineShares([shares[0], shares[2], shares[4]]);
    assert.equal(recovered.toBase58(), key.toBase58());
  });

  it('all combos of 2-of-3 recover the key', async () => {
    const key = PrivateKey.random();
    const shares = await splitKey(key, 3, 2);

    const combos: [number, number][] = [[0, 1], [0, 2], [1, 2]];
    for (const [i, j] of combos) {
      const recovered = await combineShares([shares[i], shares[j]]);
      assert.equal(
        recovered.toBase58(),
        key.toBase58(),
        `combo (${i},${j}) failed`
      );
    }
  });

  it('below threshold does NOT recover the key', async () => {
    const key = PrivateKey.random();
    const shares = await splitKey(key, 3, 2);

    await assert.rejects(
      async () => {
        const recovered = await combineShares([shares[0]]);
        // If combine doesn't throw, the recovered key should differ
        assert.notEqual(recovered.toBase58(), key.toBase58());
      }
    );
  });

  it('minimum scheme 2-of-2', async () => {
    const key = PrivateKey.random();
    const shares = await splitKey(key, 2, 2);
    assert.equal(shares.length, 2);

    const recovered = await combineShares(shares);
    assert.equal(recovered.toBase58(), key.toBase58());
  });

  it('multiple keys do not cross-contaminate', async () => {
    const key1 = PrivateKey.random();
    const key2 = PrivateKey.random();

    const shares1 = await splitKey(key1, 3, 2);
    const shares2 = await splitKey(key2, 3, 2);

    const recovered1 = await combineShares([shares1[0], shares1[1]]);
    const recovered2 = await combineShares([shares2[0], shares2[1]]);

    assert.equal(recovered1.toBase58(), key1.toBase58());
    assert.equal(recovered2.toBase58(), key2.toBase58());
    assert.notEqual(recovered1.toBase58(), recovered2.toBase58());
  });
});

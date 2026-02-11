import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Signature } from 'o1js';
import {
  generateSecretKey,
  generateAndSign,
  recodeShare,
  sign,
  messageToFields,
} from './ceremony.js';

const msg = new TextEncoder().encode('hello mina');

describe('ceremony', () => {
  it('generateSecretKey produces 32-byte keys', () => {
    const kp1 = generateSecretKey();
    const kp2 = generateSecretKey();
    assert.equal(kp1.publicKey.length, 32);
    assert.equal(kp1.privateKey.length, 32);
    assert.equal(kp2.publicKey.length, 32);
    assert.equal(kp2.privateKey.length, 32);
    // Two keypairs must differ
    assert.notDeepEqual(kp1.publicKey, kp2.publicKey);
    assert.notDeepEqual(kp1.privateKey, kp2.privateKey);
  });

  it('generateAndSign 2-of-3 returns correct shape and valid signature', async () => {
    const participants = [generateSecretKey(), generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const result = await generateAndSign(2, pks, msg);

    assert.equal(result.encryptedShares.length, 3);
    assert.ok(result.publicKey);
    assert.ok(result.signature);

    const valid = result.signature
      .verify(result.publicKey, messageToFields(msg))
      .toBoolean();
    assert.ok(valid, 'Signature from generateAndSign must verify');
  });

  it('full ceremony e2e 2-of-3', async () => {
    const participants = [generateSecretKey(), generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const { signature: sig1, encryptedShares, publicKey: pkMina } =
      await generateAndSign(2, pks, msg);

    // coordinator setup
    const coordinator = generateSecretKey();
    const nonce = BigInt(Date.now());

    // Recode shares from participants 0 and 1
    const recoded0 = recodeShare(
      encryptedShares[0],
      coordinator.publicKey,
      participants[0].privateKey,
      nonce
    );
    const recoded1 = recodeShare(
      encryptedShares[1],
      coordinator.publicKey,
      participants[1].privateKey,
      nonce
    );

    // coordinator signs
    const sig2 = await sign(
      coordinator.privateKey,
      [recoded0, recoded1],
      msg,
      nonce,
      pkMina
    );

    // Both signatures verify against same pkMina
    assert.ok(sig1.verify(pkMina, messageToFields(msg)).toBoolean());
    assert.ok(sig2.verify(pkMina, messageToFields(msg)).toBoolean());
  });

  it('all 2-of-3 share combinations work', async () => {
    const participants = [generateSecretKey(), generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const { encryptedShares, publicKey: pkMina } =
      await generateAndSign(2, pks, msg);

    const combos: [number, number][] = [
      [0, 1],
      [0, 2],
      [1, 2],
    ];

    for (const [i, j] of combos) {
      const coordinator = generateSecretKey();
      const nonce = BigInt(Date.now()) + BigInt(i * 10 + j);

      const recodedI = recodeShare(
        encryptedShares[i],
        coordinator.publicKey,
        participants[i].privateKey,
        nonce
      );
      const recodedJ = recodeShare(
        encryptedShares[j],
        coordinator.publicKey,
        participants[j].privateKey,
        nonce
      );

      const sig = await sign(
        coordinator.privateKey,
        [recodedI, recodedJ],
        msg,
        nonce,
        pkMina
      );

      assert.ok(
        sig.verify(pkMina, messageToFields(msg)).toBoolean(),
        `Combo (${i},${j}) failed`
      );
    }
  });

  it('full ceremony 3-of-5', async () => {
    const participants = Array.from({ length: 5 }, () => generateSecretKey());
    const pks = participants.map((p) => p.publicKey);

    const { encryptedShares, publicKey: pkMina } =
      await generateAndSign(3, pks, msg);

    const coordinator = generateSecretKey();
    const nonce = BigInt(42);

    const recoded = [0, 2, 4].map((i) =>
      recodeShare(
        encryptedShares[i],
        coordinator.publicKey,
        participants[i].privateKey,
        nonce
      )
    );

    const sig = await sign(
      coordinator.privateKey,
      recoded,
      msg,
      nonce,
      pkMina
    );

    assert.ok(sig.verify(pkMina, messageToFields(msg)).toBoolean());
  });

  // --- Security and Error Tests ---

  it('nonce mismatch throws', async () => {
    const participants = [generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const { encryptedShares, publicKey: pkMina } =
      await generateAndSign(2, pks, msg);

    const coordinator = generateSecretKey();
    const nonce = 100n;
    const wrongNonce = 999n;

    const recoded0 = recodeShare(
      encryptedShares[0],
      coordinator.publicKey,
      participants[0].privateKey,
      nonce
    );
    const recoded1 = recodeShare(
      encryptedShares[1],
      coordinator.publicKey,
      participants[1].privateKey,
      nonce
    );

    await assert.rejects(
      () =>
        sign(
          coordinator.privateKey,
          [recoded0, recoded1],
          msg,
          wrongNonce,
          pkMina
        ),
      /Nonce mismatch/
    );
  });

  it('wrong coordinator key throws on decryption', async () => {
    const participants = [generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const { encryptedShares, publicKey: pkMina } =
      await generateAndSign(2, pks, msg);

    const coordinator = generateSecretKey();
    const wrongCoordinator = generateSecretKey();
    const nonce = 1n;

    const recoded0 = recodeShare(
      encryptedShares[0],
      coordinator.publicKey,
      participants[0].privateKey,
      nonce
    );
    const recoded1 = recodeShare(
      encryptedShares[1],
      coordinator.publicKey,
      participants[1].privateKey,
      nonce
    );

    await assert.rejects(() =>
      sign(
        wrongCoordinator.privateKey,
        [recoded0, recoded1],
        msg,
        nonce,
        pkMina
      )
    );
  });

  it('wrong expectedPublicKey throws', async () => {
    const participants = [generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const { encryptedShares } = await generateAndSign(2, pks, msg);

    const coordinator = generateSecretKey();
    const nonce = 1n;

    const recoded0 = recodeShare(
      encryptedShares[0],
      coordinator.publicKey,
      participants[0].privateKey,
      nonce
    );
    const recoded1 = recodeShare(
      encryptedShares[1],
      coordinator.publicKey,
      participants[1].privateKey,
      nonce
    );

    // Generate a different key to use as wrong expected
    const { publicKey: wrongPk } = await generateAndSign(2, pks, msg);

    await assert.rejects(
      () =>
        sign(
          coordinator.privateKey,
          [recoded0, recoded1],
          msg,
          nonce,
          wrongPk
        ),
      /does not match/
    );
  });

  it('type tag mismatch: share passed to sign() throws', async () => {
    const coordinator = generateSecretKey();
    const other = generateSecretKey();

    const { encryptedShares, publicKey: pkMina } =
      await generateAndSign(2, [coordinator.publicKey, other.publicKey], msg);

    await assert.rejects(
      () =>
        sign(
          coordinator.privateKey,
          [encryptedShares[0], encryptedShares[0]],
          msg,
          1n,
          pkMina
        ),
      /Expected pair tag/
    );
  });

  it('input validation: threshold > n, threshold < 2, empty message', async () => {
    const participants = [generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    await assert.rejects(
      () => generateAndSign(3, pks, msg),
      /Threshold cannot exceed/
    );

    await assert.rejects(
      () => generateAndSign(1, pks, msg),
      /Threshold must be at least 2/
    );

    await assert.rejects(
      () => generateAndSign(2, pks, new Uint8Array(0)),
      /Message must not be empty/
    );

    await assert.rejects(
      () => generateAndSign(2, [pks[0]], msg),
      /Need at least 2 participants/
    );
  });

  it('independent ceremonies produce different keys', async () => {
    const participants = [generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const result1 = await generateAndSign(2, pks, msg);
    const result2 = await generateAndSign(2, pks, msg);

    assert.notEqual(
      result1.publicKey.toBase58(),
      result2.publicKey.toBase58()
    );
  });

  it('signature serialization roundtrip', async () => {
    const participants = [generateSecretKey(), generateSecretKey()];
    const pks = participants.map((p) => p.publicKey);

    const { signature, publicKey: pkMina } = await generateAndSign(2, pks, msg);

    const json = JSON.stringify(signature.toJSON());
    const restored = Signature.fromJSON(JSON.parse(json));

    assert.ok(
      restored.verify(pkMina, messageToFields(msg)).toBoolean(),
      'Deserialized signature must verify'
    );
  });
});

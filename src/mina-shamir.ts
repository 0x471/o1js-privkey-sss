import { split, combine } from 'shamir-secret-sharing';
import { PrivateKey } from 'o1js';

/**
 * Split a Mina private key into n shares, requiring t to reconstruct.
 */
export async function splitKey(
  privateKey: PrivateKey,
  totalShares: number,
  threshold: number
): Promise<string[]> {
  const base58 = privateKey.toBase58();
  const secret = new TextEncoder().encode(base58);
  const shares = await split(secret, totalShares, threshold);
  return shares.map((s) => Buffer.from(s).toString('hex'));
}

/**
 * Combine hex-encoded shares to recover a Mina private key.
 */
export async function combineShares(
  shares: string[]
): Promise<PrivateKey> {
  const byteShares = shares.map(
    (hex) => new Uint8Array(Buffer.from(hex, 'hex'))
  );
  const recovered = await combine(byteShares);
  const base58 = new TextDecoder().decode(recovered);
  return PrivateKey.fromBase58(base58);
}

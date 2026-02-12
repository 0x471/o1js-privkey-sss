import { parseArgs } from 'node:util';
import { readFileSync } from 'node:fs';
import { PublicKey, Signature } from 'o1js';
import {
  generateSecretKey,
  generateAndSign,
  recodeShare,
  sign,
  messageToFields,
} from './ceremony.js';

function readJSON(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf-8'));
}

function readKeypair(path: string): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const json = readJSON(path) as { publicKey: string; privateKey: string };
  return {
    publicKey: new Uint8Array(Buffer.from(json.publicKey, 'hex')),
    privateKey: new Uint8Array(Buffer.from(json.privateKey, 'hex')),
  };
}

const USAGE = `Usage: sss <command> [options]

Commands:
  keygen              Generate an X25519 keypair
  generate            Phase 1: generate Mina key, sign, distribute shares
  recode              Phase 2: recode an encrypted share for coordinator
  sign                Phase 3: reconstruct key and sign
  verify              Verify a signature

Run "sss <command> --help" for command-specific options.`;

function printUsage(): never {
  process.stderr.write(USAGE + '\n');
  process.exit(1);
}

async function cmdKeygen() {
  const kp = generateSecretKey();
  console.log(JSON.stringify({
    publicKey: Buffer.from(kp.publicKey).toString('hex'),
    privateKey: Buffer.from(kp.privateKey).toString('hex'),
  }));
}

async function cmdGenerate(args: string[]) {
  const { values } = parseArgs({
    args,
    options: {
      threshold: { type: 'string', short: 't' },
      pubkeys: { type: 'string', short: 'k' },
      message: { type: 'string', short: 'm' },
      help: { type: 'boolean' },
    },
  });

  if (values.help) {
    process.stderr.write('Usage: sss generate --threshold <n> --pubkeys <f1,f2,...> --message <msg>\n');
    process.exit(0);
  }

  if (!values.threshold || !values.pubkeys || !values.message) {
    process.stderr.write('Error: --threshold, --pubkeys, and --message are required\n');
    process.exit(1);
  }

  const threshold = parseInt(values.threshold, 10);
  const pubkeyPaths = values.pubkeys.split(',');
  const publicKeys = pubkeyPaths.map((p) => readKeypair(p.trim()).publicKey);
  const message = new TextEncoder().encode(values.message);

  const result = await generateAndSign(threshold, publicKeys, message);

  console.log(JSON.stringify({
    signature: result.signature.toJSON(),
    encryptedShares: result.encryptedShares,
    publicKey: result.publicKey.toBase58(),
  }));
}

async function cmdRecode(args: string[]) {
  const { values } = parseArgs({
    args,
    options: {
      ceremony: { type: 'string', short: 'c' },
      index: { type: 'string', short: 'i' },
      sk: { type: 'string', short: 's' },
      coordinator: { type: 'string' },
      nonce: { type: 'string', short: 'n' },
      help: { type: 'boolean' },
    },
  });

  if (values.help) {
    process.stderr.write('Usage: sss recode --ceremony <file> --index <n> --sk <file> --coordinator <file> --nonce <n>\n');
    process.exit(0);
  }

  if (!values.ceremony || !values.index || !values.sk || !values.coordinator || !values.nonce) {
    process.stderr.write('Error: --ceremony, --index, --sk, --coordinator, and --nonce are required\n');
    process.exit(1);
  }

  const ceremony = readJSON(values.ceremony) as { encryptedShares: string[] };
  const index = parseInt(values.index, 10);
  const participantKp = readKeypair(values.sk);
  const coordinatorKp = readKeypair(values.coordinator);
  const nonce = BigInt(values.nonce);

  const encodedShare = ceremony.encryptedShares[index];
  const recoded = recodeShare(encodedShare, coordinatorKp.publicKey, participantKp.privateKey, nonce);

  console.log(JSON.stringify({ recodedShare: recoded }));
}

async function cmdSign(args: string[]) {
  const { values } = parseArgs({
    args,
    options: {
      sk: { type: 'string', short: 's' },
      shares: { type: 'string' },
      ceremony: { type: 'string', short: 'c' },
      message: { type: 'string', short: 'm' },
      nonce: { type: 'string', short: 'n' },
      help: { type: 'boolean' },
    },
  });

  if (values.help) {
    process.stderr.write('Usage: sss sign --sk <file> --shares <f1,f2,...> --ceremony <file> --message <msg> --nonce <n>\n');
    process.exit(0);
  }

  if (!values.sk || !values.shares || !values.ceremony || !values.message || !values.nonce) {
    process.stderr.write('Error: --sk, --shares, --ceremony, --message, and --nonce are required\n');
    process.exit(1);
  }

  const coordinatorKp = readKeypair(values.sk);
  const sharePaths = values.shares.split(',');
  const encodedShares = sharePaths.map((p) => {
    const json = readJSON(p.trim()) as { recodedShare: string };
    return json.recodedShare;
  });
  const ceremony = readJSON(values.ceremony) as { publicKey: string };
  const message = new TextEncoder().encode(values.message);
  const nonce = BigInt(values.nonce);
  const expectedPublicKey = PublicKey.fromBase58(ceremony.publicKey);

  const signature = await sign(coordinatorKp.privateKey, encodedShares, message, nonce, expectedPublicKey);

  console.log(JSON.stringify({ signature: signature.toJSON() }));
}

async function cmdVerify(args: string[]) {
  const { values } = parseArgs({
    args,
    options: {
      signature: { type: 'string' },
      ceremony: { type: 'string', short: 'c' },
      message: { type: 'string', short: 'm' },
      help: { type: 'boolean' },
    },
  });

  if (values.help) {
    process.stderr.write('Usage: sss verify --signature <file> --ceremony <file> --message <msg>\n');
    process.exit(0);
  }

  if (!values.signature || !values.ceremony || !values.message) {
    process.stderr.write('Error: --signature, --ceremony, and --message are required\n');
    process.exit(1);
  }

  const sigJson = readJSON(values.signature) as { signature: { r: string; s: string } };
  const ceremony = readJSON(values.ceremony) as { publicKey: string };
  const message = new TextEncoder().encode(values.message);

  const sig = Signature.fromJSON(sigJson.signature);
  const pk = PublicKey.fromBase58(ceremony.publicKey);
  const valid = sig.verify(pk, messageToFields(message)).toBoolean();

  console.log(JSON.stringify({ valid }));
}

const commands: Record<string, (args: string[]) => Promise<void>> = {
  keygen: () => cmdKeygen(),
  generate: cmdGenerate,
  recode: cmdRecode,
  sign: cmdSign,
  verify: cmdVerify,
};

async function main() {
  const [subcommand, ...rest] = process.argv.slice(2);

  if (!subcommand || subcommand === '--help' || subcommand === '-h') {
    printUsage();
  }

  const handler = commands[subcommand];
  if (!handler) {
    process.stderr.write(`Unknown command: ${subcommand}\n\n`);
    printUsage();
  }

  await handler(rest);
}

main().catch((err: Error) => {
  process.stderr.write(`Error: ${err.message}\n`);
  process.exit(1);
});

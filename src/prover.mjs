import { randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { buildBn128 } from 'ffjavascript';
import { groth16 } from 'snarkjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const WITNESS_NAMES = [
  'registeredVkHash', 'proofVkHash', 'minimum', 'publicBalance', 'expiryBlock',
  'currentBlock', 'recipient', 'conditionRecipient', 'amount', 'maxTransfer', 'decision', 'taskId',
];
const INPUT_FIELDS = [
  'registered_vk', 'proof_vk', 'minimum', 'public_balance', 'expiry_block',
  'current_block', 'recipient', 'condition_recipient', 'amount', 'max_transfer',
];
const wasmPath = fileURLToPath(new URL('../circuits/gatekeeper.wasm', import.meta.url));
const zkeyPath = fileURLToPath(new URL('../circuits/gatekeeper_final.zkey', import.meta.url));
const vkPath = new URL('../circuits/verification_key.json', import.meta.url);
let curve;
let verificationKey;
let queue = Promise.resolve();

function serialized(operation) {
  const result = queue.then(operation);
  queue = result.catch(() => {});
  return result;
}

function uint32(value, name) {
  const valid = typeof value === 'number'
    ? Number.isSafeInteger(value) && value >= 0
    : typeof value === 'string' && /^[0-9]{1,1024}(?![\s\S])/.test(value);
  if (!valid || BigInt(value) > 0xffffffffn) {
    throw new TypeError(`${name} must be a uint32 decimal string or integer number`);
  }
  return BigInt(value);
}

function hex(value, name, address = false) {
  const format = address ? /^0x[0-9a-f]{40}(?![\s\S])/i : /^0x[0-9a-f]{1,64}(?![\s\S])/i;
  if (typeof value !== 'string' || !format.test(value)) {
    throw new TypeError(`${name} must be ${address ? 'a 20-byte hex address' : 'a hex value of 1–64 digits'}`);
  }
  return BigInt(value);
}

function ownRecord(value, fields, name) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || fields.some((field) => !Object.hasOwn(value, field))) {
    throw new TypeError(`${name} must be a record with all required own fields`);
  }
}

/** Twelve task-bound inputs, excluding the private-salt commitment output. */
export function expectedPublicInputs(envelope, decision) {
  if (decision !== 'APPROVE' && decision !== 'REJECT') {
    throw new TypeError('decision must be APPROVE or REJECT');
  }
  ownRecord(envelope, ['task_id', 'input'], 'envelope');
  const taskId = envelope.task_id;
  // Validate the original token, including the boundary before the UUID, first.
  if (typeof taskId !== 'string' || taskId.length > 160
      || !/(?:^|_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![\s\S])/.test(taskId)) {
    throw new TypeError('task_id must end in a UUID preceded by _ or the start of the ID (max 160 characters)');
  }
  const i = envelope.input;
  ownRecord(i, INPUT_FIELDS, 'input');
  return [
    hex(i.registered_vk, 'registered_vk'), hex(i.proof_vk, 'proof_vk'),
    uint32(i.minimum, 'minimum'), uint32(i.public_balance, 'public_balance'),
    uint32(i.expiry_block, 'expiry_block'), uint32(i.current_block, 'current_block'),
    hex(i.recipient, 'recipient', true), hex(i.condition_recipient, 'condition_recipient', true),
    uint32(i.amount, 'amount'), uint32(i.max_transfer, 'max_transfer'),
    decision === 'APPROVE' ? 1 : 0,
    `0x${envelope.task_id.slice(-36).replaceAll('-', '')}`,
  ].map((value) => (BigInt(value) % FIELD).toString());
}

/** Generate evidence only; this does not submit or fabricate a transaction. */
export async function proveTask(envelope, decision) {
  const expected = expectedPublicInputs(envelope, decision);
  if (decision === 'APPROVE' && BigInt(envelope.input.registered_vk) !== BigInt(envelope.input.proof_vk)) {
    throw new Error('Requested decision does not match the full verification-key condition');
  }
  const [registered, proofVk, minimum, balance, expiry, current, recipient, conditionRecipient, amount, maxTransfer] = expected.map(BigInt);
  const condition = registered === proofVk && balance >= minimum && expiry > current
    && recipient === conditionRecipient && amount <= maxTransfer;
  if ((decision === 'APPROVE') !== condition) {
    throw new Error('Requested decision does not match the circuit condition');
  }
  return serialized(() => proveInputs(expected));
}

async function proveInputs(expected) {
  const witness = Object.fromEntries(WITNESS_NAMES.map((name, index) => [name, expected[index]]));
  witness.salt = (BigInt(`0x${randomBytes(32).toString('hex')}`) % FIELD).toString();
  curve ??= await buildBn128(true);
  // With snarkjs 0.7.6, default curve lookup reuses this single-thread cache.
  // Passing singleThread:true to fullProve would build a second curve every time.
  globalThis.curve_bn128 = curve;
  verificationKey ??= JSON.parse(await readFile(vkPath, 'utf8'));
  const { proof, publicSignals } = await groth16.fullProve(
    witness, wasmPath, zkeyPath, undefined, { memorySize: 128 },
  );
  if (publicSignals.length !== 13
      || publicSignals.some((v) => typeof v !== 'string' || !/^(0|[1-9][0-9]*)(?![\s\S])/.test(v) || BigInt(v) >= FIELD)
      || publicSignals.slice(1).some((v, index) => v !== expected[index])) {
    throw new Error('Proof public signals do not match the task');
  }
  if (!await groth16.verify(verificationKey, publicSignals, proof)) {
    throw new Error('Local Groth16 verification failed');
  }
  return { proof, public_signals: publicSignals };
}

/** Release the cached curve after use; subsequent proofs initialize it again. */
export async function closeProver() {
  return serialized(async () => {
    if (curve) {
      await curve.terminate();
      if (globalThis.curve_bn128 === curve) delete globalThis.curve_bn128;
      curve = undefined;
    }
  });
}

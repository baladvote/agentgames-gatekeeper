import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { groth16, zKey } from 'snarkjs';
import * as prover from '../src/prover.mjs';

// Synthetic envelopes exercise the official artifacts, not platform/chain state.
const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const UUID = '12345678-1234-4abc-8def-1234567890ab';
const VK = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';
const ADDRESS = '0x1234567890abcdef1234567890abcdef12345678';
const fixture = (input = {}, task_id = `gk_practice_${UUID}`) => ({
  type: 'agent-games.proof-gatekeeper.v1', task_id, mode: 'practice',
  issued_at: '2026-11-15T00:00:00.000Z', deadline_at: '2026-11-15T00:01:00.000Z',
  input: {
    registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
    expiry_block: 8430000, current_block: 8420000,
    recipient: ADDRESS, condition_recipient: ADDRESS, amount: '500', max_transfer: '1000',
    ...input,
  },
});
const APPROVAL_INPUTS = [
  '4836144126773920907502496244340012141761656471453348073975163706578152814510',
  '4836144126773920907502496244340012141761656471453348073975163706578152814510',
  '1000', '1460', '8430000', '8420000',
  '103929005307927756724354605802047639613112342136',
  '103929005307927756724354605802047639613112342136',
  '500', '1000', '1', '24197857161011659757068287043102609579',
];

after(async () => { await prover.closeProver(); });

test('maps the organizer UUID suffix and every public input exactly', () => {
  const task = fixture();
  const original = structuredClone(task);
  assert.deepEqual(prover.expectedPublicInputs(task, 'APPROVE'), APPROVAL_INPUTS);
  assert.deepEqual(prover.expectedPublicInputs(fixture({}, UUID.toUpperCase()), 'REJECT'),
    APPROVAL_INPUTS.with(10, '0'));
  assert.deepEqual(task, original);
});

test('rejects malformed task IDs before stripping UUID hyphens', () => {
  for (const task_id of [
    `prefix${UUID}`, UUID.replaceAll('-', ''), UUID.replace('-', '_'),
    `gk_${UUID}\n`, `gk_${UUID} `, `gk_${UUID}_extra`, `gk_${UUID.slice(0, -1)}g`,
    'gk_24_9d1', '', null, undefined, 42, `prefix_${'a'.repeat(160)}_${UUID}`,
    `${UUID.slice(0, 14)}-${UUID.slice(14).replace('-', '')}`,
  ]) {
    const task = fixture();
    task.task_id = task_id;
    assert.throws(() => prover.expectedPublicInputs(task, 'APPROVE'), /task_id.*UUID/);
  }
});

test('validates all six uint32 operands before any field reduction', () => {
  for (const field of ['minimum', 'public_balance', 'expiry_block', 'current_block', 'amount', 'max_transfer']) {
    for (const value of [-1, 4294967296, Number.MAX_SAFE_INTEGER + 1, 1.5, NaN, Infinity,
      '', ' 1', '1 ', '1\n', '-0', '+1', '1e3', '0x01', '4294967296',
      FIELD.toString(), '0'.repeat(1025), null, undefined, true, [], {}, 0n]) {
      assert.throws(() => prover.expectedPublicInputs(fixture({ [field]: value }), 'APPROVE'),
        /uint32/, `invalid ${field}`);
    }
  }
  assert.deepEqual(prover.expectedPublicInputs(fixture({
    minimum: 0, public_balance: '0004294967295', expiry_block: '4294967295',
    current_block: 0, amount: '0', max_transfer: 4294967295,
  }), 'APPROVE').slice(2, 6), ['0', '4294967295', '4294967295', '0']);
});

test('validates full source hex tokens before converting hashes and addresses', () => {
  for (const [field, width] of [['registered_vk', 64], ['proof_vk', 64], ['recipient', 40], ['condition_recipient', 40]]) {
    for (const value of [null, undefined, false, 0, {}, [], '', '-0x1', 'a'.repeat(width),
      `0x${'a'.repeat(width + 1)}`, `0x${'g'.repeat(width)}`, `0x${'a'.repeat(width)}\n`,
      ` 0x${'a'.repeat(width)}`, `0x${'a'.repeat(width)} `]) {
      assert.throws(() => prover.expectedPublicInputs(fixture({ [field]: value }), 'APPROVE'),
        /hex/, `invalid ${field}`);
    }
  }
  for (const field of ['recipient', 'condition_recipient']) {
    assert.throws(() => prover.expectedPublicInputs(fixture({ [field]: '0x1234' }), 'APPROVE'), /20-byte/);
  }
  assert.deepEqual(prover.expectedPublicInputs(fixture({
    registered_vk: '0X01', proof_vk: '0x1',
    recipient: ADDRESS.toUpperCase(), condition_recipient: ADDRESS,
  }), 'APPROVE'), APPROVAL_INPUTS.with(0, '1').with(1, '1'));
});

test('requires the task and circuit fields as own record properties', () => {
  const task = fixture();
  for (const malformed of [
    Object.assign([], task), Object.create(task), { ...task, input: Object.create(task.input) },
    { ...task, input: Object.assign([], task.input) },
  ]) {
    assert.throws(() => prover.expectedPublicInputs(malformed, 'APPROVE'), /record|own/);
  }
  for (const field of Object.keys(task.input)) {
    const missing = fixture();
    delete missing.input[field];
    assert.throws(() => prover.expectedPublicInputs(missing, 'APPROVE'), /own/);
  }
});

test('requires an explicit APPROVE or REJECT decision', () => {
  for (const decision of [undefined, null, false, 0, 1, 'approve', 'REJECT\n', {}, '']) {
    assert.throws(() => prover.expectedPublicInputs(fixture(), decision), /decision/);
  }
});

test('generates a real approval proof bound to all thirteen public signals', async () => {
  assert.equal(typeof prover.proveTask, 'function');
  const task = fixture(); // proof_tx is optional and is not a circuit input.
  Object.freeze(task.input);
  Object.freeze(task);
  const evidence = await prover.proveTask(task, 'APPROVE');
  const vk = JSON.parse(await readFile(new URL('../circuits/verification_key.json', import.meta.url), 'utf8'));
  assert.deepEqual(Object.keys(evidence).sort(), ['proof', 'public_signals']);
  assert.equal(evidence.proof.protocol, 'groth16');
  assert.equal(evidence.proof.curve, 'bn128');
  assert.equal(evidence.public_signals.length, 13);
  assert.deepEqual(evidence.public_signals.slice(1), APPROVAL_INPUTS);
  assert.ok(evidence.public_signals.every((v) => /^(0|[1-9][0-9]*)(?![\s\S])/.test(v) && BigInt(v) < FIELD));
  assert.equal(globalThis.curve_bn128.tm.singleThread, true);
  assert.equal(await groth16.verify(vk, evidence.public_signals, evidence.proof), true);
  assert.deepEqual(await zKey.exportVerificationKey(new URL('../circuits/gatekeeper_final.zkey', import.meta.url).pathname), vk);
  for (let index = 0; index < evidence.public_signals.length; index++) {
    const changed = evidence.public_signals.with(index, ((BigInt(evidence.public_signals[index]) + 1n) % FIELD).toString());
    assert.equal(await groth16.verify(vk, changed, evidence.proof), false, `tampered signal ${index}`);
  }
});

test('rejects an incorrect requested decision before generating evidence', async () => {
  await assert.rejects(prover.proveTask(fixture(), 'REJECT'), /decision.*condition/);
  for (const input of [
    { proof_vk: '0x1' }, { public_balance: '999' }, { current_block: 8430000 },
    { recipient: '0x' + 'a'.repeat(40) }, { amount: '1001' },
  ]) {
    await assert.rejects(prover.proveTask(fixture(input), 'APPROVE'), /decision.*condition/);
  }
});

test('cannot approve distinct full VK hashes that alias modulo the field', async () => {
  const task = fixture({ registered_vk: '0x1', proof_vk: `0x${(FIELD + 1n).toString(16)}` });
  assert.deepEqual(prover.expectedPublicInputs(task, 'APPROVE').slice(0, 2), ['1', '1']);
  await assert.rejects(prover.proveTask(task, 'APPROVE'), /full.*verification.key/);
  // The circuit sees equal hashes, so a purely VK-based REJECT is unprovable too.
  await assert.rejects(prover.proveTask(task, 'REJECT'), /decision.*condition/);
});

test('closeProver releases its curve cache and permits later reuse', async () => {
  assert.equal(typeof prover.closeProver, 'function');
  const firstCurve = globalThis.curve_bn128;
  assert.ok(firstCurve);
  await prover.closeProver();
  assert.equal(globalThis.curve_bn128, undefined);
  await prover.closeProver(); // Idempotent teardown when already closed.
  const evidence = await prover.proveTask(fixture(), 'APPROVE');
  assert.notEqual(globalThis.curve_bn128, firstCurve);
  assert.equal(globalThis.curve_bn128.tm.singleThread, true);
  assert.deepEqual(evidence.public_signals.slice(1), APPROVAL_INPUTS);
});

test('concurrent tasks retain their own statements and fresh salt commitments', async () => {
  const cachedCurve = globalThis.curve_bn128;
  const trap = fixture({ public_balance: '999' }, 'gk_00000000-0000-0000-0000-000000000001');
  const [first, second, rejected] = await Promise.all([
    prover.proveTask(fixture(), 'APPROVE'), prover.proveTask(fixture(), 'APPROVE'),
    prover.proveTask(trap, 'REJECT'),
  ]);
  assert.equal(globalThis.curve_bn128, cachedCurve);
  assert.deepEqual(first.public_signals.slice(1), APPROVAL_INPUTS);
  assert.deepEqual(second.public_signals.slice(1), APPROVAL_INPUTS);
  assert.notEqual(first.public_signals[0], second.public_signals[0]);
  assert.deepEqual(rejected.public_signals.slice(1), APPROVAL_INPUTS.with(3, '999').with(10, '0').with(11, '1'));
  const vk = JSON.parse(await readFile(new URL('../circuits/verification_key.json', import.meta.url), 'utf8'));
  for (const evidence of [first, second, rejected]) {
    assert.equal(await groth16.verify(vk, evidence.public_signals, evidence.proof), true);
  }
});

test('closeProver waits for an in-flight cold-start proof before releasing the cache', async () => {
  await prover.closeProver();
  let finished = false;
  const pending = prover.proveTask(fixture(), 'APPROVE').then((evidence) => {
    finished = true;
    return evidence;
  });
  await prover.closeProver();
  const waitedForProof = finished;
  const evidence = await pending;
  assert.equal(waitedForProof, true);
  assert.equal(globalThis.curve_bn128, undefined);
  assert.deepEqual(evidence.public_signals.slice(1), APPROVAL_INPUTS);
});

test('generates verified rejection evidence for each stateless trap', async (t) => {
  const cases = [
    ['VK substitution', { proof_vk: '0x1' }, 1, '1'],
    ['threshold mismatch', { public_balance: '999' }, 3, '999'],
    ['strict expiry equality', { current_block: 8430000 }, 5, '8430000'],
    ['expired block', { current_block: 8430001 }, 5, '8430001'],
    ['recipient mismatch', { recipient: '0x' + '0'.repeat(39) + '1' }, 6, '1'],
    ['amount overflow', { amount: '1001' }, 8, '1001'],
  ];
  const vk = JSON.parse(await readFile(new URL('../circuits/verification_key.json', import.meta.url), 'utf8'));
  for (const [name, input, index, value] of cases) {
    await t.test(name, async () => {
      const evidence = await prover.proveTask(fixture(input), 'REJECT');
      assert.deepEqual(evidence.public_signals.slice(1), APPROVAL_INPUTS.with(index, value).with(10, '0'));
      assert.equal(await groth16.verify(vk, evidence.public_signals, evidence.proof), true);
      assert.equal(await groth16.verify(vk, evidence.public_signals.with(11, '1'), evidence.proof), false);
    });
  }
});

test('proves uint32 boundaries and full 20-byte recipients without truncation', async () => {
  const address = '0x' + 'f'.repeat(40);
  const task = fixture({
    minimum: '0', public_balance: '4294967295', expiry_block: 4294967295,
    current_block: 4294967294, recipient: address, condition_recipient: address,
    amount: '4294967295', max_transfer: '4294967295',
  });
  const evidence = await prover.proveTask(task, 'APPROVE');
  assert.deepEqual(evidence.public_signals.slice(3, 12), [
    '0', '4294967295', '4294967295', '4294967294',
    ((1n << 160n) - 1n).toString(), ((1n << 160n) - 1n).toString(),
    '4294967295', '4294967295', '1',
  ]);
  const vk = JSON.parse(await readFile(new URL('../circuits/verification_key.json', import.meta.url), 'utf8'));
  assert.equal(await groth16.verify(vk, evidence.public_signals, evidence.proof), true);
});

test('a queued proof binds the task snapshot taken when proveTask is called', async () => {
  const task = fixture();
  const pending = prover.proveTask(task, 'APPROVE');
  task.task_id = 'gk_00000000-0000-0000-0000-000000000001';
  task.input.amount = '501';
  const evidence = await pending;
  assert.deepEqual(evidence.public_signals.slice(1), APPROVAL_INPUTS);
});

test('malformed task IDs reject through proveTask without poisoning subsequent work', async () => {
  await assert.rejects(prover.proveTask(fixture({}, UUID.replaceAll('-', '')), 'APPROVE'), /task_id.*UUID/);
  const evidence = await prover.proveTask(fixture(), 'APPROVE');
  assert.deepEqual(evidence.public_signals.slice(1), APPROVAL_INPUTS);
});

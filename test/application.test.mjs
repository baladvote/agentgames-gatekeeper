import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import * as application from '../src/application.mjs';

// Unit tests only: injected proofs below are synthetic markers, NOT Groth16 proofs.

const input = () => ({
  registered_vk: '0x' + 'a'.repeat(64), proof_vk: '0x' + 'a'.repeat(64),
  public_balance: '1460', minimum: '1000', current_block: 10, expiry_block: 20,
  recipient: '0x' + '1'.repeat(40), condition_recipient: '0x' + '1'.repeat(40),
  amount: '500', max_transfer: '1000', proof_tx: '0x' + 'b'.repeat(64),
});
const envelope = (task_id = 'task-1', fields = {}) => ({
  type: 'agent-games.proof-gatekeeper.v1', task_id, mode: 'competition',
  issued_at: new Date().toISOString(), deadline_at: new Date(Date.now() + 60_000).toISOString(),
  input: input(), ...fields,
});

async function setup(t, options = {}) {
  const directory = await mkdtemp(join(tmpdir(), 'gatekeeper-application-unit-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const statePath = join(directory, 'state.json');
  const calls = [];
  const prove = async (task, decision) => {
    calls.push({ task: structuredClone(task), decision });
    return { proof: { unit_test_only: true, sequence: calls.length }, public_signals: ['1'] };
  };
  assert.equal(typeof application.createTaskHandler, 'function', 'application must export createTaskHandler');
  const config = { statePath, prove, ...options };
  return { statePath, calls, config, handle: application.createTaskHandler(config) };
}

test('unit application durably returns the identical proof for a task retry after reopening', async t => {
  const { handle, statePath, calls, config } = await setup(t);
  const task = envelope();
  const result = await handle(task);
  assert.deepEqual(result, {
    decision: 'APPROVE', reason_code: 'VALID_CONDITION',
    proof: { unit_test_only: true, sequence: 1 }, public_signals: ['1'],
  });
  assert.deepEqual(calls, [{ task, decision: 'APPROVE' }]);
  assert.deepEqual(await handle(structuredClone(task)), result);
  const reopened = application.createTaskHandler(config);
  assert.deepEqual(await reopened(structuredClone(task)), result);
  assert.equal(calls.length, 1);
  assert.equal((await stat(statePath)).mode & 0o777, 0o600);
  assert.ok((await readFile(statePath, 'utf8')).includes('unit_test_only'));
});

test('unit application reopens short platform proof references without losing history', async t => {
  const { handle, config, calls } = await setup(t);
  const first = envelope('short-reference', {input:{...input(),proof_tx:'0x62c4fde357144e71ae16793a5d06a562'}});
  const result = await handle(first);
  assert.equal(result.decision,'APPROVE');
  const reopened = application.createTaskHandler(config);
  assert.deepEqual(await reopened(first),result);
  assert.equal(calls.length,1);
  const replay = envelope('short-reference-replay',{input:first.input});
  assert.equal((await reopened(replay)).reason_code,'PROOF_REUSED');
});

test('unit application binds each task id to its exact canonical JSON envelope', async t => {
  const { handle, config, calls } = await setup(t);
  const task = envelope('canonical-task', { metadata: { nested: { b: 2, a: 1 }, list: [1, 2] } });
  const response = await handle(task);
  const reverseKeys = value => {
    if (Array.isArray(value)) return value.map(reverseKeys);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).reverse().map(([key, child]) => [key, reverseKeys(child)]));
    }
    return value;
  };
  const reopened = application.createTaskHandler(config);
  assert.deepEqual(await reopened(reverseKeys(task)), response, 'object key order does not change task identity');
  for (const changed of [
    { ...task, input: { ...task.input, amount: '501' } },
    { ...task, input: { ...task.input, amount: 500 } },
    { ...task, input: { ...task.input, proof_tx: task.input.proof_tx.toUpperCase() } },
    { ...task, metadata: { nested: { b: 2, a: 1 }, list: [2, 1] } },
    { ...task, metadata: { nested: { b: 3, a: 1 }, list: [1, 2] } },
    { ...task, mode: 'practice' },
    { ...task, deadline_at: new Date(Date.parse(task.deadline_at) + 1).toISOString() },
  ]) {
    assert.deepEqual(await reopened(changed), { decision: 'REJECT', reason_code: 'TASK_ID_CONFLICT' });
  }
  assert.deepEqual(await reopened(task), response, 'conflict cannot overwrite the original response');
  assert.equal(calls.length, 1);
});

test('unit application rejects a different task reusing an accepted proof after restart without proving', async t => {
  const { handle, config, calls } = await setup(t);
  const original = envelope('accepted');
  const approval = await handle(original);
  const reopened = application.createTaskHandler(config);
  const replay = envelope('different-task', { input: { ...original.input, proof_tx: original.input.proof_tx.toUpperCase() } });
  assert.deepEqual(await reopened(replay), { decision: 'REJECT', reason_code: 'PROOF_REUSED' });
  assert.deepEqual(await application.createTaskHandler(config)(replay), { decision: 'REJECT', reason_code: 'PROOF_REUSED' });
  assert.deepEqual(await reopened(original), approval, 'retrying the accepted task is not a replay');
  assert.equal(calls.length, 1);
});

test('unit application maintains independent practice and competition accepted histories', async t => {
  const { handle, config, calls } = await setup(t);
  assert.equal((await handle(envelope('practice-first', { mode: 'practice' }))).decision, 'APPROVE');
  const reopened = application.createTaskHandler(config);
  assert.equal((await reopened(envelope('competition-first'))).decision, 'APPROVE');
  for (const mode of ['practice', 'competition']) {
    assert.deepEqual(await reopened(envelope(`${mode}-replay`, { mode })), {
      decision: 'REJECT', reason_code: 'PROOF_REUSED',
    });
  }
  const otherInput = { ...input(), proof_tx: '0x' + 'c'.repeat(64) };
  assert.equal((await reopened(envelope('competition-other', { input: otherInput }))).decision, 'APPROVE');
  assert.equal((await reopened(envelope('practice-other', { mode: 'practice', input: otherInput }))).decision, 'APPROVE');
  assert.equal(calls.length, 4);
});

test('unit application fails closed on unknown or malformed JSON tasks without invoking the prover', async t => {
  const { handle, calls } = await setup(t);
  const circular = envelope('circular');
  circular.metadata = circular;
  for (const task of [
    null, undefined, false, 123, [], {},
    envelope('unknown-type', { type: 'agent-games.other.v1' }),
    envelope('', {}), envelope('   '), envelope(123),
    envelope('unknown-mode', { mode: 'production' }),
    envelope('null-input', { input: null }),
    envelope('array-input', { input: [] }),
    envelope('missing-input', { input: {} }),
    envelope('invalid-hash', { input: { ...input(), proof_tx: '0xnot-a-hash' } }),
    envelope('undefined-json', { metadata: undefined }),
    envelope('bigint-json', { metadata: 1n }),
    envelope('nonfinite-json', { metadata: Infinity }),
    circular,
  ]) {
    assert.deepEqual(await handle(task), { decision: 'REJECT', reason_code: 'INVALID_INPUT' });
  }
  assert.equal(calls.length, 0);
});

test('unit application durably rejects prover failures without consuming the proof reference', async t => {
  let attempts = 0;
  const { handle, config, statePath } = await setup(t, {
    prove: async () => {
      attempts++;
      throw new Error('synthetic prover failure containing PRIVATE_TEST_SENTINEL');
    },
  });
  const failedTask = envelope('prover-failed');
  const failure = { decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED' };
  assert.deepEqual(await handle(failedTask), failure);
  const reopened = application.createTaskHandler({
    ...config,
    prove: async () => {
      attempts++;
      return { proof: { unit_test_only: true }, public_signals: ['1'] };
    },
  });
  assert.deepEqual(await reopened(failedTask), failure, 'completed failure responses are idempotent too');
  assert.equal((await reopened(envelope('new-task-same-reference'))).decision, 'APPROVE');
  assert.equal(attempts, 2);
  assert.ok(!(await readFile(statePath, 'utf8')).includes('PRIVATE_TEST_SENTINEL'));
});

test('unit application rejects incomplete or non-JSON proof bundles without recording an acceptance', async t => {
  const bundles = [
    {}, { proof: null, public_signals: ['1'] },
    { proof: [], public_signals: ['1'] }, { proof: {}, public_signals: ['1'] },
    { proof: { unit_test_only: true } },
    { proof: { unit_test_only: true }, public_signals: null },
    { proof: { unit_test_only: true }, public_signals: [] },
    { proof: { unit_test_only: true }, public_signals: [1n] },
    { proof: { unit_test_only: undefined }, public_signals: ['1'] },
  ];
  let attempts = 0;
  const { handle, config } = await setup(t, { prove: async () => bundles[attempts++] });
  for (const [index] of bundles.entries()) {
    assert.deepEqual(await handle(envelope(`incomplete-proof-${index}`)), {
      decision: 'REJECT', reason_code: 'PROOF_GENERATION_FAILED',
    });
  }
  const reopened = application.createTaskHandler({ ...config,
    prove: async () => ({ proof: { unit_test_only: true }, public_signals: ['1'] }),
  });
  assert.equal((await reopened(envelope('retry-reference-with-complete-proof'))).decision, 'APPROVE');
  assert.equal(attempts, bundles.length);
});

test('unit application serializes concurrent duplicates, conflicts, and cross-task proof replay', async t => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  let attempts = 0;
  let active = 0;
  let peak = 0;
  const { handle, config } = await setup(t, { prove: async () => {
    attempts++;
    peak = Math.max(peak, ++active);
    entered.resolve();
    await release.promise;
    active--;
    return { proof: { unit_test_only: true, sequence: attempts }, public_signals: ['1'] };
  } });
  const original = envelope('concurrent-first');
  const first = handle(original);
  await entered.promise;
  const duplicates = Array.from({ length: 5 }, () => handle(structuredClone(original)));
  const conflict = handle({ ...original, input: { ...original.input, amount: '501' } });
  const replay = handle(envelope('concurrent-replay'));
  release.resolve();
  const [approval, ...results] = await Promise.all([first, ...duplicates, conflict, replay]);
  for (const duplicate of results.slice(0, 5)) assert.deepEqual(duplicate, approval);
  assert.deepEqual(results[5], { decision: 'REJECT', reason_code: 'TASK_ID_CONFLICT' });
  assert.deepEqual(results[6], { decision: 'REJECT', reason_code: 'PROOF_REUSED' });
  assert.equal(attempts, 1);
  assert.equal(peak, 1);
  assert.deepEqual(await application.createTaskHandler(config)(original), approval);
});

test('unit application expires queued work before a blocked prover releases the queue', async t => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const calls = [];
  const { handle, statePath } = await setup(t, { prove: async task => {
    calls.push(task.task_id);
    if (task.task_id === 'blocking') {
      entered.resolve();
      await release.promise;
    }
    return { proof: { unit_test_only: true }, public_signals: ['1'] };
  } });
  const first = handle(envelope('blocking'));
  await entered.promise;
  let queuedResult;
  const queued = handle(envelope('queued-expired', { input: { ...input(), proof_tx: '0x' + 'c'.repeat(64) } }),
    { deadlineAt: Date.now() + 20 }).then(result => { queuedResult = result; return result; });
  try {
    await new Promise(resolve => setTimeout(resolve, 50));
    assert.deepEqual(queuedResult, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
    assert.deepEqual(calls, ['blocking']);
  } finally {
    release.resolve();
    await Promise.all([first, queued]);
  }
  assert.deepEqual(calls, ['blocking']);
  assert.ok(!(await readFile(statePath, 'utf8')).includes('queued-expired'));
});

test('unit application never commits a late approval after transport aborts active work', async t => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  let attempts = 0;
  const { handle, statePath, config } = await setup(t, { prove: async () => {
    attempts++;
    if (attempts === 1) {
      entered.resolve();
      await release.promise;
    }
    return { proof: { unit_test_only: true }, public_signals: ['1'] };
  } });
  const controller = new AbortController();
  const task = envelope('aborted-active');
  let observed;
  const active = handle(task, { signal: controller.signal }).then(result => { observed = result; return result; });
  await entered.promise;
  controller.abort(new Error('PRIVATE_ABORT_SENTINEL'));
  try {
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(observed, { decision: 'REJECT', reason_code: 'REQUEST_ABORTED' });
  } finally {
    release.resolve();
    await active;
    await new Promise(resolve => setImmediate(resolve));
  }
  await assert.rejects(readFile(statePath), { code: 'ENOENT' });
  assert.equal((await application.createTaskHandler(config)(task)).decision, 'APPROVE');
  assert.equal(attempts, 2, 'an aborted task was not cached as a completed outcome');
});

test('unit application bounds pending work and frees a queued slot immediately on abort', async t => {
  const entered = Promise.withResolvers();
  const release = Promise.withResolvers();
  const calls = [];
  const { handle } = await setup(t, { maxPending: 1, prove: async task => {
    calls.push(task.task_id);
    if (task.task_id === 'bounded-blocker') { entered.resolve(); await release.promise; }
    return { proof: { unit_test_only: true }, public_signals: ['1'] };
  } });
  const first = handle(envelope('bounded-blocker'));
  await entered.promise;
  const controller = new AbortController();
  const queued = handle(envelope('bounded-aborted'), { signal: controller.signal });
  let overflowResult;
  const overflow = handle(envelope('bounded-overflow')).then(result => { overflowResult = result; return result; });
  let replacement;
  try {
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(overflowResult, { decision: 'REJECT', reason_code: 'QUEUE_FULL' });
    controller.abort();
    assert.deepEqual(await queued, { decision: 'REJECT', reason_code: 'REQUEST_ABORTED' });
    replacement = handle(envelope('bounded-replacement', { input: { ...input(), proof_tx: '0x' + 'c'.repeat(64) } }));
  } finally {
    controller.abort();
    release.resolve();
    await Promise.all([first, queued, overflow, replacement]);
  }
  assert.equal((await replacement).decision, 'APPROVE');
  assert.deepEqual(calls, ['bounded-blocker', 'bounded-replacement']);
});

test('unit application rejects unknown, contradictory, or thrown policy results without proof', async t => {
  const invalidResults = [
    null, undefined, {}, { decision: 'APPROVE', reason_code: 'INVALID_INPUT' },
    { decision: 'REJECT', reason_code: 'VALID_CONDITION' },
    { decision: 'APPROVE', reason_code: 'UNKNOWN_REASON' },
    { decision: 'MAYBE', reason_code: 'VALID_CONDITION' },
  ];
  let index = 0;
  const { handle, calls } = await setup(t, { evaluate: () => {
    if (index === invalidResults.length) throw new Error('synthetic policy failure');
    return invalidResults[index++];
  } });
  for (let n = 0; n <= invalidResults.length; n++) {
    assert.deepEqual(await handle(envelope(`invalid-policy-${n}`)), {
      decision: 'REJECT', reason_code: 'INVALID_INPUT',
    });
  }
  assert.equal(calls.length, 0);
});

test('unit application keeps caller mutation from changing the cached proof or accepted history', async t => {
  const { handle, config, calls } = await setup(t);
  const task = envelope('immutable-response');
  const first = await handle(task);
  const expected = structuredClone(first);
  first.decision = 'REJECT';
  first.proof.sequence = 999;
  first.public_signals.push('999');
  const retry = await handle(task);
  assert.deepEqual(retry, expected);
  retry.proof.sequence = 1000;
  assert.deepEqual(await handle(task), expected);
  assert.deepEqual(await handle(envelope('immutable-replay')), { decision: 'REJECT', reason_code: 'PROOF_REUSED' });
  assert.deepEqual(await application.createTaskHandler(config)(task), expected);
  assert.equal(calls.length, 1);
});

test('unit application refuses corrupt durable state instead of resetting accepted history', async t => {
  const { handle, statePath, config } = await setup(t);
  await handle(envelope('seed-corrupt-state-test'));
  const good = JSON.parse(await readFile(statePath, 'utf8'));
  const missingReference = structuredClone(good);
  delete missingReference.tasks['seed-corrupt-state-test'].proofRef;
  const missingProof = structuredClone(good);
  delete missingProof.tasks['seed-corrupt-state-test'].response.proof;
  const malformedDigest = structuredClone(good);
  malformedDigest.tasks['seed-corrupt-state-test'].digest = 'invalid';
  for (const bad of ['{}', '{broken', 'null', '{"version":2,"tasks":{}}',
    JSON.stringify(missingReference), JSON.stringify(missingProof), JSON.stringify(malformedDigest)]) {
    await writeFile(statePath, bad);
    assert.throws(() => application.createTaskHandler(config), /state/i);
    assert.equal(await readFile(statePath, 'utf8'), bad, 'corrupt state must not be silently overwritten');
  }
});

test('unit application latches storage failure closed until a fresh handler reopens state', async t => {
  const { handle, statePath, config, calls } = await setup(t);
  await mkdir(statePath); // Force atomic rename to fail against an existing directory.
  const task = envelope('storage-failure');
  const failure = { decision: 'REJECT', reason_code: 'STATE_PERSISTENCE_FAILED' };
  assert.deepEqual(await handle(task), failure);
  await rm(statePath, { recursive: true });
  assert.deepEqual(await handle(task), failure, 'a possibly uncertain commit must not keep issuing approvals');
  assert.deepEqual(await handle(envelope('another-after-storage-failure')), failure);
  assert.deepEqual(await readdir(join(statePath, '..')), [], 'temporary files are cleaned after a failed commit');
  assert.equal(calls.length, 1);
  assert.equal((await application.createTaskHandler(config)(task)).decision, 'APPROVE');
  assert.equal(calls.length, 2);
});

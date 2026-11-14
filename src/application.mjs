import {
  closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync,
} from 'node:fs';
import { dirname } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

const defaultEvaluate = async (input, seen) => (await import('./policy.mjs')).evaluateCondition(input, seen);
const defaultProve = async (envelope, decision) => (await import('./prover.mjs')).proveTask(envelope, decision);

const rejection = reason_code => ({ decision: 'REJECT', reason_code });
const isRecord = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const rejectionReasons = new Set([
  'INVALID_INPUT', 'VK_SUBSTITUTION', 'THRESHOLD_MISMATCH', 'PROOF_REUSED',
  'EXPIRED_CONDITION', 'RECIPIENT_MISMATCH', 'AMOUNT_OVERFLOW',
]);

function policyResult(value) {
  if (!isRecord(value)
      || !(value.decision === 'APPROVE' && value.reason_code === 'VALID_CONDITION'
        || value.decision === 'REJECT' && rejectionReasons.has(value.reason_code))) {
    return rejection('INVALID_INPUT');
  }
  return { decision: value.decision, reason_code: value.reason_code };
}

function canonicalJSON(value, ancestors = new Set(), depth = 0) {
  if (depth > 64) throw new TypeError('JSON nesting is too deep');
  if (value === null || typeof value === 'string' || typeof value === 'boolean'
      || (typeof value === 'number' && Number.isFinite(value))) return JSON.stringify(value);
  if ((!Array.isArray(value) && !isRecord(value)) || ancestors.has(value)) {
    throw new TypeError('Expected JSON data');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${Array.from(value, child => canonicalJSON(child, ancestors, depth + 1)).join(',')}]`;
    }
    return `{${Object.keys(value).sort().map(key =>
      `${JSON.stringify(key)}:${canonicalJSON(value[key], ancestors, depth + 1)}`).join(',')}}`;
  } finally { ancestors.delete(value); }
}

function readState(statePath) {
  try {
    const state = JSON.parse(readFileSync(statePath, 'utf8'));
    if (!isRecord(state) || state.version !== 1 || !isRecord(state.tasks)) throw new Error();
    for (const [id, record] of Object.entries(state.tasks)) {
      if (!id.trim() || !isRecord(record) || typeof record.digest !== 'string'
          || record.digest.length !== 64 || /[^a-f0-9]/.test(record.digest)
          || !['practice', 'competition'].includes(record.mode) || !isRecord(record.response)) throw new Error();
      const response = record.response;
      if (response.reason_code === 'PROOF_GENERATION_FAILED') {
        if (response.decision !== 'REJECT') throw new Error();
      } else if (JSON.stringify(policyResult(response)) !== JSON.stringify({
        decision: response.decision, reason_code: response.reason_code,
      })) throw new Error();
      const noProof = ['INVALID_INPUT', 'PROOF_REUSED', 'PROOF_GENERATION_FAILED'].includes(response.reason_code);
      if (noProof ? Object.hasOwn(response, 'proof') || Object.hasOwn(response, 'public_signals')
        : !hasProofBundle(response)) throw new Error();
      if (response.decision === 'APPROVE') {
        if (typeof record.proofRef !== 'string' || record.proofRef.length > 66
            || !/^0x[0-9a-f]{1,64}(?![\s\S])/.test(record.proofRef)) throw new Error();
      } else if (Object.hasOwn(record, 'proofRef')) throw new Error();
    }
    return state;
  } catch (error) {
    if (error.code === 'ENOENT') return { version: 1, tasks: {} };
    throw new Error('Cannot read valid durable task state');
  }
}

function hasProofBundle({ proof, public_signals }) {
  return isRecord(proof) && Object.keys(proof).length > 0
    && Array.isArray(public_signals) && public_signals.length > 0
    && public_signals.every(value => typeof value === 'string' && /^[0-9]+$/.test(value));
}

// Small event state: a synchronous, atomic commit leaves no event-loop abort gap
// between the final cancellation check and the durable rename/fsync boundary.
function writeState(statePath, state) {
  const temporary = `${statePath}.${randomUUID()}.tmp`;
  let file;
  try {
    file = openSync(temporary, 'wx', 0o600);
    writeFileSync(file, JSON.stringify(state));
    fsyncSync(file);
    closeSync(file);
    file = undefined;
    renameSync(temporary, statePath);
    const directory = openSync(dirname(statePath), 'r');
    try { fsyncSync(directory); } finally { closeSync(directory); }
  } finally {
    if (file !== undefined) closeSync(file);
    try { unlinkSync(temporary); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
}

/**
 * Own one handler in one process per statePath; concurrent writers/processes are
 * unsupported. The parent must create the state directory before serving tasks.
 * All completed policy/prover outcomes are durable; aborted, expired, queue-full,
 * and persistence-failed attempts are not cached. Retries must retain the entire
 * JSON envelope (object key order is irrelevant; array order/types are exact).
 * Only public proof data and accepted references are persisted, never envelopes
 * or prover witness/salt fields. The injected prover owns cryptographic checking.
 * The active prover cannot be forcibly canceled: its late result is discarded,
 * and the serial worker waits for settlement while pending requests expire.
 * maxPending counts waiting jobs, excluding the single active job (default 100).
 * Context accepts the transport's { signal, deadlineAt }; execution is capped at
 * 50 seconds or the earlier envelope/context deadline. An atomic fsync commit is
 * synchronous; cancellation observed before commit prevents any state write.
 */
export function createTaskHandler({ statePath, evaluate = defaultEvaluate, prove = defaultProve, maxPending = 100 }) {
  let state = readState(statePath);
  const queue = [];
  let running = false;
  let storageFailed = false;
  return async function handleTask(envelope, context = {}) {
    let canonical;
    try {
      canonical = canonicalJSON(envelope);
      envelope = JSON.parse(canonical);
    } catch { return rejection('INVALID_INPUT'); }
    if (!isRecord(envelope) || envelope.type !== 'agent-games.proof-gatekeeper.v1'
        || typeof envelope.task_id !== 'string' || !envelope.task_id.trim()
        || !['practice', 'competition'].includes(envelope.mode) || !isRecord(envelope.input)) {
      return rejection('INVALID_INPUT');
    }
    const deadlineAt = Math.min(Date.parse(envelope.deadline_at), context?.deadlineAt ?? Infinity, Date.now() + 50_000);
    if (!Number.isFinite(deadlineAt)) return rejection('INVALID_INPUT');
    const signal = context?.signal;
    if (signal?.aborted) return rejection('REQUEST_ABORTED');
    if (Date.now() >= deadlineAt) return rejection('DEADLINE_EXCEEDED');
    if (queue.length >= maxPending) return rejection('QUEUE_FULL');
    return new Promise((resolve, reject) => {
      const job = { envelope, canonical, deadlineAt, signal, resolve, reject, finished: false };
      const stop = reason => {
        job.stopped = rejection(reason);
        const pending = queue.indexOf(job);
        if (pending !== -1) queue.splice(pending, 1);
        finish(job, job.stopped);
      };
      job.onAbort = () => stop('REQUEST_ABORTED');
      job.timer = setTimeout(() => stop('DEADLINE_EXCEEDED'), deadlineAt - Date.now());
      signal?.addEventListener('abort', job.onAbort, { once: true });
      queue.push(job);
      void drain();
    });
  };

  function finish(job, response, error) {
    if (job.finished) return;
    job.finished = true;
    clearTimeout(job.timer);
    job.signal?.removeEventListener('abort', job.onAbort);
    if (error) job.reject(error); else job.resolve(structuredClone(response));
  }

  async function drain() {
    if (running) return;
    running = true;
    try {
      while (queue.length) {
        const job = queue.shift();
        try { finish(job, await processTask(job)); } catch (error) { finish(job, undefined, error); }
      }
    } finally { running = false; }
  }

  function stopped(job) {
    return job.stopped ?? (Date.now() >= job.deadlineAt ? rejection('DEADLINE_EXCEEDED') : null);
  }

  async function processTask(job) {
    if (stopped(job)) return stopped(job);
    if (storageFailed) return rejection('STATE_PERSISTENCE_FAILED');
    const { envelope, canonical } = job;
    const key = envelope.task_id;
    const digest = createHash('sha256').update(canonical).digest('hex');
    if (Object.hasOwn(state.tasks, key)) {
      return state.tasks[key].digest === digest
        ? state.tasks[key].response
        : rejection('TASK_ID_CONFLICT');
    }
    const accepted = new Set(Object.values(state.tasks)
      .filter(task => task.mode === envelope.mode && task.response.decision === 'APPROVE')
      .map(task => task.proofRef));
    let decision;
    try { decision = policyResult(await evaluate(envelope.input, accepted)); }
    catch { decision = rejection('INVALID_INPUT'); }
    if (stopped(job)) return stopped(job);
    let response = decision;
    if (!['PROOF_REUSED', 'INVALID_INPUT'].includes(decision.reason_code)) {
      try {
        const { proof, public_signals } = await prove(envelope, decision.decision);
        if (!hasProofBundle({ proof, public_signals })) {
          throw new TypeError('Incomplete proof bundle');
        }
        // Only public proof data is retained; prover-side salt/witness fields are dropped.
        response = JSON.parse(canonicalJSON({ ...decision, proof, public_signals }));
      } catch { response = rejection('PROOF_GENERATION_FAILED'); }
    }
    if (stopped(job)) return stopped(job);
    const record = { digest, mode: envelope.mode, response };
    if (response.decision === 'APPROVE') record.proofRef = envelope.input.proof_tx.toLowerCase();
    const next = { ...state, tasks: { ...state.tasks, [key]: record } };
    try { writeState(statePath, next); }
    catch {
      // A post-rename fsync error has an uncertain outcome: require reopening.
      storageFailed = true;
      return rejection('STATE_PERSISTENCE_FAILED');
    }
    state = next;
    return response;
  }
}

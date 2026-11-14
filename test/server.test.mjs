import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { request } from 'node:http';
import { connect } from 'node:net';

// Synthetic local fixtures only; no platform payloads, secrets, or proofs.
const FIXTURE_SECRET = 'ab'.repeat(32);
const FIXTURE_NOW = Date.parse('2026-11-15T12:00:00.000Z');
import { createAgentServer } from '../src/server.mjs';

function signature(raw) {
  return createHmac('sha256', FIXTURE_SECRET).update(raw).digest('hex');
}

async function startServer(t, options = {}) {
  assert.equal(typeof createAgentServer, 'function', 'createAgentServer must be exported');
  const server = createAgentServer({
    secret: FIXTURE_SECRET,
    now: () => FIXTURE_NOW,
    handleTask: async () => { throw new Error('Unexpected fixture handler invocation'); },
    ...options,
  });
  assert.equal(server.listening, false, 'Only the caller should bind the server');
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  t.after(() => new Promise((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  }));
  return server.address().port;
}

function send(port, { method = 'GET', path = '/agent', raw, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, path, method, agent: false, headers }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        const body = Buffer.concat(chunks);
        try {
          resolve({ status: res.statusCode, headers: res.headers, raw: body, json: body.length ? JSON.parse(body) : undefined });
        } catch (error) {
          reject(error);
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(2_000, () => req.destroy(new Error('Fixture HTTP request timed out')));
    req.end(raw);
  });
}

function assertSigned(response) {
  assert.equal(response.headers['content-type'], 'application/json; charset=utf-8');
  assert.equal(response.headers['x-agent-games-signature'], signature(response.raw));
  assert.match(response.headers['x-agent-games-signature'], /^[a-f0-9]{64}$/);
}

test('missing or malformed HMAC returns signed 401 before JSON parsing', async (t) => {
  const port = await startServer(t);
  for (const value of [undefined, '', 'sha256=bad', 'z'.repeat(64), 'a'.repeat(63), '00'.repeat(32)]) {
    const headers = value === undefined ? {} : { 'x-agent-games-signature': value };
    const response = await send(port, { method: 'POST', raw: '{broken JSON', headers });
    assert.equal(response.status, 401);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'UNAUTHORIZED' });
    assertSigned(response);
  }
  const raw = JSON.stringify(preflightFixture());
  for (const tampered of [raw + ' ', raw.replace('fixture-nonce', 'tampered-nonce')]) {
    const response = await send(port, { method: 'POST', raw: tampered,
      headers: { 'x-agent-games-signature': signature(raw) } });
    assert.equal(response.status, 401, 'A changed byte invalidates authentication');
    assertSigned(response);
  }
  const duplicate = await send(port, { method: 'POST', raw,
    headers: { 'x-agent-games-signature': [signature(raw), signature(raw)] } });
  assert.equal(duplicate.status, 401);
  assertSigned(duplicate);
});

test('authenticated malformed JSON returns signed 400', async (t) => {
  const port = await startServer(t);
  const raw = '{not JSON';
  const response = await send(port, {
    method: 'POST', raw, headers: { 'x-agent-games-signature': signature(raw) },
  });
  assert.equal(response.status, 400);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_JSON' });
  assertSigned(response);
});

function preflightFixture(overrides = {}) {
  return { type: 'agent-games.preflight.v1', agent_id: 'fixture-agent',
    issued_at: new Date(FIXTURE_NOW).toISOString(), nonce: 'fixture-nonce', ...overrides };
}

function post(port, envelope, prefix = '') {
  const raw = JSON.stringify(envelope, null, 2) + '\n';
  return send(port, { method: 'POST', raw, headers: {
    'content-type': 'application/json', 'x-agent-games-signature': prefix + signature(raw),
  } });
}

test('preflight accepts exact raw bytes with raw or prefixed HMAC', async (t) => {
  const port = await startServer(t);
  for (const prefix of ['', 'sha256=']) {
    const response = await post(port, preflightFixture(), prefix);
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: true, protocolVersion: 'v1' });
    assertSigned(response);
  }
  for (const issued_at of [new Date(FIXTURE_NOW - 300_000).toISOString(),
    new Date(FIXTURE_NOW + 300_000).toISOString(), '2026-11-15T13:00:00+01:00']) {
    const raw = JSON.stringify(preflightFixture({ issued_at, nonce: 'fixture-你好' }));
    const response = await send(port, { method: 'POST', raw,
      headers: { 'x-agent-games-signature': signature(raw).toUpperCase() } });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: true, protocolVersion: 'v1' });
    assertSigned(response);
  }
});

test('preflight rejects invalid identifiers or nonce', async (t) => {
  const port = await startServer(t);
  for (const overrides of [{ nonce: '' }, { nonce: '   ' }, { nonce: 123 }, { nonce: null },
    { agent_id: '' }, { agent_id: 123 }]) {
    const response = await post(port, preflightFixture(overrides));
    assert.equal(response.status, 400);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE' });
    assertSigned(response);
  }
});

test('preflight rejects invalid or out-of-window issue timestamps', async (t) => {
  const port = await startServer(t);
  for (const issued_at of [undefined, null, FIXTURE_NOW, 'garbage', '2026-11-15',
    '2026-11-15T12:00:00', '2026-02-30T12:00:00Z',
    new Date(FIXTURE_NOW - 300_001).toISOString(),
    new Date(FIXTURE_NOW + 300_001).toISOString()]) {
    const response = await post(port, preflightFixture({ issued_at }));
    assert.equal(response.status, 400, String(issued_at));
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_TIMESTAMP' });
    assertSigned(response);
  }
});

test('unknown envelope types or non-object envelopes return signed 400', async (t) => {
  const port = await startServer(t);
  for (const envelope of [null, [], 'fixture', 1, {}, { type: 'agent-games.unknown.v1' }]) {
    const response = await post(port, envelope);
    assert.equal(response.status, 400);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE' });
    assertSigned(response);
  }
});

function taskFixture(overrides = {}) {
  return { type: 'agent-games.proof-gatekeeper.v1', task_id: 'fixture-task', mode: 'practice',
    issued_at: new Date(FIXTURE_NOW).toISOString(),
    deadline_at: new Date(FIXTURE_NOW + 60_000).toISOString(),
    input: { fixture_only: true }, ...overrides };
}

test('authenticated task delegates the envelope and signs the injected decision', async (t) => {
  // This is a transport fixture, not a usable Groth16 proof.
  const decision = { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY',
    proof: { fixture_only: true }, public_signals: ['1'] };
  const seen = [];
  const port = await startServer(t, { handleTask: async (envelope) => {
    seen.push(envelope);
    return decision;
  } });
  const envelope = taskFixture();
  const response = await post(port, envelope);
  assert.equal(response.status, 200);
  assert.deepEqual(response.json, decision);
  assert.deepEqual(seen, [envelope]);
  assertSigned(response);
});

test('handler or serialization errors return a signed INTERNAL_ERROR without proof', async (t) => {
  const circular = { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY' };
  circular.proof = circular;
  for (const handleTask of [
    () => { throw new Error('sensitive fixture exception'); },
    async () => { throw new Error('sensitive fixture exception'); },
    async () => circular,
  ]) {
    const port = await startServer(t, { handleTask });
    const response = await post(port, taskFixture());
    assert.equal(response.status, 500);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
    assertSigned(response);
    assert.equal(response.raw.includes('sensitive fixture'), false);
  }
});

test('task rejects malformed envelope fields before invoking the handler', async (t) => {
  let calls = 0;
  const port = await startServer(t, { handleTask: async () => {
    calls += 1;
    return { decision: 'REJECT', reason_code: 'FIXTURE_ONLY' };
  } });
  for (const overrides of [{ task_id: undefined }, { task_id: ' ' }, { task_id: 1 },
    { mode: undefined }, { mode: 'unknown' }, { input: null }, { input: [] }, { input: undefined }]) {
    const response = await post(port, taskFixture(overrides));
    assert.equal(response.status, 400);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE' });
    assertSigned(response);
  }
  assert.equal(calls, 0);
});

test('task rejects stale, future, or invalid issue times before dispatch', async (t) => {
  const port = await startServer(t);
  for (const issued_at of [undefined, 'not-a-time', FIXTURE_NOW,
    new Date(FIXTURE_NOW - 300_001).toISOString(),
    new Date(FIXTURE_NOW + 300_001).toISOString()]) {
    const response = await post(port, taskFixture({ issued_at }));
    assert.equal(response.status, 400);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_TIMESTAMP' });
    assertSigned(response);
  }
});

test('task rejects missing or incoherent deadlines before dispatch', async (t) => {
  const port = await startServer(t);
  for (const deadline_at of [undefined, null, FIXTURE_NOW + 60_000, 'bad',
    new Date(FIXTURE_NOW).toISOString(), new Date(FIXTURE_NOW - 1).toISOString()]) {
    const response = await post(port, taskFixture({ deadline_at }));
    assert.equal(response.status, 400);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_DEADLINE' });
    assertSigned(response);
  }
});

test('expired tasks fail closed without invoking the handler', async (t) => {
  const port = await startServer(t);
  const response = await post(port, taskFixture({
    issued_at: new Date(FIXTURE_NOW - 60_000).toISOString(),
    deadline_at: new Date(FIXTURE_NOW).toISOString(),
  }));
  assert.equal(response.status, 408);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
  assertSigned(response);
});

test('task execution timeout returns a signed rejection even if handler never settles', async (t) => {
  const port = await startServer(t, { taskTimeoutMs: 20, handleTask: () => new Promise(() => {}) });
  const started = performance.now();
  const response = await post(port, taskFixture());
  assert.equal(response.status, 504);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
  assert.ok(performance.now() - started < 1_000);
  assertSigned(response);
});

test('execution is bounded by the earlier envelope deadline', async (t) => {
  const port = await startServer(t, { taskTimeoutMs: 1_000, handleTask: () => new Promise(() => {}) });
  const started = performance.now();
  const response = await post(port, taskFixture({ deadline_at: new Date(FIXTURE_NOW + 20).toISOString() }));
  assert.equal(response.status, 504);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
  assert.ok(performance.now() - started < 500, 'Envelope deadline must shorten the task budget');
  assertSigned(response);
});

test('late handler results cannot approve after the deadline', async (t) => {
  let clock = FIXTURE_NOW;
  const port = await startServer(t, { now: () => clock, handleTask: async () => {
    clock += 60_001;
    return { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY', proof: { fixture_only: true } };
  } });
  const response = await post(port, taskFixture());
  assert.equal(response.status, 504);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
  assertSigned(response);
});

test('event-loop delayed completion cannot bypass the execution budget', async (t) => {
  const port = await startServer(t, { taskTimeoutMs: 5, handleTask: () => {
    // Intentional synthetic CPU work reproduces a timer/microtask race.
    const until = performance.now() + 20;
    while (performance.now() < until) { /* fixture-only busy wait */ }
    return { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY' };
  } });
  const response = await post(port, taskFixture());
  assert.equal(response.status, 504);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
  assertSigned(response);
});

test('bodies larger than 64 KiB return signed 413', async (t) => {
  const port = await startServer(t);
  const raw = JSON.stringify(preflightFixture()) + ' '.repeat(65_536);
  const response = await send(port, { method: 'POST', raw,
    headers: { 'x-agent-games-signature': signature(raw) } });
  assert.equal(response.status, 413);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'PAYLOAD_TOO_LARGE' });
  assertSigned(response);
  const exactLimit = JSON.stringify(preflightFixture()).padEnd(65_536, ' ');
  const accepted = await send(port, { method: 'POST', raw: exactLimit,
    headers: { 'x-agent-games-signature': signature(exactLimit) } });
  assert.equal(accepted.status, 200);
  assertSigned(accepted);
});

test('missing signature is rejected before reading an oversized body', async (t) => {
  const port = await startServer(t);
  const response = await send(port, { method: 'POST', raw: 'x'.repeat(65_537) });
  assert.equal(response.status, 401);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'UNAUTHORIZED' });
  assertSigned(response);
});

test('routes only the registered agent and health paths', async (t) => {
  const port = await startServer(t);
  for (const options of [{ path: '/' }, { path: '/unknown', method: 'POST' }]) {
    const response = await send(port, options);
    assert.equal(response.status, 404);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'NOT_FOUND' });
    assertSigned(response);
  }
  for (const options of [{ path: '/agent', method: 'PUT' }, { path: '/healthz', method: 'POST' }]) {
    const response = await send(port, options);
    assert.equal(response.status, 405);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'METHOD_NOT_ALLOWED' });
    assertSigned(response);
  }
});

test('unexpected clock failure becomes a signed internal error', async (t) => {
  const port = await startServer(t, { now: () => { throw new Error('fixture clock failure'); } });
  const response = await post(port, preflightFixture());
  assert.equal(response.status, 500);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  assertSigned(response);
});

test('records authenticated raw bytes and delivery result without headers', async (t) => {
  const records = [];
  const decision = { decision: 'REJECT', reason_code: 'FIXTURE_ONLY' };
  const port = await startServer(t, { recordTask: (record) => records.push(record),
    handleTask: async () => decision });
  const envelope = taskFixture();
  const raw = JSON.stringify(envelope, null, 2) + '\n';
  const response = await send(port, { method: 'POST', raw, headers: {
    'x-agent-games-signature': signature(raw), authorization: 'fixture-header-not-for-records',
  } });
  assert.equal(response.status, 200);
  assert.equal(records.length, 1);
  assert.deepEqual(Object.keys(records[0]).sort(), ['delivered', 'rawBody', 'responseBody', 'statusCode']);
  assert.ok(Buffer.isBuffer(records[0].rawBody));
  assert.deepEqual(records[0].rawBody, Buffer.from(raw));
  assert.deepEqual(records[0].responseBody, response.raw);
  assert.equal(records[0].statusCode, 200);
  assert.equal(records[0].delivered, true);
  const malformed = '{fixture malformed JSON';
  await send(port, { method: 'POST', raw: malformed,
    headers: { 'x-agent-games-signature': signature(malformed) } });
  assert.equal(records.length, 2);
  assert.equal(records[1].statusCode, 400);
  await send(port, { method: 'POST', raw: '{unauthenticated fixture' });
  await send(port, { path: '/healthz' });
  assert.equal(records.length, 2, 'Unauthenticated payloads and health checks are never recorded');
});

test('diagnostic callback failures cannot change the HTTP response', async (t) => {
  for (const recordTask of [
    () => { throw new Error('fixture recorder failure'); },
    async () => { throw new Error('fixture recorder failure'); },
  ]) {
    const port = await startServer(t, { recordTask });
    const response = await post(port, preflightFixture());
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: true, protocolVersion: 'v1' });
    assertSigned(response);
    await new Promise((resolve) => setImmediate(resolve));
  }
});

test('invalid server configuration fails before any socket is bound', () => {
  const valid = { secret: FIXTURE_SECRET, handleTask: async () => ({ decision: 'REJECT', reason_code: 'FIXTURE_ONLY' }) };
  for (const options of [{ secret: undefined }, { secret: '' }, { secret: '   ' }, { secret: 123 },
    { handleTask: undefined }, { handleTask: true }, { now: 1 }, { recordTask: true },
    { taskTimeoutMs: 0 }, { taskTimeoutMs: -1 }, { taskTimeoutMs: NaN },
    { taskTimeoutMs: Infinity }, { taskTimeoutMs: 50_001 }, { taskTimeoutMs: 1.5 },
    { bodyTimeoutMs: 0 }, { bodyTimeoutMs: 10_001 }, { bodyTimeoutMs: NaN }]) {
    assert.throws(() => createAgentServer({ ...valid, ...options }), TypeError);
  }
});

test('malformed UTF-8 is rejected after authenticating the exact bytes', async (t) => {
  const port = await startServer(t);
  const fixture = JSON.stringify(preflightFixture({ nonce: 'X' }));
  const raw = Buffer.from(fixture);
  raw[fixture.indexOf('"X"') + 1] = 0xff;
  const response = await send(port, { method: 'POST', raw,
    headers: { 'x-agent-games-signature': signature(raw) } });
  assert.equal(response.status, 400);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INVALID_JSON' });
  assertSigned(response);
});

test('invalid injected decisions fail closed without returning proof', async (t) => {
  for (const result of [null, [], 'APPROVE', {}, { decision: 'UNKNOWN', reason_code: 'FIXTURE_ONLY' },
    { decision: 'APPROVE' }, { decision: 'APPROVE', reason_code: ' ' },
    { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY', toJSON: () => ({ decision: 'UNKNOWN' }) }]) {
    const port = await startServer(t, { handleTask: async () => result });
    const response = await post(port, taskFixture());
    assert.equal(response.status, 500);
    assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
    assertSigned(response);
  }
});

test('serialization cannot push an approval beyond the deadline', async (t) => {
  let clock = FIXTURE_NOW;
  const port = await startServer(t, { now: () => clock, handleTask: async () => ({
    decision: 'APPROVE', reason_code: 'FIXTURE_ONLY', toJSON() {
      clock += 60_001;
      return { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY' };
    },
  }) });
  const response = await post(port, taskFixture());
  assert.equal(response.status, 504);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
  assertSigned(response);
});

test('timeout aborts cooperative handler work', async (t) => {
  let context;
  const port = await startServer(t, { taskTimeoutMs: 20, handleTask: async (_envelope, execution) => {
    context = execution;
    return new Promise(() => {});
  } });
  const response = await post(port, taskFixture());
  assert.equal(response.status, 504);
  assert.ok(context?.signal instanceof AbortSignal);
  assert.equal(context.signal.aborted, true);
  assert.equal(context.deadlineAt, FIXTURE_NOW + 60_000);
});

test('client disconnect cancels active work and records undelivered payload', async (t) => {
  let enter;
  const entered = new Promise((resolve) => { enter = resolve; });
  let context;
  let recordDelivery;
  const recorded = new Promise((resolve) => { recordDelivery = resolve; });
  const port = await startServer(t, { taskTimeoutMs: 200, recordTask: recordDelivery,
    handleTask: (_envelope, execution) => {
      context = execution;
      enter();
      return new Promise(() => {});
    } });
  const raw = JSON.stringify(taskFixture());
  const req = request({ host: '127.0.0.1', port, path: '/agent', method: 'POST', agent: false,
    headers: { 'x-agent-games-signature': signature(raw) } });
  req.on('error', () => {});
  req.end(raw);
  await entered;
  req.destroy();
  const record = await recorded;
  assert.equal(record.delivered, false);
  assert.equal(record.statusCode, null);
  assert.equal(record.responseBody, null);
  assert.equal(context.signal.aborted, true);
});

test('stalled request bodies receive a signed timeout without dispatch', async (t) => {
  const port = await startServer(t, { bodyTimeoutMs: 20 });
  const response = await new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port, method: 'POST', path: '/agent', agent: false,
      headers: { 'x-agent-games-signature': 'a'.repeat(64), 'content-length': 100 } }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks);
        resolve({ status: res.statusCode, headers: res.headers, raw, json: JSON.parse(raw) });
        req.destroy();
      });
    });
    req.on('error', reject);
    req.setTimeout(1_000, () => req.destroy(new Error('Fixture stalled body did not time out')));
    req.write('{');
  });
  assert.equal(response.status, 408);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'REQUEST_TIMEOUT' });
  assertSigned(response);
});

test('invalid clock state after handler completion fails closed', async (t) => {
  let clock = FIXTURE_NOW;
  const port = await startServer(t, { now: () => clock, handleTask: async () => {
    clock = NaN;
    return { decision: 'APPROVE', reason_code: 'FIXTURE_ONLY' };
  } });
  const response = await post(port, taskFixture());
  assert.equal(response.status, 500);
  assert.deepEqual(response.json, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
  assertSigned(response);
});

test('HEAD rejection signs its transmitted empty body', async (t) => {
  const port = await startServer(t);
  const response = await send(port, { method: 'HEAD' });
  assert.equal(response.status, 405);
  assert.equal(response.raw.length, 0);
  assertSigned(response);
});

test('HTTP parser errors return signed JSON when the socket is writable', async (t) => {
  const port = await startServer(t);
  const rawResponse = await new Promise((resolve, reject) => {
    const chunks = [];
    const socket = connect({ host: '127.0.0.1', port }, () => {
      socket.end('GET /agent HTTP/1.1\r\nHost: localhost\r\nInvalid Header: value\r\n\r\n');
    });
    socket.setTimeout(1_000, () => socket.destroy(new Error('Fixture parser error did not respond')));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
  const [head, body] = rawResponse.split('\r\n\r\n');
  assert.match(head, /^HTTP\/1\.1 400 /);
  const headers = Object.fromEntries(head.split('\r\n').slice(1).map((line) => {
    const colon = line.indexOf(':');
    return [line.slice(0, colon).toLowerCase(), line.slice(colon + 1).trim()];
  }));
  assert.equal(headers['x-agent-games-signature'], signature(body));
  assert.deepEqual(JSON.parse(body), { decision: 'REJECT', reason_code: 'INVALID_HTTP' });
});

test('upload time consumes the total task execution budget', async (t) => {
  let calls = 0;
  const port = await startServer(t, { taskTimeoutMs: 25, bodyTimeoutMs: 200,
    handleTask: async () => { calls++; return { decision:'APPROVE', reason_code:'FIXTURE_ONLY' }; } });
  const raw = JSON.stringify(taskFixture());
  const response = await new Promise((resolve, reject) => {
    const req = request({ host:'127.0.0.1', port, method:'POST', path:'/agent', agent:false,
      headers:{'x-agent-games-signature':signature(raw),'content-length':Buffer.byteLength(raw)} }, res => {
      const chunks=[];
      res.on('data', chunk=>chunks.push(chunk));
      res.on('end',()=>{const body=Buffer.concat(chunks);resolve({status:res.statusCode,headers:res.headers,raw:body,json:JSON.parse(body)});});
    });
    req.on('error',reject);
    req.write(raw.slice(0,1));
    const timer=setTimeout(()=>req.end(raw.slice(1)),80);
    req.on('close',()=>clearTimeout(timer));
  });
  assert.notEqual(response.status,200);
  assert.equal(calls,0,'expired upload must never reach the decision handler');
  assertSigned(response);
});

test('health endpoints return signed JSON without invoking the task handler', async (t) => {
  const port = await startServer(t);
  for (const path of ['/healthz', '/agent']) {
    const response = await send(port, { path });
    assert.equal(response.status, 200);
    assert.deepEqual(response.json, { ok: true });
    assertSigned(response);
  }
});

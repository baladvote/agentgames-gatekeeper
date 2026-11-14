import { createServer } from 'node:http';
import { createHmac, timingSafeEqual } from 'node:crypto';

const MAX_BODY_BYTES = 64 * 1024;
const CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_TASK_TIMEOUT_MS = 50_000;
const MAX_BODY_TIMEOUT_MS = 10_000;

const nonemptyString = (value) => typeof value === 'string' && value.trim().length > 0;

// Require a timezone and reject dates Date.parse would silently normalize.
function timestamp(value) {
  if (typeof value !== 'string') return NaN;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,3})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) return NaN;
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth ||
      hour > 23 || minute > 59 || second > 59) return NaN;
  return Date.parse(value);
}

/**
 * Create an unbound Node HTTP server; the parent owns listen/TLS/shutdown.
 *
 * secret is the literal platform secret (UTF-8, including hex-looking secrets).
 * handleTask(envelope, { signal, deadlineAt }) returns a JSON decision/proof object.
 * Policy, proof correctness, replay protection and proof references belong to it.
 * It must not block the event loop; cancellation is cooperative via signal.
 * now() returns finite epoch milliseconds. Timers use a monotonic elapsed clock.
 *
 * recordTask({ rawBody, responseBody, statusCode, delivered }) runs once after an
 * authenticated delivery finishes or disconnects. Bodies are Buffers; responseBody
 * and statusCode are null if nothing was sent. No headers or secrets are passed.
 * delivered means flushed to the socket, not acknowledged by the platform.
 * The hook should enqueue quickly; promises are not awaited and errors are isolated.
 *
 * Application responses are signed, including validation errors. Never log secrets.
 */
export function createAgentServer({
  secret, handleTask, now = Date.now, recordTask,
  taskTimeoutMs = MAX_TASK_TIMEOUT_MS, bodyTimeoutMs = MAX_BODY_TIMEOUT_MS,
}) {
  if (!nonemptyString(secret)) throw new TypeError('secret must be a nonempty UTF-8 string');
  if (typeof handleTask !== 'function') throw new TypeError('handleTask must be a function');
  if (typeof now !== 'function') throw new TypeError('now must be a function returning epoch milliseconds');
  if (recordTask !== undefined && typeof recordTask !== 'function') {
    throw new TypeError('recordTask must be a function');
  }
  if (!Number.isSafeInteger(taskTimeoutMs) || taskTimeoutMs < 1 || taskTimeoutMs > MAX_TASK_TIMEOUT_MS) {
    throw new TypeError('taskTimeoutMs must be an integer between 1 and 50000');
  }
  if (!Number.isSafeInteger(bodyTimeoutMs) || bodyTimeoutMs < 1 || bodyTimeoutMs > MAX_BODY_TIMEOUT_MS) {
    throw new TypeError('bodyTimeoutMs must be an integer between 1 and 10000');
  }
  const authenticated = new WeakMap();

  function respond(res, status, value) {
    const body = res.req.method === 'HEAD' ? '' : JSON.stringify(value);
    const context = authenticated.get(res);
    if (context) {
      context.statusCode = status;
      context.responseBody = Buffer.from(body);
    }
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      'x-agent-games-signature': createHmac('sha256', secret).update(body).digest('hex'),
    });
    res.end(body);
  }

  async function serve(req, res) {
    const requestStarted = performance.now();
    const path = req.url?.split('?')[0];
    if (path !== '/agent' && path !== '/healthz') {
      respond(res, 404, { decision: 'REJECT', reason_code: 'NOT_FOUND' });
      req.resume();
      return;
    }
    if (req.method !== 'GET' && !(path === '/agent' && req.method === 'POST')) {
      res.setHeader('allow', path === '/agent' ? 'GET, POST' : 'GET');
      respond(res, 405, { decision: 'REJECT', reason_code: 'METHOD_NOT_ALLOWED' });
      req.resume();
      return;
    }
    if (req.method === 'POST') {
      const header = req.headers['x-agent-games-signature'];
      const match = typeof header === 'string' && /^(?:sha256=)?([a-fA-F0-9]{64})$/.exec(header);
      if (!match) {
        res.shouldKeepAlive = false;
        respond(res, 401, { decision: 'REJECT', reason_code: 'UNAUTHORIZED' });
        req.resume();
        return;
      }
      const chunks = [];
      let size = 0;
      const bodyTimer = setTimeout(() => {
        res.shouldKeepAlive = false;
        res.once('finish', () => req.destroy());
        respond(res, 408, { decision: 'REJECT', reason_code: 'REQUEST_TIMEOUT' });
      }, Math.min(bodyTimeoutMs, taskTimeoutMs));
      try {
        for await (const chunk of req.iterator({ destroyOnReturn: false })) {
          size += chunk.length;
          if (size > MAX_BODY_BYTES) {
            res.shouldKeepAlive = false;
            respond(res, 413, { decision: 'REJECT', reason_code: 'PAYLOAD_TOO_LARGE' });
            req.resume();
            return;
          }
          chunks.push(chunk);
        }
      } finally {
        clearTimeout(bodyTimer);
      }
      const raw = Buffer.concat(chunks);
      const digest = createHmac('sha256', secret).update(raw).digest();
      if (!timingSafeEqual(digest, Buffer.from(match[1], 'hex'))) {
        respond(res, 401, { decision: 'REJECT', reason_code: 'UNAUTHORIZED' });
        return;
      }
      if (recordTask) {
        const context = { rawBody: Buffer.from(raw), responseBody: null, statusCode: null };
        authenticated.set(res, context);
        let recorded = false;
        const record = (delivered) => {
          if (recorded) return;
          recorded = true;
          // Diagnostic hooks must never fail, delay, or rewrite a delivery.
          try {
            Promise.resolve(recordTask({ ...context, delivered })).catch(() => {});
          } catch {
            // Intentionally do not log the payload or recorder exception.
          }
        };
        res.once('finish', () => record(true));
        res.once('close', () => record(res.writableFinished));
      }
      let envelope;
      try {
        envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(raw));
      } catch {
        respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_JSON' });
        return;
      }
      if (envelope?.type === 'agent-games.preflight.v1') {
        if (!nonemptyString(envelope.agent_id) || !nonemptyString(envelope.nonce)) {
          respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE' });
          return;
        }
        const issuedAt = timestamp(envelope.issued_at);
        const currentTime = now();
        if (!Number.isFinite(issuedAt) || !Number.isFinite(currentTime) ||
            Math.abs(currentTime - issuedAt) > CLOCK_SKEW_MS) {
          respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_TIMESTAMP' });
          return;
        }
        respond(res, 200, { ok: true, protocolVersion: 'v1' });
        return;
      }
      if (envelope?.type === 'agent-games.proof-gatekeeper.v1') {
        if (!nonemptyString(envelope.task_id) || !['practice', 'competition'].includes(envelope.mode) ||
            !envelope.input || typeof envelope.input !== 'object' || Array.isArray(envelope.input)) {
          respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE' });
          return;
        }
        const issuedAt = timestamp(envelope.issued_at);
        const currentTime = now();
        if (!Number.isFinite(issuedAt) || !Number.isFinite(currentTime) ||
            Math.abs(currentTime - issuedAt) > CLOCK_SKEW_MS) {
          respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_TIMESTAMP' });
          return;
        }
        const deadline = timestamp(envelope.deadline_at);
        if (!Number.isFinite(deadline) || deadline <= issuedAt) {
          respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_DEADLINE' });
          return;
        }
        if (deadline <= currentTime) {
          respond(res, 408, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
          return;
        }
        const controller = new AbortController();
        const started = performance.now();
        const remaining = taskTimeoutMs - (started - requestStarted);
        if (remaining <= 0) {
          respond(res, 504, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
          return;
        }
        const budget = Math.min(remaining, deadline - currentTime);
        const expired = () => {
          const current = now();
          if (!Number.isFinite(current)) throw new TypeError('Clock must return finite epoch milliseconds');
          return current >= deadline || performance.now() - started >= budget;
        };
        let timer;
        const timedOut = Symbol('timeout');
        const disconnected = Symbol('disconnected');
        let onClose;
        const clientClosed = new Promise((resolve) => {
          onClose = () => {
            controller.abort();
            resolve(disconnected);
          };
          res.once('close', onClose);
        });
        try {
          const result = await Promise.race([
            clientClosed,
            Promise.resolve().then(() => handleTask(envelope, { signal: controller.signal, deadlineAt: deadline })),
            new Promise((resolve) => { timer = setTimeout(() => resolve(timedOut), budget); }),
          ]);
          if (result === disconnected) return;
          if (result === timedOut || expired()) {
            respond(res, 504, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
          } else {
            const decision = JSON.parse(JSON.stringify(result));
            if (!decision || Array.isArray(decision) ||
                !['APPROVE', 'REJECT'].includes(decision.decision) || !nonemptyString(decision.reason_code)) {
              throw new TypeError('Invalid task decision');
            }
            if (expired()) {
              respond(res, 504, { decision: 'REJECT', reason_code: 'DEADLINE_EXCEEDED' });
            } else {
              respond(res, 200, decision);
            }
          }
        } catch {
          respond(res, 500, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
        } finally {
          clearTimeout(timer);
          res.off('close', onClose);
          controller.abort();
        }
        return;
      }
      respond(res, 400, { decision: 'REJECT', reason_code: 'INVALID_ENVELOPE' });
      return;
    }
    respond(res, 200, { ok: true });
  }

  const server = createServer((req, res) => {
    void serve(req, res).catch(() => {
      if (!res.destroyed && !res.headersSent) {
        respond(res, 500, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR' });
      }
    });
  });
  server.on('clientError', (error, socket) => {
    if (error.code === 'ECONNRESET' || socket.destroyed || !socket.writable) return;
    const body = JSON.stringify({ decision: 'REJECT', reason_code: 'INVALID_HTTP' });
    const digest = createHmac('sha256', secret).update(body).digest('hex');
    socket.end('HTTP/1.1 400 Bad Request\r\n' +
      'Content-Type: application/json; charset=utf-8\r\n' +
      `Content-Length: ${Buffer.byteLength(body)}\r\n` +
      `X-Agent-Games-Signature: ${digest}\r\n` +
      'Connection: close\r\n\r\n' + body);
  });
  return server;
}

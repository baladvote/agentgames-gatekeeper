import { mkdirSync, appendFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createAgentServer } from './server.mjs';
import { createTaskHandler } from './application.mjs';
import { closeProver } from './prover.mjs';

const secret = process.env.AGENT_GAMES_HMAC_SECRET;
if (!secret || secret.length < 32) throw new Error('Platform HMAC secret is required');
const statePath = process.env.AGENT_GAMES_STATE_FILE;
if (!statePath) throw new Error('Persistent state file is required');
const port = Number(process.env.PORT || 20218);
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('Invalid listen port');
const host = process.env.HOST || '127.0.0.1';
mkdirSync(dirname(statePath), { recursive: true, mode: 0o700 });
const handleTask = createTaskHandler({ statePath });
const server = createAgentServer({
  secret,
  handleTask,
  recordTask({ rawBody, responseBody, statusCode, delivered }) {
    // Signed platform task/public-proof evidence only; never headers or secrets.
    const request = JSON.parse(rawBody.toString('utf8'));
    const response = responseBody ? JSON.parse(responseBody.toString('utf8')) : null;
    appendFileSync(join(dirname(statePath), 'deliveries.jsonl'), JSON.stringify({
      at: new Date().toISOString(), request, response, statusCode, delivered,
    }) + '\n', { mode: 0o600 });
  },
});
server.listen(port, host, () => console.log(JSON.stringify({ event: 'listening', host, port })));
let closing = false;
function shutdown() {
  if (closing) return;
  closing = true;
  const timeout = setTimeout(() => process.exit(1), 5000);
  timeout.unref();
  server.close(async () => {
    await closeProver();
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

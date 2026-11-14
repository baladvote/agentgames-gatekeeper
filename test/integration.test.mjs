import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID, createHmac } from 'node:crypto';
import { mkdtempSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import { groth16 } from 'snarkjs';
import { createAgentServer } from '../src/server.mjs';
import { createTaskHandler } from '../src/application.mjs';
import { closeProver } from '../src/prover.mjs';

// Synthetic local envelopes: actual generated proofs, no mocked verifier or HMAC.
test('real HTTP decisions, proof verification, retries and replay protection', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'gatekeeper-integration-'));
  const secret = randomBytes(32).toString('hex');
  const server = createAgentServer({secret, handleTask: createTaskHandler({statePath: join(dir, 'state.json')})});
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const endpoint = `http://127.0.0.1:${server.address().port}/agent`;
  const vk = JSON.parse(readFileSync(new URL('../circuits/verification_key.json', import.meta.url)));
  async function send(task) {
    const body = JSON.stringify(task);
    const res = await fetch(endpoint, {method: 'POST', headers: {'content-type':'application/json','x-agent-games-signature':createHmac('sha256', secret).update(body).digest('hex')}, body});
    const raw = await res.text();
    assert.equal(res.status, 200, raw);
    assert.equal(res.headers.get('x-agent-games-signature'), createHmac('sha256', secret).update(raw).digest('hex'));
    return JSON.parse(raw);
  }
  function task(changes={}) {
    return {type:'agent-games.proof-gatekeeper.v1',task_id:`practice_${randomUUID()}`,mode:'practice',issued_at:new Date().toISOString(),deadline_at:new Date(Date.now()+30000).toISOString(),input:{registered_vk:'0x'+'a'.repeat(64),proof_vk:'0x'+'a'.repeat(64),minimum:'1000',public_balance:'1460',expiry_block:8430000,current_block:8420000,recipient:'0x'+'1'.repeat(40),condition_recipient:'0x'+'1'.repeat(40),amount:'500',max_transfer:'1000',proof_tx:'0x'+randomBytes(32).toString('hex'),...changes}};
  }
  try {
    const cases = [
      [{}, 'APPROVE', 'VALID_CONDITION'],
      [{proof_vk:'0x'+'b'.repeat(64)}, 'REJECT', 'VK_SUBSTITUTION'],
      [{public_balance:'999'}, 'REJECT', 'THRESHOLD_MISMATCH'],
      [{current_block:8430000}, 'REJECT', 'EXPIRED_CONDITION'],
      [{recipient:'0x'+'2'.repeat(40)}, 'REJECT', 'RECIPIENT_MISMATCH'],
      [{amount:'1001'}, 'REJECT', 'AMOUNT_OVERFLOW'],
    ];
    for (const [changes, decision, reason] of cases) {
      const request = task(changes);
      const reply = await send(request);
      assert.equal(reply.decision, decision);
      assert.equal(reply.reason_code, reason);
      assert.equal(await groth16.verify(vk, reply.public_signals, reply.proof), true);
      assert.deepEqual(await send(request), reply, 'identical task must return the same proof');
      if (decision === 'APPROVE') {
        const reused = await send(task({proof_tx:request.input.proof_tx}));
        assert.equal(reused.reason_code,'PROOF_REUSED');
        assert.equal(reused.decision,'REJECT');
        assert.equal(reused.proof,undefined);
      }
    }
  } finally {
    server.close(); await once(server, 'close');
    await closeProver();
    rmSync(dir, {recursive:true,force:true});
  }
});

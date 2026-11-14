import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const root = fileURLToPath(new URL('..', import.meta.url));
function launch(statePath) {
  const child = spawn('/bin/sh', ['scripts/start.sh'], {cwd:root, env:{...process.env,
    NODE_BINARY:process.execPath, AGENT_GAMES_HMAC_SECRET:randomBytes(32).toString('hex'),
    AGENT_GAMES_STATE_FILE:statePath, HOST:'127.0.0.1', PORT:'29438'},stdio:['ignore','pipe','pipe']});
  let output='';
  child.stdout.on('data',d=>output+=d);
  child.stderr.on('data',()=>{});
  const exited=new Promise(resolve=>child.once('exit',(code,signal)=>resolve({code,signal})));
  return {child,exited,ready:async()=>{
    for(let i=0;i<100;i++){
      if(output.includes('"event":"listening"'))return;
      if(child.exitCode!==null)throw new Error(`Launcher exited ${child.exitCode} before listening`);
      await new Promise(resolve=>setTimeout(resolve,20));
    }
    throw new Error('Launcher did not listen');
  }};
}

test('production launcher exclusively owns state and releases ownership on exit',async t=>{
  const dir=await mkdtemp(join(tmpdir(),'gatekeeper-launcher-'));
  const children=[];
  t.after(async()=>{for(const run of children){if(run.child.exitCode===null)run.child.kill('SIGTERM');await run.exited;}await rm(dir,{recursive:true,force:true});});
  const first=launch(join(dir,'state.json'));children.push(first);await first.ready();
  const second=launch(join(dir,'state.json'));children.push(second);
  assert.equal((await second.exited).code,75,'second writer must fail on lock, before binding or loading state');
  first.child.kill('SIGTERM');assert.equal((await first.exited).code,0);
  const replacement=launch(join(dir,'state.json'));children.push(replacement);await replacement.ready();
});

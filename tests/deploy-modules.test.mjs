import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync, mkdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { checkModules } from '../scripts/check-installed-modules.mjs';

test('preflight rejects a missing runtime import without executing the server', t => {
  const dir = mkdtempSync(join(tmpdir(), 'deployment-modules-')); t.after(() => rmSync(dir, {recursive:true,force:true}));
  const server = join(dir, 'server.js');
  writeFileSync(server, "import './new.mjs'; throw new Error('must not execute');");
  assert.throws(() => checkModules(server), /Missing deployment module/);
  writeFileSync(join(dir,'new.mjs'), "import './nested.mjs';");
  assert.throws(() => checkModules(server), /nested/);
  writeFileSync(join(dir,'nested.mjs'), "import './new.mjs';");
  assert.doesNotThrow(() => checkModules(server));
});

test('checkout changing deploy.sh re-executes the target installer instead of old instructions', t => {
  const dir = mkdtempSync(join(tmpdir(), 'deployment-version-')); t.after(() => rmSync(dir, {recursive:true,force:true}));
  const repo = join(dir,'repo'); mkdirSync(repo);
  const git = (...args) => execFileSync('git',args,{cwd:repo,encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
  git('init','-q','-b','main');git('config','user.name','Test');git('config','user.email','test@example.com');
  const prefix = readFileSync(resolve('deploy.sh'),'utf8').split('# Explicit maintenance mode:')[0];
  writeFileSync(join(repo,'deploy.sh'),prefix + '\necho OLD_INSTALLER\nexit 99\n');
  git('add','.');git('commit','-qm','old');const old=git('rev-parse','HEAD');
  writeFileSync(join(repo,'deploy.sh'),'#!/bin/bash\necho TARGET_INSTALLER "$@"\n');git('commit','-qam','new');const target=git('rev-parse','HEAD');
  execFileSync('git',['clone','-q','--bare',repo,join(dir,'remote')]);git('remote','add','origin',join(dir,'remote'));git('checkout','-q','--detach',old);
  const result=spawnSync('bash',['./deploy.sh','--ref',target],{cwd:repo,encoding:'utf8'});
  assert.equal(result.status,0,result.stderr);assert.match(result.stdout,/TARGET_INSTALLER --ref/);assert.doesNotMatch(result.stdout,/OLD_INSTALLER/);
});

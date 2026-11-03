import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTerminalMailbox } from '../terminal-nfc.mjs';
const invoice = 'lnbc10n1' + 'a'.repeat(150);
test('one invoice, separate owner authorization, retry idempotence, expiry', () => {
  let time = 1000;
  const box = createTerminalMailbox({ origin: 'https://example.com', now: () => time });
  const s = box.create(1000);
  const id = new URL(s.url).pathname.split('/').at(-1);
  const d = box.discover(id);
  assert.equal(d.maxWithdrawable, 1000);
  assert.throws(() => box.poll(id, d.k1));
  assert.throws(() => box.submit(id, 'wrong', invoice));
  box.submit(id, d.k1, invoice);
  box.submit(id, d.k1, invoice);
  assert.throws(() => box.submit(id, d.k1, invoice + 'a'));
  assert.equal(box.poll(id, s.owner).invoice, invoice);
  time = s.expiresAt;
  assert.throws(() => box.poll(id, s.owner));
  assert.throws(() => box.discover(id));
});
test('cancel, invalid limits, bounded storage and payload', () => {
  const box = createTerminalMailbox({ origin: 'https://example.com', maxSessions: 1 });
  for (const n of [0, -1, 1.5, Infinity, 1e15]) assert.throws(() => box.create(n));
  const s = box.create(1000), id = new URL(s.url).pathname.split('/').at(-1);
  assert.throws(() => box.create(1000));
  assert.throws(() => box.submit(id, box.discover(id).k1, 'x'.repeat(9000)));
  assert.throws(() => box.remove(id, 'wrong'));
  box.remove(id, s.owner);
  assert.throws(() => box.discover(id));
  assert.ok(box.create(1000));
});

test('public submission enforces the maximum and does not expose owner capabilities', () => {
  const box = createTerminalMailbox({ origin: 'https://example.com' });
  const s = box.create(1000), id = new URL(s.url).pathname.split('/').at(-1), d = box.discover(id);
  assert.equal(JSON.stringify(d).includes(s.owner), false);
  assert.throws(() => box.submit(id, d.k1, invoice.replace('10n', '11n')));
  assert.throws(() => box.submit(id, d.k1, invoice.replace('10n', '1n')));
  assert.throws(() => box.submit(id, d.k1, invoice.replace('10n', '')));
  assert.throws(() => box.submit(id, d.k1, invoice.replace('10n', '10001p')));
  assert.equal(box.poll(id, s.owner).invoice, null);
});

test('HTTP discovery/callback and owner polling work without granting payment authority', async () => {
  const { createServer } = await import('node:http');
  const { terminalHandler } = await import('../terminal-nfc.mjs');
  const box = createTerminalMailbox({ origin: 'https://example.com' });
  const handler = terminalHandler({ mailbox: box, allow: () => true, readBody: async req => { const parts = []; for await (const p of req) parts.push(p); return Buffer.concat(parts); } });
  const server = createServer(async (req, res) => { await handler(req, res, new URL(req.url, 'https://example.com'), 'test'); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const created = await fetch(base + '/api/terminal-nfc', { method: 'POST', body: JSON.stringify({maxMsat: 1000}) });
    assert.equal(created.status, 201);
    assert.equal(created.headers.get('cache-control'), 'no-store');
    const s = await created.json(), path = new URL(s.url).pathname;
    const d = await (await fetch(base + path)).json();
    assert.equal((await fetch(base + path + '/status')).status, 400);
    const callback = await fetch(base + path + '/callback?k1=' + d.k1 + '&pr=' + invoice);
    assert.deepEqual(await callback.json(), { status: 'OK' });
    const headers = { Authorization: 'Bearer ' + s.owner };
    const poll = await (await fetch(base + path + '/status', {headers})).json();
    assert.equal(poll.invoice, invoice);
    assert.equal((await fetch(base + path, { method: 'DELETE', headers })).status, 200);
    assert.equal((await fetch(base + path)).status, 400);
  } finally { await new Promise(resolve => server.close(resolve)); }
});

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide, DEFAULT_STATE } from '../monitor/alert-policy.mjs';

const T0 = 1_700_000_000_000;
const MIN = 60_000;
const opts = { alertAfter: 2, reminderMs: 60 * MIN };

// Walk a sequence of pass/fail runs and collect the mail that would be sent.
function run(sequence, { start = undefined, step = 5 * MIN, options = opts } = {}) {
  let state = start;
  const sent = [];
  sequence.forEach((ok, i) => {
    const now = T0 + i * step;
    const r = decide(state, ok, now, options);
    state = r.state;
    if (r.email) sent.push(r.email.kind);
  });
  return { state, sent };
}

test('a single failed run stays quiet; the second consecutive one alerts', () => {
  assert.deepEqual(run([true, false]).sent, []);
  assert.deepEqual(run([true, false, false]).sent, ['alert']);
});

test('a one-run blip that recovers sends nothing at all', () => {
  const { sent, state } = run([true, false, true]);
  assert.deepEqual(sent, [], 'no alert and no recovery mail for a blip');
  assert.equal(state.fails, 0);
  assert.equal(state.alerted, false);
});

test('recovery is announced only after a real alert', () => {
  assert.deepEqual(run([true, false, false, true]).sent, ['alert', 'recovered']);
});

test('a sustained outage alerts once, then reminds hourly', () => {
  // 5 minute steps: an alert on the second failure, a reminder an hour later.
  const { sent } = run(Array(16).fill(false));
  assert.deepEqual(sent, ['alert', 'reminder']);
});

test('downtime is measured from the first failure, not the alert', () => {
  let state = DEFAULT_STATE;
  state = decide(state, false, T0, opts).state;              // first failure
  const alert = decide(state, false, T0 + 5 * MIN, opts);     // alert fires here
  assert.equal(alert.email.kind, 'alert');
  assert.equal(alert.state.since, T0, 'since must point at the first failure');
  const recovered = decide(alert.state, true, T0 + 25 * MIN, opts);
  assert.equal(recovered.email.minutes, 25, 'downtime spans from the first failure');
});

test('alertAfter of 1 restores immediate alerting', () => {
  const immediate = { ...opts, alertAfter: 1 };
  assert.deepEqual(run([true, false], { options: immediate }).sent, ['alert']);
});

test('state written by the previous version is accepted', () => {
  // Older releases stored only these three fields.
  const legacy = { ok: true, since: null, lastReminder: null };
  const first = decide(legacy, false, T0, opts);
  assert.equal(first.email, null);
  assert.equal(first.state.fails, 1);
  const second = decide(first.state, false, T0 + 5 * MIN, opts);
  assert.equal(second.email.kind, 'alert');
});

test('flapping never double-alerts without an intervening recovery', () => {
  const { sent } = run([false, false, true, false, false]);
  assert.deepEqual(sent, ['alert', 'recovered', 'alert']);
});

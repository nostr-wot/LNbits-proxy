/**
 * When the monitor should email, and when it should stay quiet.
 *
 * Kept separate from monitor.mjs, which runs its checks on import and so cannot
 * be unit tested. This is a pure function: given the previous state for a check
 * and the current result, it returns the next state and which mail to send.
 *
 * The damping exists because several checks reach the same stack through the
 * public edge. A brief hiccup used to fire one alert per check at once, then a
 * matching recovery on the next run, which trains people to ignore the alerts.
 */

export const DEFAULT_STATE = { ok: true, since: null, lastReminder: null, fails: 0, alerted: false };

/**
 * @param {object} prev      previous stored state for this check
 * @param {boolean} ok       did the check pass this run
 * @param {number} now       current time in ms
 * @param {object} opts      { alertAfter, reminderMs }
 * @returns {{state: object, email: null | {kind: 'alert'|'recovered'|'reminder', minutes: number, fails: number}}}
 */
export function decide(prev, ok, now, { alertAfter = 2, reminderMs = 3_600_000 } = {}) {
  const previous = { ...DEFAULT_STATE, ...(prev || {}) };

  if (ok) {
    // Only announce a recovery if we actually told anyone it was broken.
    const email = previous.alerted
      ? { kind: 'recovered', minutes: minutesSince(previous.since, now), fails: previous.fails }
      : null;
    return { state: { ...DEFAULT_STATE }, email };
  }

  const fails = (previous.fails || 0) + 1;
  const since = previous.since || now;

  if (!previous.alerted && fails >= alertAfter) {
    return {
      state: { ok: false, since, lastReminder: now, fails, alerted: true },
      email: { kind: 'alert', minutes: minutesSince(since, now), fails },
    };
  }

  if (previous.alerted && now - (previous.lastReminder || 0) >= reminderMs) {
    return {
      state: { ok: false, since, lastReminder: now, fails, alerted: true },
      email: { kind: 'reminder', minutes: minutesSince(since, now), fails },
    };
  }

  // Below the threshold, or already alerted and not yet due a reminder.
  return {
    state: { ok: false, since, lastReminder: previous.lastReminder || null, fails, alerted: previous.alerted },
    email: null,
  };
}

function minutesSince(since, now) {
  return since ? Math.round((now - since) / 60000) : 0;
}

// How much this service is being asked for, and nothing about who is asking.
//
// The platform page wants to show usage. The obvious way to get it is an
// analytics script, and this service cannot have one: it argues that it holds
// nothing able to identify a person, and a third-party beacon on the sign-in
// page would end that argument in one line.
//
// So the number is counted here, and it is a COUNT. One row per hour holding
// how many requests arrived in that hour — no address, no user agent, no path,
// no session, nothing joinable to anything. Two people and one person refreshing
// twice are the same row, deliberately: distinguishing them is exactly the
// capability this service is built not to have.
//
// Requests are tallied in memory and written once a minute, so a busy hour costs
// sixty writes rather than one per request.

import { dbAll, dbGet, dbRun } from './database.js';

const HOUR_MS = 3600000;
const KEEP_HOURS = 24 * 8;

// Not exported. A caller that could read it would be tempted to report a live
// figure that has not been flushed, and the flushed figure is the only one that
// survives a restart.
let pending = 0;

export const hourOf = (now) => Math.floor(now / HOUR_MS);

// Express middleware. Deliberately cheap: an increment and nothing else on the
// request path.
export function countRequest(req, res, next) {
  pending += 1;
  next();
}

export async function flushTraffic(now = Date.now()) {
  if (pending === 0) return 0;

  // Taken before the await, not after. Requests keep arriving while the write
  // is in flight, and reading `pending` afterwards would count them twice or
  // throw them away depending on the order things resolved.
  const delta = pending;
  pending = 0;

  try {
    await dbRun(
      `INSERT INTO traffic (hour, requests) VALUES (?, ?)
         ON CONFLICT(hour) DO UPDATE SET requests = requests + excluded.requests`,
      [hourOf(now), delta]
    );
    return delta;
  } catch (err) {
    // Put them back rather than lose them: this is a background job, and a
    // failed write is not a reason to under-report for ever.
    pending += delta;
    console.error('traffic flush failed:', err.message);
    return 0;
  }
}

export async function pruneTraffic(now = Date.now()) {
  try {
    await dbRun('DELETE FROM traffic WHERE hour < ?', [hourOf(now) - KEEP_HOURS]);
  } catch (err) {
    console.error('traffic pruning failed:', err.message);
  }
}

// The last 24 complete-or-current hours.
export async function requestsLastDay(now = Date.now()) {
  const row = await dbGet('SELECT SUM(requests) AS n FROM traffic WHERE hour > ?', [
    hourOf(now) - 24
  ]);
  return row?.n || 0;
}

// Twenty-four numbers, oldest first, for drawing. Hours with no traffic are
// zeroes rather than gaps: a chart with holes in it reads as missing data, and
// nothing was missing — nobody asked.
export async function requestsByHour(now = Date.now()) {
  const first = hourOf(now) - 23;
  const rows = await dbAll('SELECT hour, requests FROM traffic WHERE hour >= ? ORDER BY hour', [
    first
  ]);
  const byHour = new Map(rows.map((r) => [r.hour, r.requests]));
  return Array.from({ length: 24 }, (_, i) => byHour.get(first + i) || 0);
}

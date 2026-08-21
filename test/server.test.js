// server.js is the process bootstrap - importing it must start nothing, the
// same guarantee app.js gives. It only runs start() when this file is the
// process entry point, which a test never is. That is what makes it safe to
// import sweep, backup and makeShutdown directly here.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase, dbAll } from '../lib/database.js';
import { issueCode } from '../lib/codes.js';
import { CODE_TTL_MS, SWEEP_INTERVAL_MS, CODE_SWEEP_INTERVAL_MS } from '../lib/config.js';
import {
  sweep,
  sweepCodesJob,
  backup,
  makeShutdown,
  makeUncaughtExceptionHandler,
  makeUnhandledRejectionHandler
} from '../server.js';

before(async () => {
  await initDatabase(':memory:');
});
after(async () => {
  await closeDatabase();
});

test('two concurrent sweep ticks: the underlying work runs once, not twice', async () => {
  // The guard check and flag-set run synchronously before either call's
  // first await, so this is deterministic, not a timing-dependent race: two
  // ticks fired back-to-back can never both see the job idle. This is the
  // exact scenario flagged in Task 4's review - two concurrent
  // rotateIfNeeded calls each minting a signing key - fixed by never letting
  // a second tick start while the first is still running.
  const [first, second] = await Promise.all([sweep(), sweep()]);
  const ranCount = [first, second].filter((r) => r.ran).length;
  assert.equal(ranCount, 1, 'exactly one of the two concurrent ticks actually ran the sweep');
});

test('a sweep tick after the previous one finished is free to run', async () => {
  const first = await sweep();
  const second = await sweep();
  assert.equal(first.ran, true);
  assert.equal(second.ran, true);
});

test('codes get their own, shorter sweep cadence than the general sweep', () => {
  // The whole point of splitting sweepCodesJob out of sweep(): an abandoned
  // code must not have to wait for the general sweep's 10-minute cadence.
  assert.ok(
    CODE_SWEEP_INTERVAL_MS < SWEEP_INTERVAL_MS,
    'the code sweep must run more often than the general sweep'
  );
});

test('the dedicated code sweep reclaims an abandoned code on its own cadence', async () => {
  // "Abandoned" here means never consumed at all - the row that this review
  // finding is about, which the tombstoning UPDATE never touches because
  // there is no consumeCode call to run it. Only the sweep ever removes it.
  const now = Date.now();
  const abandoned = await issueCode(
    { appSub: 'sub-x', clientId: 'client-x', redirectUri: 'https://x.test/cb' },
    now - CODE_TTL_MS - 1000 // already past CODE_TTL_MS, well short of SWEEP_INTERVAL_MS
  );
  assert.ok(abandoned);

  const result = await sweepCodesJob();
  assert.equal(result.ran, true);

  const remaining = await dbAll('SELECT code_hash FROM codes');
  assert.equal(
    remaining.length,
    0,
    'the abandoned code must be gone well before the general sweep would run'
  );
});

test('two concurrent code-sweep ticks: the underlying work runs once, not twice', async () => {
  const [first, second] = await Promise.all([sweepCodesJob(), sweepCodesJob()]);
  const ranCount = [first, second].filter((r) => r.ran).length;
  assert.equal(ranCount, 1, 'exactly one of the two concurrent ticks actually ran the code sweep');
});

test('two concurrent backup ticks: the underlying work runs once, not twice', async () => {
  const [first, second] = await Promise.all([backup(), backup()]);
  const ranCount = [first, second].filter((r) => r.ran).length;
  assert.equal(ranCount, 1, 'exactly one of the two concurrent ticks actually ran the backup');
});

test('a backup tick after the previous one finished is free to run', async () => {
  const first = await backup();
  const second = await backup();
  assert.equal(first.ran, true);
  assert.equal(second.ran, true);
});

test('a second shutdown signal does not close the server or exit twice', async () => {
  let closeCalls = 0;
  let closeCallback;
  const fakeServer = {
    close(cb) {
      closeCalls += 1;
      closeCallback = cb;
    }
  };
  const exitCodes = [];
  const shutdown = makeShutdown({
    server: fakeServer,
    closeDatabase: async () => {},
    exit: (code) => exitCodes.push(code),
    timeoutMs: 5
  });

  shutdown('SIGTERM');
  shutdown('SIGINT'); // a second, differing signal must be a no-op
  shutdown('SIGTERM'); // as must a repeat of the first

  assert.equal(closeCalls, 1, 'server.close is called exactly once');
  await closeCallback();
  assert.deepEqual(exitCodes, [0], 'process.exit is called exactly once, with 0');
});

test('a rejection from closeDatabase inside the close callback does not escape', async () => {
  let closeCallback;
  const fakeServer = {
    close(cb) {
      closeCallback = cb;
    }
  };
  const exitCodes = [];
  const shutdown = makeShutdown({
    server: fakeServer,
    closeDatabase: async () => {
      throw new Error('boom');
    },
    exit: (code) => exitCodes.push(code),
    timeoutMs: 5
  });

  shutdown('SIGTERM');
  // If the rejection inside the close callback were uncaught, this await
  // would throw and take the test process down with it.
  await assert.doesNotReject(closeCallback());
  assert.deepEqual(exitCodes, [0], 'shutdown still completes after a closeDatabase failure');
});

test('an uncaught exception is logged and routed through graceful shutdown, not left to kill the process', () => {
  const logCalls = [];
  const shutdownCalls = [];
  const handler = makeUncaughtExceptionHandler(
    (signal) => shutdownCalls.push(signal),
    (...args) => logCalls.push(args)
  );

  handler(new Error('a token leaked into an error message, hypothetically'));

  assert.deepEqual(shutdownCalls, ['uncaughtException'], 'must go through the same path as a signal');
  assert.equal(logCalls.length, 1, 'must log exactly once');
  assert.equal(logCalls[0][1], 'a token leaked into an error message, hypothetically');
});

test('an uncaught exception with no message still logs and still shuts down', () => {
  const shutdownCalls = [];
  const handler = makeUncaughtExceptionHandler(
    (signal) => shutdownCalls.push(signal),
    () => {}
  );
  assert.doesNotThrow(() => handler({}));
  assert.deepEqual(shutdownCalls, ['uncaughtException']);
});

test('an unhandled rejection is logged and does not crash or shut the process down', () => {
  const logCalls = [];
  const handler = makeUnhandledRejectionHandler((...args) => logCalls.push(args));

  assert.doesNotThrow(() => handler(new Error('boom')));
  assert.equal(logCalls.length, 1);
  assert.equal(logCalls[0][1], 'boom');
});

test('an unhandled rejection with a non-Error reason is still logged safely', () => {
  // Promise.reject('a string') is legal - the reason is not guaranteed to be
  // an Error, so this must not assume `.message` exists.
  const logCalls = [];
  const handler = makeUnhandledRejectionHandler((...args) => logCalls.push(args));

  assert.doesNotThrow(() => handler('a plain string rejection'));
  assert.equal(logCalls[0][1], 'a plain string rejection');
});

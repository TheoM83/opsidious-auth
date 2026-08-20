// server.js is the process bootstrap - importing it must start nothing, the
// same guarantee app.js gives. It only runs start() when this file is the
// process entry point, which a test never is. That is what makes it safe to
// import sweep, backup and makeShutdown directly here.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { initDatabase, closeDatabase } from '../lib/database.js';
import { sweep, backup, makeShutdown } from '../server.js';

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

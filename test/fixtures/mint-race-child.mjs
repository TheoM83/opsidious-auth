// Not a *.test.js file, so test/run-tests.mjs never picks this up as a suite
// of its own. It is a standalone process spawned by
// test/keys-mint-race.test.js: open the database file it is given, mint (or
// find) the current signing key exactly like a real boot would, print the
// kid, then exit. Several of these are launched at once against one shared,
// freshly created database file to reproduce the multi-process mint race
// that a single Node process, however concurrent its own promises are,
// cannot: every one of these has its own OS process, its own SQLite
// connection, and no shared JS module state to coordinate through.
import { initDatabase, closeDatabase } from '../../lib/database.js';
import { currentSigner } from '../../lib/keys.js';

const dbPath = process.argv[2];

await initDatabase(dbPath);
const { kid } = await currentSigner();
await closeDatabase();

process.stdout.write(kid + '\n');

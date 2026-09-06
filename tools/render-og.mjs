// Renders the two share cards from tools/og-card.html.
//
// This is NOT part of `node build.mjs`, and it is not in the Dockerfile: it
// needs a browser, and the build image has none. The two PNGs it writes are
// committed instead, and this script exists so that the next person to change
// the card does not have to reinvent how they were made.
//
//   node tools/render-og.mjs
//
// A share card has to be a raster image. Every crawler that matters — Reddit,
// Slack, Discord, iMessage, X — refuses an SVG og:image outright, so the
// vector card above is rendered rather than linked.

import { spawn } from 'node:child_process';
import { access, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// 1200×630 is the size every crawler crops to 1.91:1 without touching it.
const WIDTH = 1200;
const HEIGHT = 630;

const CANDIDATES = [
  process.env.CHROME,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
  '/usr/bin/google-chrome',
  '/usr/bin/chromium',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
].filter(Boolean);

async function findChrome() {
  for (const path of CANDIDATES) {
    try {
      await access(path);
      return path;
    } catch {
      // Not installed at that path; try the next candidate.
    }
  }
  throw new Error(`no browser found. Set CHROME=/path/to/chrome.\nLooked in:\n  ${CANDIDATES.join('\n  ')}`);
}

const card = new URL('./og-card.html', import.meta.url);

async function shoot(chrome, profile, query, out) {
  const url = new URL(card);
  url.search = query;

  await new Promise((resolve, reject) => {
    const child = spawn(
      chrome,
      [
        '--headless=new',
        '--disable-gpu',
        '--hide-scrollbars',
        `--user-data-dir=${profile}`,
        `--window-size=${WIDTH},${HEIGHT}`,
        '--force-device-scale-factor=1',
        // The card loads its two typefaces over the network, and a screenshot
        // taken before they arrive is the fallback stack — visibly wrong, and
        // wrong in a way that only shows up once the card is already live on
        // somebody else's timeline. Virtual time runs the page's clock forward
        // and only then captures.
        '--virtual-time-budget=8000',
        `--screenshot=${fileURLToPath(out)}`,
        url.href
      ],
      { stdio: 'inherit' }
    );

    child.on('error', reject);
    child.on('exit', (code) => (code === 0 ? resolve() : reject(new Error(`browser exited ${code}`))));
  });
}

const chrome = await findChrome();
const profile = await mkdtemp(join(tmpdir(), 'og-'));

try {
  for (const [query, name] of [
    ['', 'og.png'],
    ['?lang=fr', 'og-fr.png']
  ]) {
    const out = new URL(`../public/${name}`, import.meta.url);
    await shoot(chrome, profile, query, out);
    console.log(`public/${name}  ${WIDTH}×${HEIGHT}`);
  }
} finally {
  await rm(profile, { recursive: true, force: true });
}

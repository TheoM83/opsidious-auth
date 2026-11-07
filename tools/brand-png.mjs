// PNG exports of the Opsidious Auth brand, rendered by headless Chrome from
// the SVGs that tools/brand.py writes. Run after it: node tools/brand-png.mjs
//
// Transparent backgrounds everywhere except the iOS icon, which iOS masks
// itself and which must therefore be a full square.

import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const chrome = process.env.CHROME || 'C:/Program Files/Google/Chrome/Application/chrome.exe';

const INK = '#0B0D12';
const A = 'M60 6 L114 108 L86 108 L60 46 L34 108 L6 108 Z';
const KEY_ICON = 'M60 67 A9 9 0 0 1 65.2 83.35 L68.5 100 L51.5 100 L54.8 83.35 A9 9 0 0 1 60 67 Z';
// The iOS icon: a full ink square, the symbol at the app icon's proportion.
const ios = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120"><rect width="120" height="120" fill="${INK}"/><g transform="translate(23.4 23.4) scale(0.61)"><path d="${A}" fill="#E3E7EE"/><path d="${KEY_ICON}" fill="#8A6CFF"/></g></svg>`;

const jobs = [
  // [source svg (repo path) or inline svg, width, height, output]
  ['public/favicon.svg', 32, 32, 'public/favicon-32.png'],
  [ios, 180, 180, 'public/apple-touch-icon.png'],
  ['logo/icones/app-icon.svg', 512, 512, 'public/icon-512.png'],
  ['logo/icones/favicon.svg', 16, 16, 'logo/icones/favicon-16.png'],
  ['logo/icones/favicon.svg', 32, 32, 'logo/icones/favicon-32.png'],
  [ios, 180, 180, 'logo/icones/apple-touch-icon-180.png'],
  ['logo/icones/app-icon.svg', 512, 512, 'logo/icones/app-icon-512.png'],
  ['logo/icones/app-icon.svg', 1024, 1024, 'logo/icones/app-icon-1024.png'],
  ['logo/icones/avatar.svg', 512, 512, 'logo/icones/avatar-512.png'],
  ['logo/svg/opsidious-auth-symbole-noir.svg', 1084, 1024, 'logo/png/opsidious-auth-symbole-noir-1024.png'],
  ['logo/svg/opsidious-auth-symbole-blanc.svg', 1084, 1024, 'logo/png/opsidious-auth-symbole-blanc-1024.png'],
  ['logo/svg/opsidious-auth-horizontal-noir.svg', 2000, 299, 'logo/png/opsidious-auth-horizontal-noir-2000.png'],
  ['logo/svg/opsidious-auth-horizontal-blanc.svg', 2000, 299, 'logo/png/opsidious-auth-horizontal-blanc-2000.png']
];

function shoot(html, w, h, out) {
  const dir = mkdtempSync(join(tmpdir(), 'brand-'));
  const page = join(dir, 'p.html');
  writeFileSync(page, html);
  return new Promise((resolve, reject) => {
    const child = spawn(chrome, [
      '--headless=new', '--disable-gpu', '--hide-scrollbars', `--user-data-dir=${join(dir, 'profile')}`,
      `--window-size=${w},${h}`, '--force-device-scale-factor=1', '--default-background-color=00000000',
      '--allow-file-access-from-files', `--screenshot=${join(root, out)}`, pathToFileURL(page).href
    ], { stdio: 'ignore' });
    child.on('exit', (code) => {
      rmSync(dir, { recursive: true, force: true });
      code === 0 ? resolve() : reject(new Error(`${out}: chrome exited ${code}`));
    });
  });
}

for (const [src, w, h, out] of jobs) {
  const img = src.startsWith('<svg')
    ? `<img src="data:image/svg+xml;base64,${Buffer.from(src).toString('base64')}">`
    : `<img src="${pathToFileURL(join(root, src)).href}">`;
  const html = `<!doctype html><html><head><style>html,body{margin:0;background:transparent}img{display:block;width:${w}px;height:${h}px;object-fit:contain}</style></head><body>${img}</body></html>`;
  await shoot(html, w, h, out);
  console.log('wrote', out);
}

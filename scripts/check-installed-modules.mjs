#!/usr/bin/env node
import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

/** Resolve local ESM dependencies without executing the production server. */
export function checkModules(entry, seen = new Set()) {
  const file = resolve(entry);
  if (seen.has(file)) return;
  if (!existsSync(file)) throw new Error(`Missing deployment module: ${file}`);
  seen.add(file);
  const source = readFileSync(file, 'utf8');
  for (const match of source.matchAll(/(?:\bfrom\s*|\bimport\s*\(?\s*)['"](\.[^'"]+)['"]/g)) {
    checkModules(resolve(dirname(file), match[1]), seen);
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { checkModules(process.argv[2]); console.log('Installed local modules are complete'); }
  catch (e) { console.error(e.message); process.exitCode = 1; }
}

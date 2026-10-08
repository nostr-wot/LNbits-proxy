#!/usr/bin/env node
/**
 * Refuse a release that disagrees with itself.
 *
 * A release here is three things saying the same thing: the tag, the version in
 * package.json, and a CHANGELOG section with that exact heading. The box deploys
 * published releases, so this check is the gate between "someone pushed a tag" and
 * "the production service restarts onto it".
 *
 * Usage: node scripts/check-release.mjs v1.2.3 [--notes]
 * Exits 0 when the release is coherent, 1 with a reason on stderr when it is not.
 * With --notes it also prints that changelog section, so the release notes and the
 * thing being checked are read by the same code rather than by a copy in YAML.
 */
import { readFileSync } from 'node:fs';

const problems = [];
const tag = process.argv[2] ?? '';
const notesOnly = process.argv.includes('--notes');

// No pre-releases and no decorated names: the deployer matches this shape too, and
// two places guessing at a format is how a tag deploys that nobody meant to ship.
if (!/^v\d+\.\d+\.\d+$/.test(tag)) {
  console.error(`check-release: tag must look like v1.2.3, got "${tag}"`);
  process.exit(1);
}
const version = tag.slice(1);

let pkg;
try {
  pkg = JSON.parse(readFileSync('package.json', 'utf8'));
} catch (e) {
  console.error(`check-release: cannot read package.json: ${e.message}`);
  process.exit(1);
}
if (pkg.version !== version) {
  problems.push(`package.json says ${pkg.version}, tag says ${version}`);
}

let changelog;
try {
  changelog = readFileSync('CHANGELOG.md', 'utf8');
} catch (e) {
  console.error(`check-release: cannot read CHANGELOG.md: ${e.message}`);
  process.exit(1);
}

// The heading may carry a date; its body is everything up to the next level-2
// heading. Scanned line by line rather than with one regex, because the end of the
// last section is the end of the file and JS has no end-of-input anchor under /m.
const escaped = version.replace(/\./g, '\\.');
const heading = new RegExp(`^## ${escaped}(?: .*)?$`);
let section = '';
const lines = changelog.split('\n');
const start = lines.findIndex(line => heading.test(line));
if (start === -1) {
  problems.push(`CHANGELOG.md has no "## ${version}" section — rename the Unreleased heading`);
} else {
  const rest = lines.slice(start + 1);
  const next = rest.findIndex(line => line.startsWith('## '));
  section = (next === -1 ? rest : rest.slice(0, next)).join('\n');
  if (!section.trim()) problems.push(`the CHANGELOG.md section for ${version} is empty`);
}

if (problems.length) {
  for (const problem of problems) console.error(`check-release: ${problem}`);
  process.exit(1);
}
if (notesOnly) {
  process.stdout.write(`${section.trim()}\n`);
} else {
  console.log(`check-release: ${tag} is coherent (package.json and CHANGELOG.md agree)`);
}

import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const original = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const workspace = mkdtempSync(join(tmpdir(), 'oauth-audit-sources-'));
const installed = process.env.TEST_SKILL_PATH || join(workspace, 'read-only-skill');
if (!process.env.TEST_SKILL_PATH) {
  for (const folder of ['scripts', 'sources']) mkdirSync(join(installed, folder), { recursive: true });
  for (const file of ['scripts/fetch-sources.mjs', 'scripts/rfc-quote.mjs', 'sources/rfc9700.txt']) {
    copyFileSync(join(original, file), join(installed, file));
    chmodSync(join(installed, file), 0o444);
  }
  for (const folder of ['scripts', 'sources', '']) chmodSync(join(installed, folder), 0o555);
}

// failing に URL を渡すと、その要求だけを 503 にする
const mockFetch = (status = 200, failing = '') => `
globalThis.fetch = async (url) => {
  if (${status} !== 200 || url === ${JSON.stringify(failing)}) return new Response('unavailable', { status: 503 });
  if (url === 'https://zenn.dev/api/books/oauth-attacks-and-bcp?username=hidebike712') {
    return Response.json({ book: { chapters: [{ id: 'fixture', slug: 'id-token-injection' }, { id: 'second', slug: 'second' }] } });
  }
  if (url === 'https://zenn.dev/api/chapters/fixture' || url === 'https://zenn.dev/api/chapters/second') {
    return Response.json({ chapter: { title: 'Fixture chapter', body_html: '<p>Chapter &amp; source.</p>' } });
  }
  if (url === 'https://openid.net/specs/openid-connect-core-1_0.html') {
    return new Response('<p>The client MUST validate the fixture.</p>');
  }
  throw new Error('Unexpected request: ' + url);
};`;

const run = (script, args, mock = mockFetch()) => spawnSync(process.execPath, [
  '--import', `data:text/javascript;base64,${Buffer.from(mock).toString('base64')}`,
  join(installed, 'scripts', script), ...args,
], { cwd: workspace, encoding: 'utf8' });

const snapshot = (folder) => readdirSync(folder, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name)).map((entry) => [
  entry.name, entry.isDirectory() ? snapshot(join(folder, entry.name)) : readFileSync(join(folder, entry.name)).toString('base64'),
]);

test('fetch requires an explicit output directory before making requests', () => {
  for (const args of [[], ['one', 'two']]) {
    const result = run('fetch-sources.mjs', args, 'globalThis.fetch = () => { throw new Error("Unexpected network"); };');
    assert.equal(result.status, 1);
    assert.match(result.stderr, /Usage:/);
    assert.doesNotMatch(result.stderr, /Unexpected network/);
  }
});

test('fetch and quote work outside a read-only installation without changing it', () => {
  const before = snapshot(installed);
  const result = run('fetch-sources.mjs', ['audit work/sources']);
  assert.equal(result.status, 0, result.stderr);
  const sources = join(workspace, 'audit work', 'sources');
  assert.match(readFileSync(join(sources, 'zenn', '01-idt-injection.txt'), 'utf8'), /^取得日: \d{4}-\d{2}-\d{2}$[\s\S]*Chapter & source\./m);
  assert.match(readFileSync(join(sources, 'fetched.txt'), 'utf8'), /^取得日: .*\nzenn\/01-idt-injection\.txt\nzenn\/02-second\.txt\noidc-core-1_0\.txt\n$/);
  const oidc = join(sources, 'oidc-core-1_0.txt');
  assert.match(readFileSync(oidc, 'utf8'), /https:\/\/openid.net\//);
  const quote = run('rfc-quote.mjs', [oidc, 'The client MUST']);
  assert.equal(quote.status, 0, quote.stderr);
  assert.equal(quote.stdout.trim(), 'The client MUST validate the fixture.');
  const rfc = run('rfc-quote.mjs', [join(installed, 'sources', 'rfc9700.txt'), 'This document']);
  assert.equal(rfc.status, 0, rfc.stderr);
  assert.match(rfc.stdout, /^This document/);
  const missing = run('rfc-quote.mjs', [oidc, 'Not in this fixture']);
  assert.equal(missing.status, 1);
  assert.match(missing.stdout, /NOT FOUND/);
  assert.deepEqual(snapshot(installed), before);
});

test('absolute output paths are supported', () => {
  const output = join(workspace, 'absolute-sources');
  const result = run('fetch-sources.mjs', [output]);
  assert.equal(result.status, 0, result.stderr);
  assert.match(readFileSync(join(output, 'oidc-core-1_0.txt'), 'utf8'), /MUST validate/);
});

test('HTTP failures are reported instead of being saved as source text', () => {
  const result = run('fetch-sources.mjs', ['failed-sources'], mockFetch(503));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /HTTP 503/);
});

for (const [label, url] of [
  ['a later chapter', 'https://zenn.dev/api/chapters/second'],
  ['OIDC Core', 'https://openid.net/specs/openid-connect-core-1_0.html'],
]) {
  test(`a failure on ${label} leaves no partial sources behind`, () => {
    const output = join(workspace, `partial-${label.replace(/\W/g, '')}`);
    const result = run('fetch-sources.mjs', [output], mockFetch(200, url));
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /HTTP 503/);
    assert.ok(!existsSync(output), 'nothing is written when any request fails');
  });
}

test('a failed refetch keeps the previous sources and fetched.txt unchanged', () => {
  const output = join(workspace, 'refetch-failed');
  assert.equal(run('fetch-sources.mjs', [output]).status, 0);
  const before = snapshot(output);
  const result = run('fetch-sources.mjs', [output], mockFetch(200, 'https://zenn.dev/api/chapters/second'));
  assert.notEqual(result.status, 0);
  assert.deepEqual(snapshot(output), before);
});

test('a write failure during refetch leaves no completion marker', () => {
  const output = join(workspace, 'refetch-write-failed');
  assert.equal(run('fetch-sources.mjs', [output]).status, 0);
  assert.ok(existsSync(join(output, 'fetched.txt')));
  const mock = `
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
const write = fs.writeFileSync;
fs.writeFileSync = (file, ...args) => {
  if (String(file).endsWith('/zenn/02-second.txt')) {
    throw Object.assign(new Error('simulated disk full'), { code: 'ENOSPC' });
  }
  return write(file, ...args);
};
syncBuiltinESMExports();
${mockFetch()}`;
  const result = run('fetch-sources.mjs', [output], mock);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /ENOSPC/);
  assert.ok(existsSync(join(output, 'zenn', '01-idt-injection.txt')));
  assert.ok(!existsSync(join(output, 'fetched.txt')));
});

test('a successful refetch drops stale chapters and rewrites fetched.txt', () => {
  const output = join(workspace, 'refetch-stale');
  mkdirSync(join(output, 'zenn'), { recursive: true });
  writeFileSync(join(output, 'zenn', '99-removed.txt'), 'old chapter');
  writeFileSync(join(output, 'fetched.txt'), '取得日: 2000-01-01\nzenn/99-removed.txt\n');
  assert.equal(run('fetch-sources.mjs', [output]).status, 0);
  assert.deepEqual(readdirSync(join(output, 'zenn')).sort(), ['01-idt-injection.txt', '02-second.txt']);
  const fetched = readFileSync(join(output, 'fetched.txt'), 'utf8');
  assert.doesNotMatch(fetched, /2000-01-01|99-removed/);
  assert.match(fetched, /\nzenn\/02-second\.txt\noidc-core-1_0\.txt\n$/);
});

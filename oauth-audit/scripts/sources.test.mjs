import assert from 'node:assert/strict';
import { test } from 'node:test';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, readdirSync } from 'node:fs';
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

const mockFetch = (status = 200) => `
globalThis.fetch = async (url) => {
  if (${status} !== 200) return new Response('unavailable', { status: ${status} });
  if (url === 'https://zenn.dev/api/books/oauth-attacks-and-bcp?username=hidebike712') {
    return Response.json({ book: { chapters: [{ id: 'fixture', slug: 'id-token-injection' }] } });
  }
  if (url === 'https://zenn.dev/api/chapters/fixture') {
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

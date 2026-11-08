import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync, statSync } from 'node:fs';

const skill = new URL('../', import.meta.url);

test('the skill has valid identifying frontmatter', () => {
  const text = readFileSync(new URL('SKILL.md', skill), 'utf8');
  const frontmatter = /^---\n([\s\S]*?)\n---\n/.exec(text)?.[1];
  assert.ok(frontmatter, 'SKILL.md must start with YAML frontmatter');
  const field = (name) => new RegExp(`^${name}: (.+)$`, 'm').exec(frontmatter)?.[1];
  assert.equal(field('name'), 'oauth-audit');
  assert.ok(field('description')?.length <= 1024);
  assert.ok(field('description')?.length > 0);
  assert.equal(field('license'), 'MIT');
  assert.ok(field('compatibility')?.length <= 500);
});

test('the standalone skill contains its runtime files', () => {
  for (const path of [
    'README.md', 'LICENSE', 'checklist-as.md', 'checklist-rp.md', 'report-template.md',
    'scripts/fetch-sources.mjs', 'scripts/rfc-quote.mjs', 'sources/README.md',
    'sources/rfc6749.txt', 'sources/rfc7636.txt', 'sources/rfc8252.txt',
    'sources/rfc9207.txt', 'sources/rfc9700.txt', 'sources/rfc10017.txt',
    'tools/go.mod', 'tools/fakeidp/main.go', 'tools/auditcheck/main.go',
  ]) {
    assert.ok(statSync(new URL(path, skill)).isFile(), path);
  }
});

// スキルを単体で導入しても許諾文が付くよう、各スキルは LICENSE を同梱する。
// 単体の導入先にはルートの LICENSE が無いので、この比較はリポジトリ側で行う。
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('oauth-audit/LICENSE matches the root LICENSE', () => {
  const root = read('LICENSE').replace('oauth-audit/sources/', 'sources/');
  assert.equal(read('oauth-audit/LICENSE'), root);
});

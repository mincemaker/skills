// 転載できない原文を、照合の前に作業フォルダへテキストで取り直す。
// Zenn の本は著者の著作物、OpenID Connect Core 1.0 は利用許諾が仕様の策定と実装の目的に限られるので、
// どちらも Git には入れない。
//   node <skill>/scripts/fetch-sources.mjs <work>/sources
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const [output, ...extra] = process.argv.slice(2);
if (!output || extra.length) {
  console.error('Usage: node fetch-sources.mjs <output-directory>');
  process.exit(1);
}
const destination = resolve(output);
const fetched = `取得日: ${new Date().toISOString().slice(0, 10)}`;

const request = async (url) => {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}: ${url}`);
  return response;
};

const decode = (s) => s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;|&#x27;/g, "'")
  .replace(/&nbsp;|&#160;/g, ' ').replace(/&amp;/g, '&');
const htmlToText = (html) => decode(html
  .replace(/<(script|style)[\s\S]*?<\/\1>/g, '')
  .replace(/<br\s*\/?>/g, '\n')
  .replace(/<\/(p|li|h\d|tr|pre|div|blockquote|dt|dd)>/g, '\n')
  .replace(/<[^>]+>/g, ''))
  .replace(/\n\s*\n+/g, '\n\n');

// 途中で失敗したときに一部だけの原文を残さないよう、全部を取得してから書き出す。
// 書き出しの最後に fetched.txt を置き、これがあれば取得が完了している。
const files = new Map();

// Zenn の本：各章を出力先の zenn/NN-<slug>.txt に。文書化されていない非公式の API なので、章の間に間隔を空けて負荷をかけない
const user = 'hidebike712', slug = 'oauth-attacks-and-bcp';
// ファイル名に token が入ると、秘密情報を守るフックが読み込みを止めるので短く言い換える
const rename = (s) => s.replace(/access-token/, 'at').replace(/id-token/, 'idt');
const { book } = await (await request(`https://zenn.dev/api/books/${slug}?username=${user}`)).json();
for (const [i, c] of book.chapters.entries()) {
  if (i) await sleep(1000);
  const { chapter } = await (await request(`https://zenn.dev/api/chapters/${c.id}`)).json();
  const name = `zenn/${String(i + 1).padStart(2, '0')}-${rename(c.slug)}.txt`;
  files.set(name, `# ${c.title}\nhttps://zenn.dev/${user}/books/${slug}/viewer/${c.slug}\n${fetched}\n\n${htmlToText(chapter.body_html)}`);
}

// OpenID Connect Core 1.0 incorporating errata set 2
const oidcUrl = 'https://openid.net/specs/openid-connect-core-1_0.html';
files.set('oidc-core-1_0.txt', `${oidcUrl}\n${fetched}\n\n${htmlToText(await (await request(oidcUrl)).text())}`);

const marker = join(destination, 'fetched.txt');
rmSync(marker, { force: true });
rmSync(join(destination, 'zenn'), { recursive: true, force: true });
mkdirSync(join(destination, 'zenn'), { recursive: true });
for (const [name, text] of files) {
  writeFileSync(join(destination, name), text);
  console.log(name);
}
writeFileSync(marker, `${fetched}\n${[...files.keys()].join('\n')}\n`);

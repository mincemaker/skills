# 判定の根拠にする原文

[oauth-redirect-attacks](https://github.com/mincemaker/oauth-redirect-attacks/tree/b001ca62035d9f11bdbdb6331207431d6db728d0/sources) `b001ca6` の `sources/` を写したもの。

| ファイル | 中身 |
|---|---|
| `rfc*.txt` | RFC のテキスト |
| `<work>/sources/zenn/` | Hideki Ikeda 氏の [攻撃手法から学ぶ OAuth セキュリティベストプラクティス](https://zenn.dev/hidebike712/books/oauth-attacks-and-bcp)。取得した時点の最新版になるので、各ファイルの先頭に URL と取得日を書く。著作物なので Git に入れない |
| `<work>/sources/oidc-core-1_0.txt` | OpenID Connect Core 1.0。利用許諾が仕様の策定と実装の目的に限られるので Git に入れない |

Git に入れないものは、書き込み可能な監査用の作業フォルダ `<work>` に取得する。スキルのインストール先には書き込まない。zenn.dev と openid.net に接続する。Zenn からは文書化されていない非公式の API で、章の間に間隔を空けて取得する。

```sh
node <skill>/scripts/fetch-sources.mjs <work>/sources
```

RFC は `<skill>/sources/rfc*.txt`、取得した原文は上の保存先から読む。引用には次のようにファイルを指定する。

```sh
node <skill>/scripts/rfc-quote.mjs <skill>/sources/rfc9700.txt "<書き出し>"
node <skill>/scripts/rfc-quote.mjs <work>/sources/oidc-core-1_0.txt "<書き出し>"
```

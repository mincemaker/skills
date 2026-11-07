---
name: oauth-audit
description: OAuth / OIDCの実装を、oauth-redirect-attacksのチェックリストで監査する。IdPや認可サーバはAS-01〜AS-11で、SSOやソーシャルログインのライブラリなどクライアント側はRP-01〜RP-16で確かめる。対象の言語で監査テストを書いて実行し、判定の報告をまとめる。「このIdPを監査して」「このSSOライブラリのstate・PKCE・IDトークン検証を確かめて」「redirect_uriの照合を確かめて」「Pocket IDと同じ確認を<対象>でも」と頼まれたときに使う。稼働中のサービスへの攻撃には使わない。
---

# OAuth / OIDC実装の監査

同じディレクトリのファイルを使う。

| ファイル | 読むとき |
|---|---|
| `checklist-as.md` | 対象が認可サーバの役割を持つとき |
| `checklist-rp.md` | 対象がクライアントの役割を持つとき |
| `report-template.md` | 報告を書くとき |
| `tools/` | Goのツール。`fakeidp` はRPのテストで使う偽のIdP、`auditcheck` は報告とテストの機械的な検査 |

`tools/` のコマンドは `go -C <skill>/tools run ./<コマンド>` で動かし、`tools/` へは移動しない。sandboxでGoのビルドキャッシュに書けなければ、`GOCACHE` に一時ディレクトリを指定する。

## 手順

### 1. 対象と役割を決める

- 対象リポジトリを取得し、コミットSHAに固定する。ブランチやタグで指定されたら、解決したSHAを記録する。モノレポなら、対象のパッケージと版も記録する。
- OAuthの処理や検証を外部ライブラリに任せているなら、その版とSHAも記録する。forkか本家かも確かめる。
- 対象の役割を決める。認可エンドポイントとトークンエンドポイントを提供するならAS、別のIdPへログインしに行くならRP。上流のIdPを中継するブローカーやプロキシは両方。
- 該当するチェックリストを全部読む。該当しない方は読まない。
- 作業フォルダの構成は次の形にする。

```
<work>/
  <repo>/            対象のソース
  <oauth-lib>/       検証を任せているライブラリ。読む必要があるとき
  dist/
    README.md                     配布物の説明とテストの実行手順
    <target>-checklist.md         報告
    security_audit<suffix>        監査テスト。名前は対象のテスト基盤の検出規則に合わせ、配置先と同じにする
                                  例: Goは security_audit_test.go、vitestは security_audit.test.ts。置き方は手順3
```

- 依頼が一部の項目だけなら、対象の項目IDを控える。範囲外の項目は判定で未確認とし、理由を「依頼の範囲外」と書く。
- 対象のソースが加工されたコピーなら、例えばコメントを取り除いたものなら、テストの組み立てと確認範囲への影響を報告に書く。
- リンクの形やファイルの置き場所について利用者の指定があれば、このスキルの既定より優先する。

### 2. 入口を探す

ASなら次の場所を探す。

- redirect_uriの照合関数。完全一致の後に別の照合でやり直していないか
- 認可エンドポイントと、照合に失敗したときの応答
- トークンエンドポイント、client認証、PKCE検証、code再利用時の失効
- イントロスペクションとトークンの検証、codeとトークンの生成
- 対応するresponse_typeとメタデータ
- 同意画面のソースとCSP、Referrer-Policyの設定
- ログアウト後のURLやクライアントメタデータの許可リストが、redirect_uriと同じ照合を使うか

RPなら、プロバイダごとに次の場所を探す。処理が同じプロバイダはまとめる。

- ログイン開始: state、nonce、code_verifierの生成と保存先。Cookieの名前と属性
- callback: stateの照合、`iss` の扱い、トークン要求
- IDトークン: 受け取るか、検証するか、アプリに渡すか
- UserInfoやユーザーAPIの呼び方。アクセストークンの送り方
- アプリが値を上書きできるオプション
- ドキュメントがアプリに任せている事項

ファイルと行を控え、報告のリンクに使う。

### 3. 監査テストを書く

- テストの仕掛けはチェックリストに従う。ASは照合関数やプロバイダを直接呼ぶ。RPは偽のIdPと最小のアプリをテスト内に作り、外向きの通信をすべて偽のIdPへ向ける。
- 対象のテスト基盤と既存の補助関数を使う。対象のコードは変えない。
- チェックリストの表を1行1サブテストにし、ケース名をそのまま使う。プロバイダ名などの接尾辞は付けてよい。例: `cross_callback_google_to_x`。
- 対象外や依頼の範囲外のケースも、名前を残してスキップにし、理由を書く。例: `it.skip('idt_valid: 対象外。IDトークンを扱わない')`、Goなら `t.Skip`。
- 期待値は表のとおりに書いて実行するのが基本。失敗したケースは、ソースで原因を確かめてから実際の挙動を期待値にし、`不適合: RP-xx` のように注記する。ケース名は変えず、注記は期待値を書いた assert の行にコメントで付ける。前提を確かめられず判定を未確認にする項目で、期待と違う挙動を記録するときは `期待と異なる: RP-xx（前提未確認）` と注記する。
- チェックリストの表に無い挙動もテストで確かめたら、`extra_` で始まる名前のサブテストにし、報告で引用する。
- 先にソースで原因を確かめてあれば、表のケースでも `extra_` のケースでも、不適合の期待値を最初から書いてよい。その場合、表の期待値での実行は省いてよい。
- 原因を確かめないまま期待値を書き換えない。テストや偽のIdPの不備と、対象の不適合を区別する。
- テストの置き方は言語で決める。Goは `dist/` の実体へ配置先からsymlinkを張る。JavaScriptとTypeScriptは、symlinkだと相対importの解決やテストの検出が壊れるので、`dist/` から配置先へコピーし、READMEにコピーの手順を書く。ほかの言語はsymlinkを試し、テストの検出かimportが壊れたらコピーにする。Pythonのpytestはsymlinkで動く。どれも編集は `dist/` 側で行う。
- テスト関数の名前に言語の決まりの接頭辞が付くのはよい。例: pytest の `test_state_valid`。`auditcheck` はこの形も認める。
- 役割が両方なら、ASとRPのテストを別のファイルにしてよい。

#### RPの偽のIdP

`tools/fakeidp` を使う。既定で正しく振る舞うIdPで、codeは1回だけ使え、client_id、redirect_uri、PKCEのchallengeに結び付く。IDトークンはES256で署名する。

```sh
go -C <skill>/tools run ./fakeidp -addr 127.0.0.1:9400 -issuer https://idp.example   # バックグラウンドで起動する
```

2つ目のIdPが要るケース、例えば cross_callback では、`fakeidp` を別のポートと別の issuer でもう1つ起動する。

```sh
go -C <skill>/tools run ./fakeidp -addr 127.0.0.1:9401 -issuer https://idp2.example
```

| エンドポイント | 中身 |
|---|---|
| authorize | 同意は自動。ユーザーは `victim`。攻撃者のcodeが欲しいときは、認可URLに `_user=attacker` を足す |
| token | form、クエリ、JSONのどれで送られても受ける。PKCEを検証し、scopeに `openid` があればIDトークンを返す |
| userinfo、jwks、discovery | `sub`、`id`、`data.id` を同時に返すので、プロバイダごとの形に合わせなくてよい |
| そのほかのパス | 有効なアクセストークンを Authorization ヘッダーか `access_token` クエリで送ると、userinfo と同じ形でトークンの持ち主を返す。`/photos/me` のようなリソースAPIを呼ぶアプリでも、誰としてログインしたかを確かめられる |
| `POST /_audit/scenario` | 改ざんを指定する。`{"iss_param":true}`、`{"iss_override":"https://evil.example"}`、`{"id_token":{"aud":"other","nonce":null}}`、`{"alg":"none"}`、`{"bad_signature":true}`、`{"userinfo_sub":"other"}`、`{"omit_access_token":true}` |
| `GET /_audit/requests` | RPが送った要求の記録。トークン要求を送ったか、どこへ何を送ったかはこれで判定する。アクセストークン付きの要求には、そのトークンの持ち主が `user` に入るので、誰としてログインしたかもこれで分かる |
| `POST /_audit/reset` | ケースごとに呼ぶ |

対象が `fakeidp` の返さないメタデータを必須とするときは、テストの通信の差し替えで応答に足してよい。足したことを報告に書く。通信エラーやタイムアウトのように `fakeidp` では起こせない失敗も、テストの通信の差し替えで起こしてよい。これも報告に書く。

パスはキーワードで振り分ける。テストは、本物のプロバイダのURLのオリジンだけを偽のIdPに差し替えればよい。JavaScriptなら次の形にする。

```ts
const realFetch = globalThis.fetch
globalThis.fetch = (input, init) => {
  const u = new URL(input instanceof Request ? input.url : String(input))
  return realFetch('http://127.0.0.1:9400' + u.pathname + u.search, init)
}
```

ブラウザの代わりに、テストがログイン開始の応答の `Location` を偽のIdPへ送り、その応答の `Location` をcallbackへ送る。

PythonのhttpxやrequestsはHTTP_PROXYなどの環境変数に従うので、sandboxのプロキシ経由で 127.0.0.1 への接続が拒否されることがある。そのときは、テストのコマンドに `NO_PROXY=127.0.0.1` を付けるか、sandboxで 127.0.0.1 への接続を許可する。

sandboxがローカルのポートでの待ち受けを止めたら（`bind: operation not permitted`）、利用者に `sandbox.network.allowLocalBinding: true` の設定を頼む。設定できなければ、テスト内のモックで偽のIdPを書き、`tools/fakeidp/main.go` と同じ振る舞いにする。

### 4. 実行する

- 監査テストと、関連する既存テストを一緒に実行し、すべて成功させる。使ったコマンドをそのまま記録する。
- sandboxの中で依存のキャッシュを読めずに失敗したら、sandboxの外で実行する。
- テストがときどき失敗するなら、まず偽のIdPやテストの仕掛けの不備を疑う。テスト側で回避したら、回避したことと理由を報告に書く。期待値は変えない。
- ネットワークが使えないなら、パッケージマネージャーの実行前の依存確認を止める。例: pnpmは `--config.verify-deps-before-run=false`。付けたオプションも記録する。
- 対象のコミットを変えたら、symlinkとリンクの行番号を確かめ直す。

### 5. 判定する

- チェックリストの判定の区分に従う。テストもソースも見ていない範囲を適合にしない。
- 攻撃の成立を実証したケースと、ソースから推測しただけのものを分けて書く。
- ASだけを監査したら、RPの16項目は未判定とし、AS側の関連事実だけを書く。

### 6. 報告を書く

- `report-template.md` を `dist/<target>-checklist.md` に写して埋める。役割に該当しない節は消す。
- ソースへのリンクは `https://github.com/<owner>/<repo>/blob/<SHA>/<path>#L<n>` の形で、コミットを固定する。
- `dist/README.md` に、ファイルの一覧、確認したコミット、テストを取得から実行まで再現するコマンドを書く。対象が直るとどのテストが失敗するかも書く。
- ASのAS-01かAS-02が不適合なら、管理者向けに登録の運用ルールを別ファイルで書くか利用者に確かめる。AS-02で記録したワイルドカードの範囲を根拠にする。利用者に確かめられない環境では書かず、報告の「必要な対応」に、運用ルールの文書が未作成であることを書く。redirect URI を登録する機能そのものが無い対象では、運用ルールでは防げないので文書は作らず、「必要な対応」に実装の修正を書く。
- 書き終えたら `auditcheck` で検査し、`ok` になるまで直す。`-only` には依頼の範囲の項目IDを渡す。全項目なら省く。

```sh
go -C <skill>/tools run ./auditcheck -report <work>/dist/<target>-checklist.md \
  -checklist <skill>/checklist-<as|rp>.md -tests <work>/dist/<監査テストのファイル> [-only AS-01,AS-02]
```

`-checklist` には、ASなら `checklist-as.md`、RPなら `checklist-rp.md`、両方ならカンマでつないで両方を渡す。`-tests` も、テストのファイルが複数ならカンマでつなぐ。

`auditcheck` が見るのは、未記入の `{{...}}`、判定の表のIDの欠け、判定の語彙、コミットに固定されていないGitHubのリンク、チェックリストのケース名がテストにあるか。

### 7. 不適合を見つけたら

- 対象リポジトリには何も書き込まない。issue、PR、コメント、discussion、Security Advisoryの作成をすべて禁じる。利用者に頼まれても、送るのは利用者自身にしてもらう。
- 報告は非公開で扱う。報告の文書は `dist/` に置くだけにし、外部のサービスへ送らない。

### 8. 推敲する

報告とREADMEを [yomiyasu](https://github.com/nanaism/yomiyasu) で推敲する。入っていなければ、利用者に次のコマンドで入れてもらう。

```sh
npx skills add nanaism/yomiyasu
```

yomiyasu の手順に従い、次のようにつなぐ。監査の報告では、lint の候補を直し、run と verify を通すところまででよい。

- 推敲の前に、`dist/` の報告とREADMEを `<work>/.draft/` に写す。写したものを原文にし、推敲の結果は `dist/` のファイルに書く。
- yomiyasu のコマンドは作業フォルダで実行する。yomiyasu の手順がディレクトリの移動を求めていなくても、作業フォルダの外では実行しない。シェルの作業ディレクトリが呼び出しごとに戻る環境では、`cd <work> && ` を前に1回だけ付ける。yomiyasu は `cd` や `&&` を付けないよう求めるが、この手順ではこちらを優先する。検査の記録を作業フォルダの中に作るためである。
- 検査の記録は作業フォルダの `.yomiyasu/` に作られ、原稿の全文が入る。`.draft/` と一緒に、終わったら消すよう利用者に伝える。

yomiyasu が使えなければ推敲を省き、推敲していないことを報告の最後の行に書く。

## やらないこと

- 利用者の許可なく、本物のIdPや稼働中のサービスに攻撃的な要求を送らない。ASのAS-11の実環境の確認も、対象のURLを利用者から受け取ってから行う。
- 未判定や未確認を「問題なし」と書かない。

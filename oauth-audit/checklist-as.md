# OAuth / OIDC IdPの監査チェックリスト

[oauth-redirect-attacks](https://github.com/mincemaker/oauth-redirect-attacks/blob/b001ca62035d9f11bdbdb6331207431d6db728d0/README.md#7-チェックリスト) `b001ca6` の第7節を、IdPごとにテストを書ける形に整理したもの。AS・RPの番号は原文の掲載順。ケース名は監査テストのサブテスト名にそのまま使う。

## 判定の区分

| 判定 | 使う条件 |
|---|---|
| 適合 | その項目のケースがすべて期待どおり |
| 不適合 | 期待と違う挙動が1件以上ある |
| 未確認 | テストでもソースでも確かめられない範囲が残る。残った範囲を書く |
| 対象外 | 前提の機能が無い。例として、ワイルドカードを登録できないIdPのAS-02、public client を作れないIdPのAS-03、PKCE に対応していないIdPのAS-04とAS-05。理由を書く |
| 未判定 | RP側の項目。IdP単体では判定しない |

SHOULDを満たさない挙動や、IdPの外で効く穴は「残るリスク」として書き、判定は変えない。

「適合」は記載した確認範囲で項目を満たすという意味で、製品全体の安全性は保証しない。報告の結論にもこの一文を入れる。

## テストの共通ルール

- 対象のテスト基盤と既存の補助関数を使う。製品のコードは変えない。
- 期待値には実際の挙動を書く。不適合な挙動も成功するテストとして記録し、`不適合: AS-01` のような注記を付ける。IdPが直すとテストが失敗し、報告を見直す合図になる。
- 照合関数を直接呼べるならそれを使い、呼べなければ認可エンドポイントにHTTPで要求する。
- 認証と同意はテスト内で成立させる。ブラウザやpasskeyの操作は範囲外として報告に書く。
- 既定の登録URLは `https://app.example/callback`、攻撃者のホストは `attacker.example`。表で登録欄が空のケースは既定の登録URLを使う。

## AS-01: 登録URLと異なる転送先を拒否する

基準: ループバックIPのポート違いを除き、redirect_uriを登録URLと文字列で完全一致させる。RFC 9700 §2.1。

| ケース | 登録 | 要求 | 期待 |
|---|---|---|---|
| exact | | `https://app.example/callback` | 受理 |
| host_suffix | | `https://app.example.evil.test/callback` | 拒否 |
| subdomain | | `https://evil.app.example/callback` | 拒否 |
| registered_in_query | | `https://attacker.example/?u=https://app.example/callback` | 拒否 |
| registered_in_path | | `https://attacker.example/https://app.example/callback` | 拒否 |
| host_as_userinfo | | `https://app.example@attacker.example/callback` | 拒否 |
| userinfo_added | | `https://attacker.example@app.example/callback` | 拒否 |
| dot_segment_escape | | `https://app.example/callback/../logout` | 拒否 |
| path_dot_segment | | `https://app.example/x/../callback` | 拒否 |
| encoded_dot_segment | | `https://app.example/x/%2e%2e/callback` | 拒否 |
| different_path | | `https://app.example/logout` | 拒否 |
| trailing_slash | | `https://app.example/callback/` | 拒否 |
| extra_query | | `https://app.example/callback?next=x` | 拒否 |
| host_case | | `https://APP.EXAMPLE/callback` | 拒否 |
| scheme_case | | `HTTPS://app.example/callback` | 拒否 |
| default_port | | `https://app.example:443/callback` | 拒否 |
| query_order | `https://app.example/callback?a=1&b=2` | `https://app.example/callback?b=2&a=1` | 拒否 |
| query_encoding | `https://app.example/callback?a=A` | `https://app.example/callback?a=%41` | 拒否 |
| mismatch_stops | | `https://attacker.example/callback` | エラー画面で止まり、要求したURLへ転送しない |

判定: 期待が拒否のケースで、受理が1件でもあれば不適合。報告では受理された例を二つに分ける。

redirect URI を登録する機能そのものが無く、どのURLも受理する対象では、登録欄を無視して表の要求だけを送ってテストする。AS-01 は不適合、AS-02 は対象外とする。

- ブラウザ上で登録URLと同じ場所に解決される別表記。大文字、既定ポート、ドットセグメント、クエリ順など。
- 別ホストや登録範囲外のパスに届くもの。こちらがあれば影響は大きい。

受理したURLを正規化してから転送するのか、要求のまま転送するのかもソースで確かめて書く。

## AS-02: ワイルドカードでホストやパスをまたがせない

前提: 登録URLにワイルドカードやパターンを書ける。書けなければ対象外。

| ケース | 登録 | 要求 | 期待 |
|---|---|---|---|
| wildcard_host_slash | `https://*.app.example/callback` | `https://attacker.example/.app.example/callback` | 拒否 |
| wildcard_host_question | `https://*.app.example/callback` | `https://attacker.example?.app.example/callback` | 拒否 |
| wildcard_host_hash | `https://*.app.example/callback` | `https://attacker.example#.app.example/callback` | 拒否 |
| wildcard_host_backslash | `https://*.app.example/callback` | `https://attacker.example\.app.example/callback` | 拒否 |
| wildcard_host_encoded_slash | `https://*.app.example/callback` | `https://attacker.example%2f.app.example/callback` | 拒否 |
| wildcard_path_dot_escape | `https://app.example/cb/*` | `https://app.example/cb/x/../../logout` | 拒否 |
| query_wildcard_external_url | `https://app.example/callback?next=*` | `https://app.example/callback?next=https://attacker.example` | 拒否 |

ワイルドカードが許す範囲も記録する。判定には使わず、運用ルールの根拠にする。

| ケース | 登録 | 要求 | 記録すること |
|---|---|---|---|
| wildcard_subdomain | `https://*.app.example/callback` | `https://attacker.app.example/callback` | 受理するか |
| wildcard_multilevel_subdomain | `https://*.app.example/callback` | `https://a.b.app.example/callback` | 多段のサブドメインも通るか |
| global_wildcard | `*` | `https://attacker.example/collect` | 任意のURLを許すか |
| path_wildcard | `https://app.example/**` | `https://app.example/logout` | 同一ホストの全パスを許すか |
| query_glob | `https://app.example/callback?tenant=[ab]` | `https://app.example/callback?tenant=a` | `*` 以外のグロブ文字も効くか |

ログアウト後のURLやクライアントメタデータの許可リストが同じ照合を使うかも、ソースで確かめて書く。

## AS-03: ループバックIPのポート違いを認める

前提: public client を登録できる。RFC 8252 のネイティブアプリは secret を守れないので public client になる。対象のドキュメントか設定に public client の種類が無く、secret を空にするのが想定外の使い方なら、public client を作れないとみなして対象外とする。secret が空の client を作って試した挙動は記録する。対象外にしたときも表のケースは流して挙動を記録し、ポート違いを拒否するなら、ネイティブアプリとは連携できないという運用の注意として書く。拒否は厳しい側の挙動なので、セキュリティの不備としては書かない。

| ケース | 登録 | 要求 | 期待 |
|---|---|---|---|
| loopback_port | `http://127.0.0.1/callback` | `http://127.0.0.1:51004/callback` | 受理 |
| ipv6_loopback_port | `http://[::1]/callback` | `http://[::1]:5000/callback` | 受理 |
| loopback_path | `http://127.0.0.1/callback` | `http://127.0.0.1:51004/other` | 拒否 |
| localhost_port | `http://localhost/callback` | `http://localhost:5000/callback` | 記録のみ。受理しても拒否しても判定に使わない |

RFC 9700 §2.1 と §4.1.3 は、ネイティブアプリの `localhost` の redirect URI でもポート違いを完全一致の例外としている。`localhost_port` を受理しても不適合にしない。RFC 8252 §8.3 はクライアントに `localhost` ではなくループバックIPで登録するよう勧めているので、受理した場合は運用の注意として書く。

判定: loopback_port か ipv6_loopback_port が拒否されたら不適合。RFC 8252 §7.3 のMUST。loopback_path が受理されたら、AS-01の不適合として扱う。

## AS-04: PKCEのverifierの省略・改ざんを拒否する

前提: 対象が PKCE に対応している。AS-04 はトークンエンドポイントでの verifier の検証を、AS-05 は challenge を外させるダウングレードを、認可エンドポイントとトークンエンドポイントで確かめる。

PKCE に対応しているかは、次の順で判断する。

1. ソース: 認可リクエストの `code_challenge` を読んで保存する処理があれば、対応している。無ければ非対応の候補。
2. 挙動: 存在しない方式 `code_challenge_method=S999` を付けて認可を求める。拒否すれば、パラメータを解釈しているので対応している。受理すれば非対応の候補。ソースが読めない対象では、これで判断する。
3. discovery: `code_challenge_methods_supported` を載せていれば、対応していると表明しているものとして扱う。

1〜3 のどれか1つでも対応を示せば、対応している IdP として表どおりに判定する。表明しているのにパラメータを無視するなら、不適合のうち最も悪い形として書く。すべてが非対応を示したときだけ、AS-04 と AS-05 を対象外とする。RFC 7636 §5 は、対応していないサーバが `code_challenge` を無視することを互換の挙動としているので、ダウングレードの攻撃は成り立たない。

対象外にしたときも表のケースは流して挙動を記録し、判断に使った1〜3の結果を報告に書く。PKCE に対応していないこと自体は RFC 9700 §2.1.1 の MUST に反するので、「必要な対応」に書く。

S256のchallengeを付けて取ったcodeを交換する。RFC 7636 §4.6。

| ケース | 交換時のverifier | 期待 |
|---|---|---|
| valid | 正しい値 | 交換できる |
| missing_verifier | 省略 | 拒否 |
| wrong_verifier | 別の43文字 | 拒否 |

## AS-05: PKCEのchallengeの除去を防ぐ

PKCE に対応していない対象の扱いは、AS-04 の前提に従う。

| ケース | 手順 | 期待 |
|---|---|---|
| public_requires_challenge | public clientでchallengeなしの認可リクエスト | 拒否。受理されるなら次のケースで止まればよい |
| downgrade | challengeなしで取ったcodeを、verifier付きで交換 | 拒否 |
| plain_method | `code_challenge_method=plain` で認可と交換 | 記録のみ。受理するならRP-06の事実として書く |

判定: challengeなしの認可を受理し、さらにdowngradeの交換も通れば不適合。public clientとconfidential clientの両方で試す。対象が client の種類を区別しないなら、secret が空の client をテスト内で作って public client とし、作ったことを報告に書く。

## AS-06: codeの再利用を拒否し、発行済みトークンを失効させる

| ケース | 手順 | 期待 |
|---|---|---|
| reuse | 同じcodeで2回交換 | 2回目は `invalid_grant`。RFC 6749 §4.1.2 のMUST |
| reuse_revokes_access | 2回目の後に、1回目のアクセストークンをIdP自身の検証かイントロスペクションで確かめる | 無効。SHOULD |
| reuse_revokes_refresh | 1回目でリフレッシュトークンが出ていれば、2回目の後に使う | 拒否。SHOULD |

判定: 2回目を受理したら不適合。失効しなければ残るリスク。アクセストークンが自己完結型のJWTなら、署名だけで検証するリソースサーバは失効後も有効期限まで受け入れるので、既定の有効期限と合わせて残るリスクに書く。

## AS-07: codeを別clientや別redirect_uriで交換させない

| ケース | 交換時の変更 | 期待 |
|---|---|---|
| wrong_client | 別の登録済み `client_id` | 拒否 |
| wrong_redirect | 認可リクエストと違う `redirect_uri` | 拒否 |
| missing_redirect | 認可リクエストに含めた `redirect_uri` を省略 | 拒否 |

## AS-08: secretを持つclientに認証を求める

| ケース | 交換時の認証 | 期待 |
|---|---|---|
| confidential_auth_missing | 省略 | `invalid_client` |
| confidential_auth_wrong | 誤ったsecret | `invalid_client` |

メタデータの `token_endpoint_auth_methods_supported` にある方式をすべて試すか、試していない方式を範囲外として書く。

## AS-09: code・トークンを推測や偽造から守る

ソースで確かめる。

- codeの生成に暗号学的乱数を使い、128ビット以上あるか。
- アクセストークンは乱数か署名付きか。署名なら鍵の生成と保管場所。

リンクはコミットを固定したパーマリンクで書く。推測できそうなら、トークンエンドポイントでの総当たりが止まるかを試す。試さなければ「負荷試験は未実施」と書く。

## AS-10: response_typeの変更でアクセストークンを漏らさない

`response_type=code` だけを登録したclientで、次の値を要求する。

| ケース | response_type | 期待 |
|---|---|---|
| token | `token` | 拒否 |
| id_token_token | `id_token token` | 拒否 |
| code_token | `code token` | 拒否 |
| code_id_token | `code id_token` | 拒否 |
| code_id_token_token | `code id_token token` | 拒否 |

IdPがImplicitやハイブリッドに対応しているなら、登録で許したclientだけが通ることも確かめる。

## AS-11: 同意画面からRefererや外部リソース経由で漏らさない

ソースで確かめる。

- Referrer-Policyの指定。ヘッダー、meta、要素の属性のどれにも既定より緩い値が無いか。
- 同意画面の外部リンクと外部リソース。CSPで外部を許していればそれも書く。
- 同意画面のURLにcodeやトークンが入らないか。

実環境で確かめる。

```sh
curl -sI '<同意画面のURL>' | grep -i -E 'referrer-policy|content-security-policy'
```

ブラウザの開発者ツールか agent-browser で、同意画面が行う外部への通信を見る。実環境を見ていなければ未確認とする。

## RP側の判定に使う事実

RPの項目の判定には使わないが、連携アプリを調べる人のためにテストで確かめて書く。

| ケース | 確かめること | 関連 |
|---|---|---|
| issuer_parameter | 認可レスポンスに `iss` が入るか。メタデータの `authorization_response_iss_parameter_supported` | RP-13、RP-14、RFC 9207 |
| state_echo | `state` をそのまま返すか | RP-02 |
| pkce_methods | 受け付ける `code_challenge_method` | RP-06 |
| response_types | 受け付けるresponse_type | RP-12、RP-16 |

## RP側の項目

連携アプリの責任で、そのアプリを調べないと判定できない。IdPの監査ではすべて未判定とし、IdP側の関連事実だけを書く。未判定は安全を確認したという意味ではない。

| ID | 確認項目 | 確認する場所 |
|---|---|---|
| RP-01 | 他人のcodeによるログイン・アカウント連携を防ぐ | callbackとアカウント紐付け |
| RP-02 | stateの欠落・改ざん・別セッションの値を検出する | stateとセッションの照合 |
| RP-03 | ログイン開始時のセッション固定を防ぐ | セッションIDの発行・更新 |
| RP-04 | state・nonce・verifierをフローごとに生成する | これらの値の生成と保存 |
| RP-05 | 別ブラウザのcodeを注入されても他人にならない | 二つのブラウザセッションでの試験 |
| RP-06 | public clientがPKCEを使い、方式をS256にする | 送信するパラメータ |
| RP-07 | nonceの照合が済むまでトークンを使わない | IDトークン受信後の処理 |
| RP-08 | IDトークンのiss・aud・exp・nonceを検証する | IDトークンの検証 |
| RP-09 | IDトークンの受信経路に応じて署名を検証する | 署名検証を省く条件 |
| RP-10 | UserInfoとIDトークンのsubを照合する | 二つの応答の照合 |
| RP-11 | callbackのページやログからcodeを漏らさない | ページ、ヘッダー、外部スクリプト、ログ |
| RP-12 | アクセストークンをURLのクエリに載せない | トークンの使い方 |
| RP-13 | 複数IdPを使う場合にmix-up攻撃を防ぐ | IdPの識別方法 |
| RP-14 | issの改ざん・削除をトークン送信前に検出する | codeを送る前のiss検証 |
| RP-15 | 別IdP用のcallbackに届いた応答を拒否する | IdPごとのcallbackの処理 |
| RP-16 | Implicit Grantを使わず、使う場合はトークン差し替えを防ぐ | 選ぶフローと検証 |

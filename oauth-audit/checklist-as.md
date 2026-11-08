# OAuth / OIDC IdPの監査チェックリスト

[oauth-redirect-attacks](https://github.com/mincemaker/oauth-redirect-attacks/blob/b001ca62035d9f11bdbdb6331207431d6db728d0/README.md#7-チェックリスト) `b001ca6` の第7節を、IdPごとにテストを書ける形に整理したもの。AS・RPの番号は原文の掲載順。ケース名は監査テストのサブテスト名にそのまま使う。

各項目には、守りたいものと、それを破る攻撃の出典を書いた。攻撃の手順と前提は、`sources/zenn/` の章と原文の README の節にある。判定と出し方は SKILL.md の「5. 判定する」に従う。

## 判定の区分

| 判定 | 使う条件 |
|---|---|
| 適合 | 守りたいものを破る攻撃が、確かめた範囲で成り立たない |
| 不適合 | 攻撃が成り立つ。テストで攻撃を再現したか、攻撃の決め手になる1歩を示した |
| 未確認 | テストでもソースでも確かめられない範囲が残る。残った範囲を書く |
| 対象外 | 攻撃の前提になる機能が無く、攻撃を組めない。理由を書く |
| 未判定 | RP側の項目。IdP単体では判定しない |

表のケースは攻撃を確かめる代表例で、すべてを尽くしてはいない。表に無い `extra_` のケースで攻撃が成り立つことを示したら、その項目を不適合とする。

## テストの共通ルール

- 対象のテスト基盤と既存の補助関数を使う。製品のコードは変えない。
- 照合関数を直接呼べるならそれを使い、呼べなければ認可エンドポイントにHTTPで要求する。
- 認証と同意はテスト内で成立させる。ブラウザやpasskeyの操作は範囲外として報告に書く。
- 既定の登録URLは `https://app.example/callback`、攻撃者のホストは `attacker.example`。表で登録欄が空のケースは既定の登録URLを使う。
- トークンエンドポイントのケースは、正常な要求から値を1つだけ変え、ケースごとに未使用の code を用意する。正常な交換を確かめた code はそれで使用済みになる。使用済み、期限切れ、client 認証の失敗で拒否されても、確かめたい検証が効いた証拠にはならない。拒否されたら、どの検証で拒否されたかをエラーかソースで確かめる。

## AS-01: 登録URLと異なる転送先を拒否する

守りたいもの: code が登録外の URL に届かないこと。照合が緩いと、攻撃者が用意した URL や登録外のページに code が届く。攻撃は `sources/zenn/02-insufficient-redirect-uri-validation.txt` と原文の README の第2節。

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
| mismatch_with_invalid_param | | `https://attacker.example/callback` に、不正な response_type か scope を付ける | エラー画面で止まり、要求したURLへ転送しない。転送したら「照合前の転送」を見る |
| response_mode_fragment | | 正しい redirect_uri に `response_mode=fragment` を付ける | 記録する。受け付けるか |

判定: 受理した要求で、code がブラウザ上で登録URLと別の場所、つまり別ホストや登録範囲外のパスに届けば不適合。転送先は、ブラウザが実際にたどり着く場所で比べる。Location を URL として解析し、ホスト、userinfo、パスを要求と比べる。スキームやホストの大文字と小文字、クエリの順序とエンコードは、AS が書き換えることがあるので、届く先の判断には使わない。

登録URLと同じ場所に解決される別表記、例えば大文字、既定ポート、ドットセグメントで戻る形、クエリの順序やエンコードだけを受理するなら、code は登録外に届かないので不適合にしない。照合が完全一致でないことは、RFC 9700 §2.1 の完全一致の MUST に反するので info に出す。ワイルドカードやパターンを登録すると届く範囲が広がるので、AS-02 で記録した範囲と合わせて残るリスクにも書く。受理したURLを正規化してから転送するのか、要求のまま転送するのかもソースで確かめて書く。

`response_mode=fragment` を受け付ける AS では、登録URLのページがオープンリダイレクタだと、code がフラグメントに載って攻撃者のサイトまで運ばれる。原文の README の第2節と RFC 9700 §4.1.2。AS の判定には使わず、連携するクライアントが調べるべき事実として書く。

redirect URI を登録する機能そのものが無く、どのURLも受理する対象では、登録欄を無視して表の要求だけを送ってテストする。code が攻撃者のURLに届くので AS-01 は不適合、AS-02 は対象外とする。

### 照合前の転送

エラーの経路で、照合する前の redirect_uri へ転送する実装がある。実装が redirect_uri より先にほかのパラメータを調べると、その途中のエラーで、要求に書かれたままの redirect_uri にエラーを付けて返してしまう。code は載らないので AS-01 の判定には使わない。ただし AS がオープンリダイレクタになり、利用者を任意の URL へ飛ばせる。RFC 9700 §4.11.2 の攻撃に当たるので、チェックリスト外の脆弱性として報告する。RFC 6749 §4.1.2.1 の MUST NOT にも反するので、info にも出す。ソースのエラー処理で照合しないまま転送する経路が無いかをたどり、見つけたら `extra_` のケースで示す。

## AS-02: ワイルドカードでホストやパスをまたがせない

守りたいもの: ワイルドカードの登録から、別ホストや登録範囲外のパスに code が届かないこと。攻撃は `sources/zenn/02-insufficient-redirect-uri-validation.txt` の、`*` が `/` にも一致する照合の例。

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

ワイルドカードが許す範囲も記録する。判定には使わず、残るリスクと運用ルールの根拠にする。ワイルドカードの登録を許すこと自体は、RFC 9700 §2.1 の完全一致の MUST に反するので info に出す。

| ケース | 登録 | 要求 | 記録すること |
|---|---|---|---|
| wildcard_subdomain | `https://*.app.example/callback` | `https://attacker.app.example/callback` | 受理するか |
| wildcard_multilevel_subdomain | `https://*.app.example/callback` | `https://a.b.app.example/callback` | 多段のサブドメインも通るか |
| global_wildcard | `*` | `https://attacker.example/collect` | 任意のURLを許すか |
| path_wildcard | `https://app.example/**` | `https://app.example/logout` | 同一ホストの全パスを許すか |
| query_glob | `https://app.example/callback?tenant=[ab]` | `https://app.example/callback?tenant=a` | `*` 以外のグロブ文字も効くか |

ログアウト後のURLやクライアントメタデータの許可リストが同じ照合を使うかも、ソースで確かめて書く。

## AS-03: ループバックIPのポート違いを認める

この項目は攻撃を探すものではない。ネイティブアプリのループバックIPの redirect URI でポートだけが違う要求を受理するのは正しく、それを不備と誤報しないための項目。原文の README の第2節。

| ケース | 登録 | 要求 | 期待 |
|---|---|---|---|
| loopback_port | `http://127.0.0.1/callback` | `http://127.0.0.1:51004/callback` | 受理 |
| ipv6_loopback_port | `http://[::1]/callback` | `http://[::1]:5000/callback` | 受理 |
| loopback_path | `http://127.0.0.1/callback` | `http://127.0.0.1:51004/other` | 拒否 |
| localhost_port | `http://localhost/callback` | `http://localhost:5000/callback` | 記録する |

判定: ポート違いを受理しても拒否しても適合。拒否は厳しい側の挙動で、攻撃は成り立たない。ただし RFC 8252 §7.3 の「MUST allow any port」に反し、ポートを動的に選ぶネイティブアプリと連携できないので、info に出す。loopback_path を受理したら、AS-01 で code の届く先として判定する。

`localhost` のポート違いは、RFC 9700 §2.1 と §4.1.3 がネイティブアプリの例外としているので、受理しても info にしない。RFC 8252 §8.3 はクライアントに `localhost` ではなくループバックIPで登録するよう勧めているので、受理した場合は運用の注意として書く。

## AS-04: PKCEのverifierの省略・改ざんを拒否する

守りたいもの: 盗まれた code を、フローを始めたクライアントのセッションにある verifier なしで使わせないこと。AS が PKCE を検証しないと、認可コードの注入が通り、public client では漏れた code がそのままアクセストークンになる。攻撃は `sources/zenn/05-authorization-code-injection.txt` と原文の README の第3節。

前提: AS が PKCE に対応している。対応していなければ、PKCE で守る仕組みそのものが無いので対象外とする。対応していないこと自体は RFC 9700 §2.1.1 の「Authorization servers MUST support PKCE」に反するので info に出す。連携するクライアントは注入を PKCE で防げず、confidential な OIDC クライアントなら nonce で防ぐことになる。public client を連携させるなら漏れた code がそのまま使われる。これを RP 側の事実として書く。

対応していないのに検証が抜けていると取り違えないように注意する。どちらも「verifier なしで交換できる」という同じ挙動になる。取り違えて見逃すほうが害が大きいので、対応していることを示すものが1つでもあれば、対応しているものとして判定する。手がかりは、ソースで `code_challenge` を読んで保存しているか、知らない `code_challenge_method` を拒否するか、discovery が `code_challenge_methods_supported` を載せているか。対応していない AS がパラメータを無視するのは、RFC 6749 §3.1 の「The authorization server MUST ignore unrecognized request parameters」に沿った挙動。どちらと判断したかと根拠を報告に書く。

S256のchallengeを付けて取ったcodeを交換する。RFC 7636 §4.6。

| ケース | 交換時のverifier | 期待 |
|---|---|---|
| valid | 正しい値 | 交換できる |
| missing_verifier | 省略 | 拒否 |
| wrong_verifier | 別の43文字 | 拒否 |

## AS-05: PKCEのchallengeの除去を防ぐ

守りたいもの: CSRF の対策を PKCE だけに頼るクライアントで、challenge を外して取った攻撃者の code を被害者に踏ませても、ログインが成立しないこと。攻撃は `sources/zenn/08-pkce-downgrade-attack.txt` と原文の README の第4節。

前提: AS が PKCE に対応している。8章は、この攻撃が成り立つ条件を「認可サーバーが PKCE (RFC 7636) をサポートしており」としている。対応していない AS では対象外とし、扱いは AS-04 と同じ。

| ケース | 手順 | 期待 |
|---|---|---|
| public_requires_challenge | public clientでchallengeなしの認可リクエスト | 拒否。受理されるなら次のケースで止まればよい |
| downgrade | challengeなしで取ったcodeを、verifier付きで交換 | 拒否 |
| plain_method | `code_challenge_method=plain` で認可と交換 | 記録する。受理するならRP-06の事実として書く |

判定: challengeなしの認可を受理し、さらにdowngradeの交換も通れば不適合。public clientとconfidential clientの両方で試す。対象が client の種類を区別しないなら、secret が空の client をテスト内で作って public client とし、作ったことを報告に書く。不適合なら、連携するクライアントが state を照合していれば攻撃は止まるので、そのことも書く。

`plain` を受け付けることは info にしない。RFC 9700 §2.1.1 の S256 の規則はクライアントへの SHOULD で、AS への規則ではない。

## AS-06: codeの再利用を拒否し、発行済みトークンを失効させる

守りたいもの: 漏れた code を使わせないこと。攻撃者が先に交換した場合でも、正規のクライアントの2回目の交換で、攻撃者のトークンを止められること。原文の README の第4節。

| ケース | 手順 | 期待 |
|---|---|---|
| reuse | 同じcodeで2回交換 | 2回目は `invalid_grant` |
| reuse_revokes_access | 2回目の後に、1回目のアクセストークンで API を呼ぶか、IdP自身の検証かイントロスペクションで確かめる | 無効 |
| reuse_revokes_refresh | 1回目でリフレッシュトークンが出ていれば、2回目の後に使う | 拒否 |

判定: 2回目を受理したら不適合。2回目の拒否がどの仕組みで成り立っているかもソースで確かめて書く。発行済みのトークンが失効しないなら、RFC 6749 §4.1.2 の SHOULD に反するので info に出す。アクセストークンが自己完結型のJWTなら、署名だけで検証するリソースサーバは失効後も有効期限まで受け入れる。これはリソースサーバの検証の仕方しだいの攻撃なので、既定の有効期限と合わせて残るリスクに書く。

## AS-07: codeを別clientや別redirect_uriで交換させない

守りたいもの: code が、発行先の client と認可リクエストの redirect_uri に結び付くこと。結び付かないと、漏れた code を攻撃者が自分の client で交換できる。原文の README の第4節。

| ケース | 交換時の変更 | 期待 |
|---|---|---|
| wrong_client | 別の登録済み `client_id` | 拒否 |
| wrong_redirect | 認可リクエストと違う `redirect_uri` | 拒否 |
| missing_redirect | 認可リクエストに含めた `redirect_uri` を省略 | 拒否 |

wrong_client では、別の client が自分の正しい認証情報で交換する。認証の失敗で拒否されても、結び付きを確かめたことにはならない。

## AS-08: secretを持つclientに認証を求める

守りたいもの: secret を持つ client の漏れた code を、secret なしで交換させないこと。原文の README の第7節。

| ケース | 交換時の認証 | 期待 |
|---|---|---|
| confidential_auth_missing | 省略 | `invalid_client` |
| confidential_auth_wrong | 誤ったsecret | `invalid_client` |

メタデータの `token_endpoint_auth_methods_supported` にある方式をすべて試すか、試していない方式を範囲外として書く。Basic 認証の失敗に 401 と `WWW-Authenticate` を返さないなら、RFC 6749 §5.2 の MUST に反するので info に出す。

## AS-09: code・トークンを推測や偽造から守る

守りたいもの: code やトークンを推測させないこと。原文の README の第4節。

ソースで確かめる。

- codeの生成に暗号学的乱数を使い、128ビット以上あるか。RFC 6749 §10.10 は、推測できる確率を 2^-128 以下にするよう MUST で求めている。
- アクセストークンは乱数か署名付きか。署名なら鍵の生成と保管場所。

何回か発行した値を並べ、桁数が少ない、連番に近いなど推測できそうなら、トークンエンドポイントでの総当たりが止まるかを試す。推測できる値なら不適合。ソースで基準に足りないと分かったが、総当たりを試していないなら info に出し、「負荷試験は未実施」と書く。リンクはコミットを固定したパーマリンクで書く。

## AS-10: response_typeの変更でアクセストークンを漏らさない

守りたいもの: `response_type=code` だけのクライアントについて、アクセストークンをフラグメントで返さないこと。フラグメントのトークンは、オープンリダイレクタや履歴から漏れ、PKCE の結び付きも効かない。攻撃は `sources/zenn/02-insufficient-redirect-uri-validation.txt` の Implicit の例、`sources/zenn/06-at-injection.txt`、原文の README の第6節。

`response_type=code` だけを登録したclientで、次の値を要求する。

| ケース | response_type | 期待 |
|---|---|---|
| token | `token` | 拒否 |
| id_token_token | `id_token token` | 拒否 |
| code_token | `code token` | 拒否 |
| code_id_token | `code id_token` | 拒否 |
| code_id_token_token | `code id_token token` | 拒否 |

判定: アクセストークンを返したら、その client の登録で Implicit やハイブリッドを許しているかを確かめる。許していないのに返したら不適合。許しているなら AS の不備ではなく、使わない Implicit を許した登録設定として書く。AS が response_type を client ごとに許可していて、許していない client を `unauthorized_client` 以外のエラーで拒否するなら、RFC 6749 §4.2.2.1 に沿っていないので info に出す。AS 自体がその response_type に対応していないなら、`unsupported_response_type` が正しい応答なので info にしない。

## AS-11: 同意画面からRefererや外部リソース経由で漏らさない

守りたいもの: 同意画面の URL に入る値、とくに state を外部へ漏らさないこと。state が漏れると、クライアントの CSRF の防御が効かなくなる。攻撃は `sources/zenn/03-credential-leakage-via-referer-headers.txt` と原文の README の第5節。

現在のブラウザの既定の Referrer Policy では、別オリジンへの Referer にクエリは載らない。漏れるのは、既定より緩い Referrer Policy のページから外部へ通信するときと、外部の JavaScript を読み込むとき。外部のスクリプトは Referer を介さず `location.href` から値を読める。

ソースで確かめる。

- Referrer-Policyの指定。ヘッダー、meta、要素の属性のどれにも既定より緩い値が無いか。
- 同意画面の外部リンク、外部リソース、外部スクリプト。CSPで外部を許していればそれも書く。
- 同意画面のURLに何が入るか。state のほか、code やトークンが入らないか。
- アクセスログや解析ツールに同意画面のURLを残すか。

実環境で確かめる。

```sh
curl -sI '<同意画面のURL>' | grep -i -E 'referrer-policy|content-security-policy'
```

ブラウザの開発者ツールか agent-browser で、同意画面が行う外部への通信を見る。実環境を見ていなければ未確認とする。

判定: 緩い Referrer Policy と外部への通信がそろうか、外部スクリプトを読み込むなら不適合。既定の Referrer Policy のままで外部リソースやリンクがあるだけなら、値は漏れないので不適合にせず、RFC 9700 §4.2.4 の SHOULD NOT に反するので info に出す。

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

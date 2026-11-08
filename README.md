# skills

コーディングエージェント向けのスキル集。各ディレクトリの `SKILL.md` に、エージェントが使う手順を定義している。

## スキル一覧

| スキル | 用途 |
|---|---|
| [oauth-audit](oauth-audit/README.md) | OAuth / OIDC 実装の監査。認可サーバとクライアントのチェックリストに沿って、監査テストと報告を作る |

必要な実行環境、利用上の注意、付属ツールの使い方は、各スキルの README を参照。

## 導入

必要なスキルを個別に選んで導入する。以下の `<skill-name>` は、一覧にあるスキル名に置き換える。

### APM

[APM](https://github.com/microsoft/apm) でユーザー全体に入れる。

```sh
apm install -g mincemaker/skills/<skill-name>
```

プロジェクト単位なら、`apm.yml` に対象エージェントと依存を書く。例えば `oauth-audit` を Claude Code に導入する場合：

```yaml
name: my-project
version: 0.1.0
targets:
  - claude
dependencies:
  apm:
    - mincemaker/skills/oauth-audit
```

```sh
apm install
```

### agent-skills-nix

[Kyure-A/agent-skills-nix](https://github.com/Kyure-A/agent-skills-nix) で Home Manager から管理する場合、利用者の flake に次の inputs を追加する。このリポジトリ自体に flake は不要。

```nix
inputs = {
  agent-skills.url = "github:Kyure-A/agent-skills-nix";
  mincemaker-skills = {
    url = "github:mincemaker/skills";
    flake = false;
  };
};
```

既存の `outputs` を `outputs = inputs@{ ... }: ...;` の形にし、Home Manager の構成に module と inputs を渡す。

```nix
home-manager.lib.homeManagerConfiguration {
  inherit pkgs;
  modules = [
    inputs.agent-skills.homeManagerModules.default
    ./home.nix
  ];
  extraSpecialArgs = { inherit inputs; };
}
```

`home.nix` でソース、スキル、配置先を選ぶ。例えば `oauth-audit` を Claude Code に導入する場合：

```nix
{ ... }:
{
  programs.agent-skills = {
    enable = true;
    sources.mincemaker.input = "mincemaker-skills";
    skills.enable = [ "oauth-audit" ];
    targets.claude.enable = true;
    # ~/.agents/skills に配置する場合は、代わりに次を指定する。
    # targets.agents.enable = true;
  };
}
```

スキルはリポジトリ直下にあるため、`subdir` は指定しない。`skills.enable` に必要なスキル名を列挙する。revision は利用者の `flake.lock` で固定する。既存の skills ディレクトリがある場合は、適用前に upstream の [destination ownership](https://github.com/Kyure-A/agent-skills-nix/blob/HEAD/docs/installation.md#destination-ownership) を確認する。

スキルが必要とする言語ランタイムやツールは、別途用意する。要件は各スキルの README を参照。

## ライセンス

MIT。全文は [LICENSE](LICENSE)。

`oauth-audit/sources/` の RFC のテキストは、このライセンスの対象外。IETF Trust の著作物で、[IETF Trust Legal Provisions](https://trustee.ietf.org/license-info) の条件に従う。

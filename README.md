# skills

English | [日本語](README_ja.md)

A collection of skills for coding agents. Each directory contains a `SKILL.md` file that defines the instructions agents follow.

## Skills

| Skill | Purpose |
|---|---|
| [oauth-audit](oauth-audit/README.md) | Audit OAuth / OIDC implementations. Create audit tests and reports using checklists for authorization servers and clients. Skill instructions, checklists, and the report template are in Japanese. |

See each skill's README for required runtimes, usage notes, and instructions for using included tools.

## Installation

Before installing, read the usage notes in each skill's README. Use security audit skills only on systems you manage or have permission from the administrator to audit.

Install the skills you need individually. Replace `<skill-name>` below with a name from the list above.

### APM

Install for your user account with [APM](https://github.com/microsoft/apm):

```sh
apm install -g mincemaker/skills/<skill-name>
```

For a project, declare the target agent and dependency in `apm.yml`. For example, to install `oauth-audit` for Claude Code:

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

To manage skills through Home Manager with [Kyure-A/agent-skills-nix](https://github.com/Kyure-A/agent-skills-nix), add these inputs to your flake. This repository does not need its own flake.

```nix
inputs = {
  agent-skills.url = "github:Kyure-A/agent-skills-nix";
  mincemaker-skills = {
    url = "github:mincemaker/skills";
    flake = false;
  };
};
```

Capture the inputs with `outputs = inputs@{ ... }: ...;`, then pass the module and inputs to your Home Manager configuration:

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

In `home.nix`, choose the source, skills, and installation target. For example, to install `oauth-audit` for Claude Code:

```nix
{ ... }:
{
  programs.agent-skills = {
    enable = true;
    sources.mincemaker.input = "mincemaker-skills";
    skills.enable = [ "oauth-audit" ];
    targets.claude.enable = true;
    # To install into ~/.agents/skills, use this instead:
    # targets.agents.enable = true;
  };
}
```

Skills are at the repository root, so do not set `subdir`. List the skills you need in `skills.enable`. Your `flake.lock` pins the source revision. If you already have a skills directory, read the upstream [destination ownership guide](https://github.com/Kyure-A/agent-skills-nix/blob/HEAD/docs/installation.md#destination-ownership) before applying the configuration.

Provide any language runtimes or tools required by the skills separately. See each skill's README for its requirements.

## License

MIT. See [LICENSE](LICENSE) for the full text.

The RFC texts in `oauth-audit/sources/` are not covered by this license. They are copyright of the IETF Trust and the persons identified as the document authors, and are reproduced under the [IETF Trust Legal Provisions Relating to IETF Documents](https://trustee.ietf.org/license-info).

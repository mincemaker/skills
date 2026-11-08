# oauth-audit

English | [日本語](README_ja.md)

A skill for agents auditing OAuth / OIDC implementations. Audit authorization servers using checklist items AS-01 through AS-11, and clients using RP-01 through RP-16. Write audit tests in the target's programming language and produce audit reports.

The skill uses the checklist from [oauth-redirect-attacks](https://github.com/mincemaker/oauth-redirect-attacks). See [SKILL.md](SKILL.md) for the specific audit procedures. The skill instructions, checklists, and report template are in Japanese.

## Before using

This skill and its tools are intended for defensive checks of systems you manage or systems whose administrators have authorized you to audit.

- Conduct the audit using tests run locally against source code obtained locally. The exception is AS-11, which checks the consent screen using curl and a browser against the live system. Do this only if the user is the system's administrator or has the administrator's permission, and has provided the target URL. Do not send verification requests to any other live service or real IdP.
- Do not send verification requests to systems managed by others without the administrator's permission. The same applies to requests that exceed the scope of that permission. Under Japan's Act on Prohibition of Unauthorized Computer Access, the following acts may also be criminal offenses, in addition to gaining access by exploiting flaws in authentication checks: accessing a system using another person's authorization code, access token, ID token, password, or other authentication credentials (Article 2, Paragraph 4, Item 1); obtaining them for the purpose of unauthorized access (Article 4); and storing them for that purpose (Article 6). If you encounter another person's credentials during an audit, do not use them or include them in reports or records.
- Do not send requests to live services that could interfere with their operation, such as brute-force tests. Such acts may constitute the crime of obstruction of business by damaging a computer under Japan's Penal Code.
- Audit tests and the fake IdP (`tools/fakeidp`) are intended to be run by users locally, as they choose. They are not programs intended to make another person's computer perform actions against that person's will. Do not modify the tests or tools to make them do so, or distribute them for the purpose of having others run them. Such acts may constitute an offense involving electromagnetic records of unauthorized commands under Japan's Penal Code, including the creation of computer viruses.
- By default, the fake IdP listens only on 127.0.0.1. Do not use `-addr` to bind it to an address reachable from outside. Do not run it somewhere accessible to third parties while `-issuer` is set to the URL of a real provider. This could cause someone who mistakes it for the real IdP to enter their credentials, which may constitute an unlawful request for input under Article 7 of Japan's Act on Prohibition of Unauthorized Computer Access, commonly known as phishing.
- When performing checks in a live environment or writing reports, do not record real users' personal information, tokens, or URLs or logs containing them. Redact values when necessary. In addition to potentially being subject to Japan's Act on the Protection of Personal Information, obtaining the contents of another person's communications may violate the secrecy of communications.
- Do not publicly disclose flaws found during an audit until they have been fixed. When notifying the target's developers, use the vulnerability reporting channel they provide. In Japan, there is also a vulnerability information reporting system run by IPA and JPCERT/CC. Do not post details of unfixed flaws in public issues, pull requests, or comments. The skill places audit tests in a locally obtained copy of the target's source code using a symlink or by copying them; it does not write anything to the target's remote repository. Do not commit or push from the working tree where the tests have been placed.
- When dealing with systems or users outside Japan, also comply with the laws of the relevant country.

The guidance here is intended as a general reference and is not legal advice. What is permitted depends on the contract with the target, the scope of authorization, and the circumstances. If in doubt, agree on the scope in writing with the target's administrator before beginning the audit, and consult a professional if necessary.

This skill and its tools are provided "as is." The author assumes no liability for the results of their use, to the extent permitted by law. An audit report indicates whether items were met within the scope checked; it does not guarantee the target's security.

## Installation

Install for your user account with APM.

```sh
apm install -g mincemaker/skills/oauth-audit
```

For project-level APM settings and the Home Manager configuration for `Kyure-A/agent-skills-nix`, see the [installation guide](https://github.com/mincemaker/skills#installation). With Nix, add this repository as a `flake = false` input and select `oauth-audit`. No dedicated flake or build steps are needed.

## Requirements

- A coding agent that can load this skill
- Go 1.24 or later
- Node.js 22 or later
- The language and test framework used by the audit target
- A writable working directory

Retrieving source material requires connections to zenn.dev and openid.net. From Zenn, chapters are retrieved using an undocumented, unofficial API. To avoid overloading the service, retrieval is spaced out between chapters; do not repeatedly fetch them. Reuse the copies you have retrieved. See SKILL.md for what to do if retrieval fails. Any network access required to obtain the target or resolve dependencies depends on the target's development environment.

Go and Node.js are not installed simply by installing APM or placing the skill. With Home Manager, you can provide them, for example, with `home.packages = [ pkgs.go pkgs.nodejs ];`.

## Audit workflow

1. Pin the target commit and determine whether it acts as an authorization server (AS), a client (RP), or both.
2. Write audit tests using the target's test framework. For an RP audit, direct all outbound traffic to a fake IdP running locally.
3. Run the tests and assess each item.
4. Write the report and validate it with the tool.

Determine the result based on whether an attack that defeats the protection intended by the item can actually succeed against the target. The report should distinguish these four categories:

| Category | Contents |
|---|---|
| Vulnerability | An attack that can succeed. Reproduce it with a test or show the decisive step |
| info | Something that cannot be shown to enable an attack but clearly violates an RFC. Quote the original RFC text |
| Residual risk | An attack that can succeed depending on conditions outside the target, such as how it is registered |
| Observation | Something that does not fit any of the above but should be brought to the reader's attention |

Issues outside the checklist may be missed. State anything that was not checked in the report's section for unchecked scope.

## Files and working directories

`<skill>` represents the installation directory for this skill, and `<work>` represents the working directory for the audit. Replace these with the actual paths in commands.

| Location | Contents |
|---|---|
| `<skill>/SKILL.md` | Audit procedures for the agent |
| `<skill>/checklist-*.md` | Checklists for each role |
| `<skill>/report-template.md` | Report template |
| `<skill>/sources/` | Bundled RFCs and source notes |
| `<skill>/tools/` | Go tool source code |
| `<work>/sources/` | Zenn chapters and OIDC Core retrieved later |
| `<work>/dist/` | Audit reports and test deliverables |

The installation directory may be read-only. Save retrieved source material, audit tests, and deliverables in the working directory.

## Retrieving and quoting source material

The `sources/` directory contains texts of RFCs 6749, 7636, 8252, 9207, 9700, and 10017. They are copied from commit `b001ca6` of [oauth-redirect-attacks](https://github.com/mincemaker/oauth-redirect-attacks).

Hideki Ikeda's [攻撃手法から学ぶ OAuth セキュリティベストプラクティス](https://zenn.dev/hidebike712/books/oauth-attacks-and-bcp) and OpenID Connect Core 1.0 are not included in this repository because of restrictions on reproduction. Users should retrieve them locally with the following command.

`<work>/sources/zenn/` is reserved for the script. On a refetch, all its contents are deleted after all source material has been fetched and before anything is written. Do not put your own files there.

```sh
node <skill>/scripts/fetch-sources.mjs <work>/sources
node <skill>/scripts/rfc-quote.mjs <skill>/sources/rfc9700.txt "<sentence-start>"
node <skill>/scripts/rfc-quote.mjs <work>/sources/oidc-core-1_0.txt "<sentence-start>"
```

For quotations, replace `<sentence-start>` with the beginning of the sentence to retrieve. When quoting a Zenn chapter, specify `<work>/sources/zenn/<chapter>.txt` as the file. Retrieved source material is not covered by this repository's MIT license. See [sources/README.md](sources/README.md) for source notes in Japanese.

Keep the following points in mind when handling retrieved source material:

- Retrieved files are for local reading as part of the audit. Do not share or redistribute them. Zenn's terms of use prohibit reproduction and redistribution without the rights holder's permission (Article 6, Paragraph 3).
- Quote only the portions necessary to support the assessment in the report. Keep the report text primary and the quotation secondary, distinguish quoted passages, and include the author's name, book or specification title, chapter, URL, and retrieval date. This is to meet the requirements for quotations under Japan's Copyright Act (Article 32) and identifying sources (Article 48).
- Retrieval for business purposes may not qualify as reproduction for private use under Article 30 of Japan's Copyright Act. The license for OpenID Connect Core 1.0 is limited to the purposes of developing specifications and implementing them. When using these materials in an organization, verify the scope of permission from each rights holder.

## Go tools

Run the tools from the working directory; do not change into the skill's `tools/` directory.

```sh
go -C <skill>/tools run ./fakeidp -h
go -C <skill>/tools run ./auditcheck -h
```

The Go build cache must be writable. If the default cache cannot be used in a sandbox, set `GOCACHE` to the absolute path of a writable temporary directory. Follow [SKILL.md](SKILL.md) for how to use the tools with the audit target and for assessment criteria.

## Development-time verification

Run from the repository root.

```sh
node --test oauth-audit/scripts/*.test.mjs tests/*.test.mjs
go -C oauth-audit/tools test ./...
```

Tests for retrieving source material simulate the network and do not connect to external services.

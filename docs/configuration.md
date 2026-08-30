# Repository configuration

Revoot optionally reads `.revoot.toml` from the repository root. The file
describes codebase review semantics; it cannot choose a provider, model,
credential, network route, publication authority, execution graph, tool set, or
agent strategy.

```toml
version = 1

[review]
include = ["src/**", "crates/**", "migrations/**"]
exclude = ["vendor/**", "dist/**", "**/*.generated"]
minimum_confidence = 80
max_findings = 12

[repository]
generated_files = "ignore"
guidance = "All externally retried writes must be idempotent."

[[rules]]
paths = ["crates/payments/**"]
focus = ["authorization", "idempotency", "money-handling"]
guidance = """
Amounts are integer cents. Authorization must be checked inside the write
transaction, and every externally retried write must be idempotent.
"""

[[suppressions]]
fingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
reason = "Accepted eventual consistency during replication."
expires = "2026-12-31"
ticket = "ENG-1842"
```

## Fields

`review.include` and `review.exclude` accept exact paths, directory prefixes
ending in `/**`, and suffixes beginning with `**/*`. Inclusion narrows the
changed-file review scope. Exclusion takes precedence. Neither setting prevents
Revoot from reading an unchanged checkout file when it is crucial to verifying
a finding.

`review.minimum_confidence` is clamped to the supported high-signal range of
70–100. `review.max_findings` may lower the product ceiling but cannot raise it.

`repository.generated_files` is either `ignore` (the default) or `review`.
Repository guidance and rule guidance are bounded, untrusted model input. A rule
increases attention to its listed concerns; it does not disable correctness,
security, reliability, compatibility, data-loss, concurrency, or performance
analysis elsewhere.

## Environment variables

Environment variables are operator-owned configuration. Command-line options
take precedence over them; repository `.revoot.toml` settings do not control
provider credentials, model selection, publication, or network access. Integer
values must be unsigned decimal numbers, booleans must be exactly `true` or
`false`, and comma-separated lists must not contain empty entries.

### Provider and review

| Variable | Default | Value and effect |
| --- | --- | --- |
| `REVOOT_PROVIDER` | `auto` | `auto`, `anthropic`, or `openai`. `auto` selects the available key; if both keys exist, Anthropic wins. |
| `REVOOT_MODEL` | `auto` | `auto` selects the provider's catalog default. Any other value is passed as the provider model ID. |
| `REVOOT_REVIEW_MODEL` | `auto` | Compatibility alias for `REVOOT_MODEL`. Do not set both. |
| `REVOOT_REVIEW_CONTEXT_LINES` | `40` | Unsigned diff context radius; effective range `0` through `200`. |
| `REVOOT_MINIMUM_CONFIDENCE` | `70` | Unsigned minimum finding confidence; effective range `70` through `100`. |
| `REVOOT_MAX_FILES` | `100` | Unsigned selected-file limit; effective range `1` through `100`. |
| `REVOOT_MAX_INPUT_BYTES` | `1000000` | Unsigned selected-diff byte limit; effective range `1` through `1000000`. |
| `REVOOT_MAX_FINDINGS` | `25` | Unsigned candidate-finding limit; effective range `1` through `25`. |
| `REVOOT_MAX_MODEL_REQUESTS` | `20` | Unsigned provider-request limit; effective range `1` through `20`. |
| `REVOOT_DEADLINE_SECONDS` | `600` | Unsigned review deadline; effective range `1` through `600` seconds. |
| `REVOOT_PUBLICATION_ENABLED` | `false` | Whether a host-backed review may publish comments. Generated CI sets this to `true`. |
| `REVOOT_FORK_BEHAVIOR` | `skip` | GitLab fork behavior: `skip` or `report-only`. GitHub fork behavior is encoded in the generated workflow. |

The product bounds shown above are final ceilings. A repository configuration
may request lower limits, while an environment variable or CLI option can
override that request only within the product bounds.

### Code-host network

| Variable | Default | Accepted value and effect |
| --- | --- | --- |
| `REVOOT_GITHUB_SERVER_URL` | inferred | Exact HTTPS web origin for GitHub Enterprise Server, such as `https://github.example.com`. |
| `REVOOT_GITHUB_CA_BUNDLE_FILE` | unset | PEM CA bundle used for the configured GitHub host. |
| `REVOOT_GITHUB_PRIVATE_CIDRS` | unset | Comma-separated private CIDRs allowed for a self-managed GitHub host; at most 16. |
| `REVOOT_GITLAB_CA_BUNDLE_FILE` | unset | PEM CA bundle used for the discovered GitLab host. |
| `REVOOT_GITLAB_PRIVATE_CIDRS` | unset | Comma-separated private CIDRs allowed for a self-managed GitLab host; at most 16. |

Private CIDR exceptions apply only to the corresponding code host. They do not
expand provider API access.

### Credentials

Store these as CI secrets, not repository variables or `.revoot.toml` values.

| Variable | Purpose and precedence |
| --- | --- |
| `ANTHROPIC_API_KEY` | Anthropic provider credential. |
| `OPENAI_API_KEY` | OpenAI provider credential. |
| `REVOOT_MODEL_TOKEN` | Compatibility alias for `OPENAI_API_KEY`; setting both is rejected. |
| `REVOOT_GITHUB_TOKEN` | Optional short-lived token from a dedicated automation identity, preferably a repository-installed GitHub App; enables automatic thread resolution and is preferred over `GH_TOKEN`, then `GITHUB_TOKEN`. Do not use a developer PAT for durable CI automation. |
| `GH_TOKEN` | GitHub CLI-compatible token; used when `REVOOT_GITHUB_TOKEN` is absent. |
| `GITHUB_TOKEN` | GitHub Actions token fallback; completes publication, state tracking, and duplicate prevention. If GitHub denies automatic resolve or reopen mutations, Revoot records the non-fatal limitation and preserves lifecycle state in the overview. |
| `REVOOT_GITLAB_TOKEN` | GitLab private token with read and write access; highest precedence. |
| `GITLAB_TOKEN` | GitLab private token used when `REVOOT_GITLAB_TOKEN` is absent. |
| `REVOOT_GITLAB_BEARER_TOKEN` | GitLab OAuth bearer token used when private-token variables are absent. |
| `CI_JOB_TOKEN` | GitLab job token fallback. It can read merge-request data but cannot publish discussions. |

GitHub Actions repository or organization variables named `REVOOT_PROVIDER`
and `REVOOT_MODEL` are mapped into the generated review job, with `auto` as the
fallback for each. This repository's dogfooding workflow also uses `REVOOT_TAG`
to select the newest green `main` image or an RC or branch image, with `latest`
as its fallback. These are workflow controls, not `revoot` process environment
variables. GitHub and GitLab also inject host-owned CI metadata; those platform
variables identify the pull or merge request and are not Revoot configuration
knobs.

## Automatic attention budgeting

Before model execution, Revoot assigns every exact changed file a deterministic
review-value tier, score, and set of reasons. The ranking is part of the
snapshot-bound partition plan and is replay-validated.

- High signal includes sensitive subsystems, database migrations, public
  interfaces, dependency manifests, and build or deployment control surfaces.
- Standard signal includes ordinary source, configuration, and test code.
- Low signal includes lockfiles, generated output, snapshots, minified assets,
  and documentation.
- Binary and unsupported text contents are excluded from model context.

High signal wins capacity before standard signal, regardless of diff size.
Low-signal files share at most 10% of the selected diff-byte budget, capped at
64 KiB. They remain available as full-checkout context when a higher-value
change makes them relevant.

Revoot also scans added diff lines locally for a narrow set of structural
hazards. Merge-conflict markers and recognizable private credential material
promote a low-signal file before any provider request. These scans affect
attention; they do not publish a finding without normal review validation.

Repository configuration may narrow scope and lower global budgets, but it
cannot redefine tiers, promote paths, or expand the low-signal quota. This keeps
cost behavior predictable and prevents a proposed change from buying itself
more reviewer attention.

Suppressions match the exact `finding_key` emitted in the JSON review report.
Each suppression requires a reason and a valid, non-expired UTC date. An
optional ticket provides a traceable owner. Duplicate, malformed, or expired
suppressions reject the configuration. Broad path or category suppressions are
not supported.

Repository-owned resource fields may only lower hard ceilings:

```toml
[budget]
max_files = 80
max_input_bytes = 750000
max_model_requests = 12
deadline_seconds = 480
```

## Trust and precedence

For local branch review, a GitHub pull request, or a GitLab merge-request
pipeline, Revoot reads `.revoot.toml` from the exact comparison base commit with
a bounded, shell-free Git object read. The proposed working or head version
never controls its own review. In CI, Revoot also requires the configuration
commit to match the authoritative host snapshot before model execution. A
configuration change becomes active after merge.

Product policy always clamps repository and operator requests. Effective
precedence is CLI, environment, trusted local configuration, repository
configuration, then compiled defaults. Provider/model choice, credentials,
private-network exceptions, publication, and other operator settings remain
trusted environment or CLI policy.

Use `revoot config explain --base-config .revoot.toml --json` to inspect scalar
provenance, effective policy clamps, structured rules, and suppressions without
loading credentials.

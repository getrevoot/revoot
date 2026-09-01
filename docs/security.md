# Security architecture

Revoot assumes pull-request authors, repository bytes, filenames, diffs,
commit messages, review comments, and model output may be hostile. It also
assumes the selected model provider is outside the CI trust boundary. The goal
is to give an untrusted reviewer the minimum capability required to analyze a
change without turning repository content into executable authority.

## What crosses each boundary

The model provider receives the trusted reviewer policy plus bounded review
data: selected diffs and anchors, policy-approved repository file excerpts,
bounded commit history, repository guidance, and prior review discussions. The
selected provider key is attached by the HTTP adapter as authentication; it is
not placed in the prompt or a model tool result.

Code-host credentials are used only by the GitHub or GitLab transport. They are
not included in model requests. Unknown environment variables are ignored by
the configuration and credential allowlists, and secret values have redacted
debug representations and are zeroed when their in-process wrapper is dropped.

Revoot sends source code to the model provider by design. Do not use Revoot
with a provider or account whose contractual, residency, retention, or training
terms do not meet your requirements.

## Repository context controls

In GitHub and GitLab CI, the model's repository toolbox is built from the Git
index rather than a directory walk. Untracked runner files, mounted secret
files, build output, and neighboring workspace content are therefore outside
the inventory. Symbolic links are not followed, and each admitted file is
rechecked as a regular file before reads. Reads, searches, diffs, file counts,
bytes, model turns, elapsed time, and findings are bounded.

Sensitive path classes are excluded from changed-file prompts and auxiliary
reads by default. The built-in policy covers `.env` variants, common package
and cloud credential files, private-key and keystore formats, Terraform state,
and common cloud, SSH, Kubernetes, and Terraform state directories. This is
intentionally conservative: `.env.example` and similar templates are denied
unless renamed outside the `.env.*` class.

Add repository-specific exclusions to the base branch's `.revoot.toml`:

```toml
version = 1

[model_context]
exclude = [
  "internal/customer-data/**",
  "fixtures/private/**",
  "**/*.vault",
]
```

Patterns support exact paths, `directory/**`, and `**/*suffix`. This policy is
loaded from the exact comparison base commit, so a pull request cannot weaken
it for its own review. It only narrows access; it cannot override built-in
denials. `review.exclude` controls which changed files are reviewed, whereas
`model_context.exclude` also prevents toolbox access.

Local worktree review intentionally includes non-ignored untracked changes so
developers can review work in progress. The same sensitive-path policy still
applies, but CI's tracked-only guarantee does not. Keep unrelated sensitive
files outside a locally reviewed worktree or exclude them explicitly.

## Private diff handling and bounded context

Selected unified diffs are materialized for one run in a randomized private
temporary directory. The directory is mode `0700`, artifact files are mode
`0600`, filenames are internal digests rather than repository paths, and the
model never receives an artifact filesystem path. RAII cleanup removes the
store on success, error, or cancellation.

Groups no larger than 16 KiB may receive their complete diff once when the
whole request remains inside the 32,000-token target. Larger groups receive
only file and hunk metadata initially. Workers fetch exact bounded hunk pages
with `read_diff` or search the private artifacts with `search_diff`; no large
group is partially inlined. Tool results are deterministically paginated and
never exceed 32 KiB. Delivered coverage is recorded from successful inline and
tool results rather than model claims.

Rebased model turns retain the immutable compact group brief, a structured
checkpoint of at most 4 KiB, and only the latest tool-call/result exchange.
Older source slices and raw conversation history are not repeatedly inserted,
persisted, or summarized by another model call.

## Prompt-injection containment

Repository content is placed in delimited user content and is explicitly
labeled untrusted. Repository guidance can express domain invariants and review
priorities, but cannot change provider selection, credentials, budgets,
publication, network policy, or the trusted system prompt.

The model has a closed tool set: list approved files, read approved files,
search approved files, inspect approved diffs and bounded history, read prior
discussions, submit a candidate finding, and submit one summary. There is no
shell, subprocess, environment, arbitrary HTTP, filesystem write, code-host
write, or credential tool. Tool arguments are parsed through strict schemas and
the repository toolbox independently enforces its allowlist, so prompt text
cannot grant access to a denied path.

Publication is a separate deterministic stage. Findings must bind to an anchor
issued from the authoritative diff, pass size and confidence limits, and survive
deduplication and freshness checks. Model-authored Markdown links, images,
external URLs, code-host quick actions, marker injection, and control characters
are rejected; HTML is escaped. The model never receives a publication tool or
a host token.

The stdio MCP server exposes the same bounded read-only repository and diff
handlers through opaque process-local review handles. It has no listener,
publication, write, command, provider-call, credential, environment, or network
tool. Cursor tokens are authenticated and bound to the handle, snapshot, tool,
and query; stale, tampered, cross-handle, and cross-snapshot cursors fail closed.
Standard output is reserved for protocol JSON.

These are capability controls, not a claim that prompt injection is solved. A
successful injection can still influence analysis or cause allowed repository
text to be repeated in plain-text output. Keep secrets out of the tracked
reviewable repository and use the context policy as a second boundary.

## Network and runtime containment

Revoot constructs clients only for the selected model provider and code host.
Endpoints must be canonical HTTPS; requests use exact origins and API paths,
platform DNS results are pinned to the client, private and special-purpose
addresses are denied unless an operator explicitly allows a CIDR for a
self-managed code host, bundled WebPKI roots are the default, and HTTP proxies
and redirects are disabled. The model has no interface for creating a new
client or choosing a destination.

Application egress policy is not an operating-system firewall. Restrict review
jobs at the runner, namespace, VPC, or firewall layer to the selected provider
API and code-host API. Account for the registry and GitHub Actions endpoints
needed before the review process starts. Prefer a dedicated ephemeral runner
with no cloud instance metadata route, service-account token, Docker socket, or
shared credentials.

The OCI image declares UID/GID 65532. GitLab runs the image as that user. A
GitHub job container starts as root because `actions/checkout` must populate the
mounted workspace; the generated workflow then assigns the workspace to UID
65532 and invokes only Revoot as that user with `no-new-privileges`. Git remains
in the image for checkout compatibility, but Revoot uses its embedded Git
implementation and never executes repository hooks or Git subprocesses.

Generated configuration requires `image@sha256:DIGEST` references. The OCI base
image and third-party GitHub Actions are pinned by digest or commit. Release CI
runs dependency advisory checks, publishes `SHA256SUMS` and a CycloneDX SBOM,
and creates signed GitHub attestations for archives and the multi-architecture
image. Verify a downloaded archive with both the checksum and GitHub CLI:

```sh
sha256sum --check SHA256SUMS
gh attestation verify revoot-linux-amd64.tar.gz --repo getrevoot/revoot
```

## Provider data handling

Provider API retention is a deployment property, not something Revoot can
verify from an API response. Use a dedicated provider project, disable provider
logging and training where the provider supports it, set spend and rate limits,
and obtain the required zero-data-retention or modified-monitoring approval
before reviewing sensitive code.

At the time this document was updated, OpenAI states that API data is not used
for training by default but standard abuse-monitoring logs may retain customer
content for up to 30 days; Zero Data Retention and Modified Abuse Monitoring
require eligibility and configuration. Anthropic states that standard API
inputs and outputs are deleted within 30 days, subject to exceptions, and that
zero-data-retention eligibility is a separate arrangement. Recheck the current
[OpenAI API data controls](https://developers.openai.com/api/docs/guides/your-data)
and [Anthropic API retention policy](https://privacy.claude.com/en/articles/7996866-how-long-do-you-store-my-organization-s-data)
before adoption.

## Deliberate limitations

- Revoot does not scan inbound repository content or outbound model payloads
  for secret values. Path policy and tracked membership are deterministic
  exposure controls, not content classification.
- Provider and code-host credentials exist in the Revoot process while their
  adapters are active. They are not exposed as model capabilities, but Revoot
  does not put each adapter in a separate credential broker or process.
- The provider necessarily receives reviewed code and approved context. A
  compromised provider, runner, Revoot binary, TLS trust root, or operating
  system is outside the in-process containment guarantee.
- Plain-text model output may quote approved repository content. Publication
  validation blocks active links and markup abuse, not semantic disclosure.
- Repository comments and uploaded JSON reports inherit the visibility and
  retention of the code host and CI artifact settings.

## Deployment checklist

1. Pin the Revoot image by the release digest and verify release attestations.
2. Use ephemeral, isolated runners without privileged mounts or ambient cloud
   credentials; enforce outbound network policy outside the process.
3. Keep fork behavior at `skip`. Never combine `pull_request_target` with an
   untrusted checkout and secrets.
4. Give host tokens only repository-read and review-publication permissions.
   Use a dedicated, budget-limited provider project with reviewed retention.
5. Inventory sensitive repository paths and add `model_context.exclude` entries
   on the protected base branch. Keep secrets out of Git even when excluded.
6. Leave publication disabled for initial evaluation by setting
   `REVOOT_PUBLICATION_ENABLED=false`; inspect JSON reports before enabling
   comments.
7. Protect workflow and `.revoot.toml` changes with code owners and required
   review, and periodically rerun prompt-injection and policy regression tests.

Report security issues privately as described in [SECURITY.md](../SECURITY.md).

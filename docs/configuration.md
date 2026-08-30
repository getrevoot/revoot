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

Product and organization policy always clamp repository requests.
Provider/model choice, credentials, private-network exceptions, publication,
and other operator settings remain trusted environment or CLI policy.

Use `revoot config explain --base-config .revoot.toml --json` to inspect scalar
provenance, effective policy clamps, structured rules, and suppressions without
loading credentials.

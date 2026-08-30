# GitLab component operation

The Revoot source, issues, pull requests, releases, and container image live on
GitHub. `gitlab.com/getrevoot/revoot-ci` is a deliberately small GitLab-native
component and acceptance project; it is not a mirror of the Rust repository.

The component project contains only its README, license, pipeline, deterministic
fixture changes, and `templates/review/template.yml`. The template runs the
released `ghcr.io/getrevoot/revoot` image. Each component release pins the exact
image digest produced by the corresponding GitHub release.

The acceptance pipeline exercises:

- merge-request discovery and exact diff acquisition;
- checkout and API snapshot binding;
- initial inline publication and repeat-run convergence;
- changed-head and stale-finding behavior;
- job-token report-only behavior and project-token publication; and
- cross-project fork safety when the companion fork fixture is available.

With a write-capable project token, each successful review also updates one
bounded, version-marked `<details>` block in the merge-request description.
Author text outside that block is preserved. The overview records the
implementation summary, overall risk, material risk areas, assumptions or gaps,
manual validation still required, and a footer identifying the Revoot version,
linked GitLab job, provider/model, and reviewed commit. Repeated runs converge
to one block; ambiguous markers stop publication.

Before model work, Revoot completely acquires the bounded merge-request
discussion inventory, including live resolution state, resolver identity,
current and original anchors, timestamps, and attributed replies. The reviewer
must interpret that untrusted context before submitting findings. Revoot embeds
lineage and occurrence metadata in its own notes, carries still-open lineages
without reposting them, leaves human-resolved findings suppressed, resolves an
owned finding only after an omission-free review explicitly proves it fixed,
and reopens a discussion only when Revoot resolved it and semantic review
confirms a recurrence. A moved finding is posted at its current anchor before an
open old thread is resolved; notes without trustworthy position metadata remain
untouched. Human and foreign-bot discussions are never mutated. GitLab
discussions and the owned description block are the durable state store; no
external Revoot state service is required.

The owned overview carries the last review checkpoint. It is an attention hint,
not authorization to omit code: merge-request descriptions are author-editable.
Revoot verifies local ancestry, derives the tree delta since the prior reviewed
head, and prioritizes those paths while preserving the complete merge-request
diff as scope. Incomplete coverage, policy changes, rewritten history, empty or
excessive deltas, and two consecutive incremental passes force full attention.
The checkpoint is written only after notes and resolution transitions converge.

The component marks review jobs interruptible and serializes publication per
merge request with a GitLab resource group. Revoot still rechecks the immutable
head and reacquires the discussion inventory before publication because
job-level serialization is not an atomic code-host transaction. A concurrent
reply, edit, resolution, or new discussion stops publication.

GitHub remains authoritative if the component project or fixture diverges. Do
not accept product source contributions, publish Revoot binaries, or build a
second container image from GitLab.

The canonical component template is maintained under `ci/gitlab/components` in
the GitHub repository. A component release copies that reviewed template into
the GitLab project's `templates/` directory and records the matching GHCR
digest. GitLab platform state—merge requests, tokens, and pipeline results—is
intentionally local to the fixture project.

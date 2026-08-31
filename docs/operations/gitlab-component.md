# GitLab CI/CD component

## Set up

Generate a version-pinned component include and add it to `.gitlab-ci.yml`:

```sh
REVOOT_IMAGE='ghcr.io/getrevoot/revoot:VERSION@sha256:DIGEST'
revoot init gitlab --image "$REVOOT_IMAGE"
```

Copy the digest from the matching
[GitHub release](https://github.com/getrevoot/revoot/releases) in
`image-digest.txt`. The component input rejects mutable tags.

Add either `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` as a masked CI/CD variable.
Provider and model default to `auto` and can be overridden through component
inputs.

## Publishing token

Revoot needs a write-capable token to create inline discussions, resolve its
old discussions, and update the merge-request summary. Create a project access
token with the `api` scope and at least the Developer role, then save it as a
masked CI/CD variable named `REVOOT_GITLAB_TOKEN`. GitLab attributes comments
to the project token's bot user.

`CI_JOB_TOKEN` can read merge-request data but cannot publish discussions. If
`REVOOT_GITLAB_TOKEN` is absent, the publishing job fails its readiness check.
GitLab.com project access tokens require Premium or Ultimate; on other plans,
use a dedicated bot user's personal access token with the `api` scope.

Do not expose either the provider key or publishing token to untrusted fork
pipelines. The component starts on merge-request pipelines so it can classify
the authoritative context; Revoot then skips fork merge requests by default
before provider or publication work.

## Job behavior

The job uses `.post`, which exists even when a project defines custom stages.
An empty `needs` list starts it alongside other jobs; pass job names through the
`needs` input to wait for checks. A pipeline with no ordinary-stage job does not
run `.post`, so a Revoot-only pipeline should set `stage` to `test`.

Review jobs are interruptible and publication is serialized per merge request.
Revoot also rechecks the head and discussions before writing, stopping if
either changed during review.

On later pushes, Revoot updates one summary and reconciles its existing inline
discussions. Resolved findings stay suppressed unless semantic review confirms
a recurrence. Human and other bot discussions may suppress duplicates but are
never modified. Embedded metadata identifies owned comments; GitLab remains
the state store.

## Component project

The component and its acceptance fixtures live at
[`gitlab.com/revoot/revoot-ci`](https://gitlab.com/revoot/revoot-ci). It is not a mirror of this Rust repository and does not build Revoot. Each component
release points to the matching image from the
[Revoot container package](https://github.com/getrevoot/revoot/pkgs/container/revoot).

GitHub remains authoritative for Revoot
[source](https://github.com/getrevoot/revoot),
[releases](https://github.com/getrevoot/revoot/releases), and container images.
The canonical component template is maintained in
[`ci/gitlab/components/review/template.yml`](https://github.com/getrevoot/revoot/blob/main/ci/gitlab/components/review/template.yml).

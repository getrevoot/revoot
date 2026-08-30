# Review-quality corpus

`public/` contains provider-independent scorer vectors. `scenarios/` contains
executable exact diffs plus complete checkout files, known defect positions,
clean silence cases, cross-file context, and an incremental resolution pair.
The standard suite strictly parses every diff, derives real opaque anchors,
inventories every checkout, and verifies the declared expectations.

Future held-out cases must live outside the repository and use the same
`revoot.evaluation-scenario/v1` contract so implementation work cannot tune
directly against their answers.

The public seed corpus spans Rust, TypeScript, Python, Go, Java, Terraform, and
SQL. Adversarial cases embed instructions in source comments and `REVOOT.md`;
those strings remain repository data and cannot redefine reviewer policy. The
optional live quality test applies aggregate precision, recall, category,
duplicate, and clean-silence thresholds.

Exact anchor/category identity determines recall and false positives. A clean
case passes only when the reviewer remains silent. Incremental revisions derive
new snapshot-bound anchors; publication fingerprints and reconciliation, not a
fiction of cross-head anchor stability, determine comment convergence.

# Provider conformance policy

Provider adapters share one provider-neutral contract. The product ships two:
Anthropic Messages and OpenAI Responses, both called directly over canonical
HTTPS. Bedrock, generic compatible endpoints, and model CLI adapters are out of
scope.

Every adapter must demonstrate:

- direct authenticated HTTPS with redirects and ambient proxies disabled;
- bounded request, response, header, and JSON handling, plus bounded recorded
  SSE normalization;
- user/assistant text, read-only tool definitions, tool calls, and tool results;
- batched and provider-parallel tool calls with deterministic result binding;
- response and streaming normalization into the shared model contract;
- reported and missing usage accounting, finish reasons, deadlines, and
  cooperative cancellation;
- payload-free authentication, permission, rate-limit, timeout, unavailable,
  malformed-response, and oversized-response errors; and
- no credential, prompt, tool payload, or raw response in Debug, Display,
  telemetry, or retained error state.

Recorded fixtures run in the standard suite. An optional credentialed smoke
test executes an exact tool-call/post-tool round trip through
`mise run test:providers:live`. Unknown model IDs never silently replace the
configured model.

The tool-first engine creates a fresh bounded request from the immutable group
brief, structured checkpoint, unresolved coverage, and most recent tool
exchange. Adapters must not require provider-side conversation storage,
`previous_response_id`, or a separate model summarization call. Missing or
ambiguous usage conservatively charges the full reservation to the exact
grouping, planning, review, verification, or adjudication phase.

Grouping is a single metadata-only, no-tools request when four or more files are
selected. Isolated review workers may use the bounded read-only tools. Group
verification is one no-tools request containing only prepared candidates and
their narrow cited evidence. Global adjudication receives only verified
candidates, group summaries, coverage, lineage state, omissions, and usage; it
cannot create a finding or change an anchor. Provider failures at grouping fall
back deterministically, worker failures produce partial coverage, verifier
failures suppress unverified candidates, and adjudicator failures rank already
verified candidates deterministically.

New adapters implement `revoot_core::provider::ProviderAdapter` and reuse the
shared request, response, usage, cancellation, and payload-free error types.
They must not add provider wire types to the agent or findings domains.
Adding another direct provider is a deliberate product decision and requires
the same recorded and live suites; repository configuration can never add an
adapter or endpoint.

## Streaming transport boundary

The direct runtime currently requests one bounded JSON response per call.
Anthropic requests explicitly set `stream: false`; OpenAI requests omit the
streaming option. The shared HTTP transport exposes a completely bounded
response body rather than an incremental event stream, so the recorded SSE
normalizers are conformance-tested but are not used by production calls.

Enabling live streaming requires a provider-neutral incremental transport
contract that preserves the existing total-body, per-event, event-count,
header, idle-timeout, deadline, cancellation, and payload-free error bounds.
It must also preserve conservative accounting when a request may have reached
the provider but the response stream is lost. Until that contract exists,
adapters must not silently enable provider streaming.

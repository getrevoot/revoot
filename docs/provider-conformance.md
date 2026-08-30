# Provider conformance policy

Provider adapters share one provider-neutral contract.

Every adapter must demonstrate:

- direct authenticated HTTPS with redirects and ambient proxies disabled;
- bounded request, response, header, JSON, and stream handling;
- user/assistant text, read-only tool definitions, tool calls, and tool results;
- response and streaming normalization into the shared model contract;
- usage accounting, finish reasons, deadlines, and cooperative cancellation;
- payload-free authentication, permission, rate-limit, timeout, unavailable,
  malformed-response, and oversized-response errors; and
- no credential, prompt, tool payload, or raw response in Debug, Display,
  telemetry, or retained error state.

Recorded fixtures run in the standard suite. An optional credentialed smoke
test executes an exact tool-call/post-tool round trip through
`mise run test:providers:live`. Unknown model IDs never silently replace the
configured model.

New adapters implement revoot_core::provider::ProviderAdapter and reuse the
shared request, response, usage, cancellation, and payload-free error types.
They must not add provider wire types to the agent or findings domains.

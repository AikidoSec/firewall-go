# AI usage monitoring

Zen can monitor AI usage by observing outbound `net/http` responses. This works
with SDKs using the standard HTTP transport and with direct HTTP calls, including
custom provider hosts, gateways, and proxy path prefixes.

Build your application with `zen-go` and call
`zen.Protect()` as described in the [installation instructions](../README.md#installation).
Capture is enabled automatically when Zen is loaded and not disabled.

## Supported responses

Only successful (HTTP 2xx) POST requests returning non-streaming JSON are captured:

- OpenAI-compatible chat completions (`/chat/completions`) and Responses (`/responses`), including Azure OpenAI and compatible providers such as Mistral.
- Anthropic Messages (`/v1/messages`) and Anthropic on Vertex AI (`/publishers/anthropic/models/...:rawPredict`).
- Gemini and Google Vertex AI (`/models/...:generateContent`).
- AWS Bedrock Converse (`/model/.../converse`) and Anthropic-compatible Invoke (`/model/.../invoke`).

The provider is reported as the request URL's origin (scheme, hostname, and port),
not an SDK provider name. Statistics include model, call count, input and output
tokens, and total input plus output tokens.
Gemini input includes tool-use prompt tokens; output includes reasoning tokens.
Model-only responses count as calls with zero tokens if usage is absent or invalid.

Statistics are included in the existing Aikido heartbeat. Configure `AIKIDO_TOKEN`
to send them to your dashboard. Prompts, generated content, request bodies,
URL credentials, query strings, and fragments are not reported.

## Limits

- Capture observes bytes only as your application reads the body; it does not read
  ahead or change the response bytes. Read bodies to completion and close them.
  Bodies closed early, read errors, malformed JSON, and oversized responses are discarded.
- Encoded and decoded bodies are each limited to 2 MiB. At most 1,000 distinct
  provider/model pairs are collected per heartbeat; existing pairs continue to aggregate.
- Identity, gzip, and zlib-wrapped deflate are supported, including Go's automatic
  gzip decompression. Other content encodings (including Brotli) are skipped.
- Streaming responses (SSE and AWS event streams), embeddings, and custom
  `RoundTripper` implementations not delegating to an instrumented `http.Client`
  with `*http.Transport` are not captured.
- Monitoring is disabled when Zen is disabled or has not loaded successfully.

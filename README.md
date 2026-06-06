# AgentTrust ID SDKs

Official client SDKs for [AgentTrust ID](https://agenttrust.id) — authentication, authorization, and runtime security for AI agents.

| Language | Install | Source | Docs |
|----------|---------|--------|------|
| Python | `pip install agenttrustid` | [python/](python/) | [SDK Guide](https://agenttrust.id/docs) |
| TypeScript | `npm install @agenttrustid/sdk` | [typescript/](typescript/) | [SDK Guide](https://agenttrust.id/docs) |
| Go | `go get github.com/agenttrustid/sdk/go` | [go/](go/) | [pkg.go.dev](https://pkg.go.dev/github.com/agenttrustid/sdk/go) |
| Java | Maven/Gradle `id.agenttrust:agenttrustid` | [java/](java/) | [SDK Guide](https://agenttrust.id/docs) |
| Rust | `cargo add agenttrustid` | [rust/](rust/) | [docs.rs](https://docs.rs/agenttrustid) |

Every SDK covers the same core surface: agent registration, opaque token issue/introspect/revoke, pre-flight action checks through Fast Guard, and telemetry reporting. Each directory has its own README with a quick start and full API reference.

## Versioning

SDKs are versioned independently with per-language tags: `python/v0.3.0`, `typescript/v0.3.0`, `go/v0.3.0`, `java/v0.3.0`, `rust/v0.3.0`. Go consumers resolve the `go/vX.Y.Z` tags automatically via the module path.

## License

Apache License 2.0 — see the LICENSE file in each SDK directory.

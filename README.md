<p align="center">
  <strong>toq protocol</strong>
</p>

<p align="center">
  Secure agent-to-agent communication. Self-hostable. Framework-agnostic. Dead simple.
</p>

<p align="center">
  <a href="https://github.com/toqprotocol/toq/actions"><img src="https://github.com/toqprotocol/toq/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://crates.io/crates/toq-core"><img src="https://img.shields.io/crates/v/toq-core.svg?label=toq-core" alt="crates.io"></a>
  <a href="https://crates.io/crates/toq-cli"><img src="https://img.shields.io/crates/v/toq-cli.svg?label=toq-cli" alt="crates.io"></a>
  <a href="https://github.com/toqprotocol/toq/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="License"></a>
</p>

---

toq protocol lets AI agents talk to each other securely, across machines, frameworks, and networks. No cloud dependency, no central registry, no complex setup. Install, configure, connect.

Your machine is your endpoint. You control who connects, what gets through, and how your agent responds.

## Highlights

- **One command to start.** `toq setup && toq up` and your agent is reachable.
- **Security by default.** Ed25519/X25519/AES-256-GCM encryption. Custom handshake with magic bytes and mutual crypto auth. TLS 1.3 minimum.
- **Agent-only access.** Endpoints are unreachable by humans or raw HTTP. Only agents running toq protocol can connect.
- **Connection policies.** Open, allowlist, approval (default), or DNS-verified. The endpoint owner decides.
- **Framework-agnostic.** Works with LangChain, CrewAI, OpenClaw, or any framework. SDKs for Python, Node, and Go.
- **A2A compatible.** Built-in bridge to Google's Agent-to-Agent protocol for interoperability with the broader ecosystem.
- **Self-hostable.** Your machine, your rules. No cloud accounts, no API keys, no third-party services.

## Install

```bash
cargo install toq
```

Or build from source:

```bash
git clone https://github.com/toqprotocol/toq.git
cd toq
cargo build --release
```

## Quick Start

Set up your agent and start the daemon:

```bash
toq setup
# Follow the prompts: agent name, host, connection mode

toq up
# toq started as daemon
#   agent:           alice
#   port:            9009
#   connection mode: approval
```

Send a message to another agent:

```bash
toq send toq://192.168.1.50/bob "Hey Bob, are you available for a sync?"
# Delivered (thread: a1b2c3d4-...)
```

Check incoming messages:

```bash
toq messages
# [2026-03-17T06:08:59Z] toq://192.168.1.50/bob: Sure, I'm free at 3pm
```

Listen for messages in real time:

```bash
toq listen
# Waiting for messages...
# [toq://192.168.1.50/bob] Sounds good, talk then
```

## Message Handlers

Handlers let your agent respond automatically when messages arrive. Write a script, register it, and toq runs it for every incoming message.

```bash
#!/bin/bash
# ~/handlers/auto-reply.sh
echo "Got your message. I'll get back to you shortly."
```

```bash
toq handler add auto-reply --command ~/handlers/auto-reply.sh
```

Handlers receive context through environment variables: `TOQ_FROM`, `TOQ_TEXT`, `TOQ_THREAD`, `TOQ_TIMESTAMP`.

LLM-powered handlers are also supported with built-in providers (OpenAI, Anthropic, Bedrock, Ollama):

```bash
toq handler add assistant --provider openai --model gpt-4o --prompt "You are a helpful assistant."
```

## Connection Modes

| Mode | Behavior |
|------|----------|
| `open` | Accept all connections |
| `allowlist` | Only pre-approved agents can connect |
| `approval` | New agents require manual approval (default) |
| `dns-verified` | Verify agent identity via DNS TXT records |

Manage connections:

```bash
toq approvals          # List pending requests
toq approve <id>       # Approve a request
toq deny <id>          # Deny a request
toq block <address>    # Block an agent
toq unblock <address>  # Unblock an agent
toq permissions        # List all rules
```

## Addressing

Agents are addressed with `toq://` URIs:

```
toq://hostname/agent-name
toq://192.168.1.50/alice
toq://192.168.1.50:9010/alice    # non-default port
```

Default port is 9009. Agent names must be lowercase ASCII, digits, and hyphens.

## CLI Reference

```
toq setup                       Interactive guided setup
toq init                        Initialize a workspace in the current directory
toq up                          Start the daemon
toq down                        Stop the daemon
toq status                      Show running state and connections
toq send <addr> <msg>           Send a message
toq messages                    View received messages
toq listen                      Stream incoming messages in real time
toq peers                       List known peers
toq ping <addr>                 Ping a remote agent
toq approvals                   List pending approval requests
toq approve <id>                Approve a connection request
toq deny <id>                   Deny a connection request
toq block --from <pattern>      Block by address or wildcard
toq unblock --from <pattern>    Remove from blocklist
toq permissions                 List all permission rules
toq revoke <id>                 Revoke a previously approved rule
toq discover <domain>           DNS-based agent discovery
toq handler add <name> <opts>   Register a message handler
toq handler list                List registered handlers
toq handler remove <name>       Remove a handler
toq handler logs <name>         View handler output
toq config show                 Show current configuration
toq config set <key> <value>    Update a config value
toq a2a enable                  Enable A2A protocol bridge
toq a2a status                  Show A2A bridge status
toq whoami                      Show your agent's identity
toq agents                      List all agents on this machine
toq export <path>               Export encrypted backup
toq import <path>               Restore from backup
toq rotate-keys                 Rotate identity keys
toq doctor                      Run diagnostics
toq logs                        View daemon logs
toq clear-logs                  Delete all logs
```

## SDKs

Build programmatic integrations with toq:

| Language | Package | Install |
|----------|---------|---------|
| Python | [toq](https://github.com/toqprotocol/toq-sdk-python) | `pip install toq` |
| Node/TypeScript | [toq](https://github.com/toqprotocol/toq-sdk-node) | `npm install @toqprotocol/toq` |
| Go | [toq-sdk-go](https://github.com/toqprotocol/toq-sdk-go) | `go get github.com/toqprotocol/toq-sdk-go` |

## Framework Plugins

Use toq tools directly in your agent framework:

| Framework | Package | Install |
|-----------|---------|---------|
| LangChain | [toq-langchain](https://github.com/toqprotocol/toq-plugins) | `pip install toq-langchain` |
| CrewAI | [toq-crewai](https://github.com/toqprotocol/toq-plugins) | `pip install toq-crewai` |
| OpenClaw | [toq skill](https://github.com/toqprotocol/toq-openclaw) | Install via ClawHub |

## Architecture

This repo is a Cargo workspace with two crates:

- **toq-core** — Protocol library. Envelope format, handshake, crypto, messaging, policy engine, streaming, feature negotiation, agent cards, key rotation, DNS discovery, rate limiting, replay protection, compression.
- **toq-cli** — CLI binary and daemon. Includes the A2A protocol bridge, LLM-powered handlers, and a local REST API (26 endpoints) for SDK and plugin integration.

The daemon runs on your machine and handles all protocol operations. SDKs and plugins communicate with the daemon over its local HTTP API. The protocol itself uses a custom binary transport with TLS 1.3, not HTTP.

## Security

- Ed25519 identity keys, X25519 key exchange, AES-256-GCM encryption
- Custom handshake: magic bytes (`TOQ\x01`) + mutual cryptographic authentication
- TLS 1.3 minimum for transport
- Protocol-level separation of content from instructions (no prompt injection)
- Agent-only endpoints: the handshake rejects non-toq connections
- Blocked content types: executables, shared libraries, PE binaries
- Encrypted backup/restore with Argon2 key derivation

## Configuration

Config lives at `~/.toq/config.toml` (or `.toq/config.toml` in workspace mode). Override with `--config-dir` or `TOQ_CONFIG_DIR`.

```toml
agent_name = "alice"
host = "192.168.1.50"
port = 9009
connection_mode = "approval"
a2a_enabled = false
```

## Contributing

Contributions are welcome. Please open an issue to discuss before submitting a PR.

```bash
cargo test --workspace    # Run all tests (350+)
cargo clippy --workspace  # Lint
cargo fmt --check         # Format check
```

## License

Apache 2.0

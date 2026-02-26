---
# Cartouche v1
title: "cpp-holons — C++ SDK for Organic Programming"
author:
  name: "B. ALTER"
created: 2026-02-12
revised: 2026-02-13
access:
  humans: true
  agents: false
status: draft
---
# cpp-holons

**C++ SDK for Organic Programming** — header-only transport/identity core
with native Holon-RPC client support.

## Build & Test

```bash
clang++ -std=c++20 -pthread -I include -I /opt/homebrew/include test/holons_test.cpp -o test_runner && ./test_runner
```

## API surface

| Symbol | Description |
|--------|-------------|
| `holons::scheme(uri)` | Extract transport scheme |
| `holons::parse_uri(uri)` | Parse transport URI into normalized fields |
| `holons::listen(uri)` | Create listener variant (`tcp_listener`, `unix_listener`, `stdio_listener`, `mem_listener`, `ws_listener`) |
| `holons::accept(listener)` | Accept one runtime connection (`tcp`, `unix`, `stdio`, `mem`) |
| `holons::mem_dial(listener)` | Dial client-side `mem://` connection |
| `holons::conn_read(conn, buf, n)` | Read bytes from a runtime connection |
| `holons::conn_write(conn, buf, n)` | Write bytes to a runtime connection |
| `holons::close_connection(conn)` | Close runtime connection FDs |
| `holons::close_listener(listener)` | Close and cleanup listener resources |
| `holons::parse_flags(args)` | CLI arg extraction |
| `holons::parse_holon(path)` | HOLON.md YAML parser |
| `holons::holon_rpc_client` | `connect(url)`, `invoke(method, params)`, `register_handler(method, fn)`, `close()` |
| `holons::kDefaultURI` | Default transport URI |

## Transport support

| Scheme | Support |
|--------|---------|
| `tcp://<host>:<port>` | Bound socket (`tcp_listener`) |
| `unix://<path>` | Bound UNIX socket (`unix_listener`) |
| `stdio://` | Native runtime accept (single-connection semantics) |
| `mem://` | Native in-process transport (`mem_dial` + `accept`) |
| `ws://<host>:<port>` | Listener metadata (`ws_listener`) |
| `wss://<host>:<port>` | Listener metadata (`ws_listener`) |

## Parity Notes vs Go Reference

Implemented parity:

- URI parsing and listener dispatch semantics
- Runtime accept path for `tcp`, `unix`, `stdio`, and `mem`
- In-process memory transport with explicit client/server ends (`mem_dial` + `accept`)
- Holon-RPC client protocol support over `ws://` (JSON-RPC 2.0, heartbeat, reconnect, server-initiated calls)
- Standard serve flag parsing
- HOLON identity parsing

Not yet achievable in this header-only runtime (justified gaps):

- `wss://` Holon-RPC client support:
  - Requires TLS/WebSocket client dependencies (for example OpenSSL + Beast), intentionally excluded from this minimal header-only SDK.
- `ws://` / `wss://` runtime listener parity:
  - This SDK currently exposes ws/wss as metadata only.
  - A full Go-style WebSocket listener for gRPC would require additional HTTP/WebSocket runtime dependencies, which are intentionally excluded to keep this SDK zero-dependency.
- Full gRPC transport parity (`Dial("tcp://...")`, `Dial("stdio://...")`, `Listen("stdio://...")`, and `Serve.Run()` wiring):
  - Not present yet; requires a dedicated C++ gRPC integration layer beyond this header-only core.

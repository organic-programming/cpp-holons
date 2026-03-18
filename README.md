# cpp-holons

**C++ SDK for Organic Programming** — header-first transport,
identity, discovery, connect, serve, and Holon-RPC utilities.

## Build & Test

```bash
clang++ -std=c++20 -pthread -I include -I /opt/homebrew/include test/holons_test.cpp -o test_runner && ./test_runner
```

POSIX shortcut:

```bash
make test
```

With `grpc++`, `protobuf`, and `grpc_cpp_plugin` available, CMake also exposes:

```bash
cmake -S . -B build
cmake --build build --target cpp_echo_server
```

The bundled codegen step emits `*.pb.*` and `*.grpc.pb.*` into `build/generated/`.

## API surface

| Symbol | Description |
|--------|-------------|
| `holons::scheme(uri)` | Extract transport scheme |
| `holons::parse_uri(uri)` | Parse transport URI into normalized fields |
| `holons::listen(uri)` | Create a listener variant |
| `holons::accept(listener)` | Accept one runtime connection |
| `holons::parse_flags(args)` | CLI arg extraction |
| `holons::parse_holon(path)` | `holon.proto` parser |
| `holons::discover(root)` | Discover holons under a root |
| `holons::discover_local()` | Discover from the current working directory |
| `holons::discover_all()` | Discover from local, `$OPBIN`, and cache roots |
| `holons::find_by_slug(slug)` | Resolve a holon by slug |
| `holons::find_by_uuid(prefix)` | Resolve a holon by UUID prefix |
| `holons::connect(target)` | Dial a direct target or auto-start a holon by slug |
| `holons::disconnect(channel)` | Stop any process started by `connect()` |
| `holons::channel_target(channel)` | Read the resolved direct target for a connected channel |
| `holons::serve::parse_flags(args)` | Parse repeated `--listen` / `--port` flags |
| `holons::serve::start(listeners, register_fn)` | Build and start a gRPC server |
| `holons::serve::serve(listeners, register_fn)` | Run until SIGTERM/SIGINT then gracefully shut down |
| `holons::holon_rpc_client` | Holon-RPC client |

## Current scope

- Runtime transports: `tcp://`, `unix://`, `stdio://`
- `ws://` and `wss://` are metadata-only at the transport layer
- Discovery scans local, `$OPBIN`, and cache roots
- `connect()` supports direct targets and slug-based startup on POSIX and Windows
- POSIX `stdio://` gRPC transport uses a direct socketpair/FD path when grpc++ exposes the POSIX FD APIs
- `serve.hpp` supports `tcp://`, `unix://`, and `stdio://` listeners
- Bundled protos under `protos/` can be code-generated with CMake
- Sample C++ holon source lives at `examples/echo_server.cpp`

## Current gaps vs Go

- `stdio://` serving requires grpc++ POSIX FD support; on platforms without it, serving over stdio is unavailable.
- Full grpc++ verification requires the local machine to provide `grpc++`, `protobuf`, and `grpc_cpp_plugin`.
- gRPC service stubs are generated at build time rather than committed as a prebuilt SDK surface.
- Holon-RPC remains a websocket JSON-RPC transport; this SDK still does not expose a separate gRPC Holon-RPC server module.

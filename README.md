# cpp-holons

**C++ SDK for Organic Programming** — header-only transport,
identity, discovery, and Holon-RPC client utilities.

## Build & Test

```bash
clang++ -std=c++20 -pthread -I include -I /opt/homebrew/include test/holons_test.cpp -o test_runner && ./test_runner
```

POSIX shortcut:

```bash
make test
```

## API surface

| Symbol | Description |
|--------|-------------|
| `holons::scheme(uri)` | Extract transport scheme |
| `holons::parse_uri(uri)` | Parse transport URI into normalized fields |
| `holons::listen(uri)` | Create a listener variant |
| `holons::accept(listener)` | Accept one runtime connection |
| `holons::mem_dial(listener)` | Dial the client side of a `mem://` listener |
| `holons::parse_flags(args)` | CLI arg extraction |
| `holons::parse_holon(path)` | `holon.yaml` parser |
| `holons::discover(root)` | Discover holons under a root |
| `holons::discover_local()` | Discover from the current working directory |
| `holons::discover_all()` | Discover from local, `$OPBIN`, and cache roots |
| `holons::find_by_slug(slug)` | Resolve a holon by slug |
| `holons::find_by_uuid(prefix)` | Resolve a holon by UUID prefix |
| `holons::connect(target)` | Dial a direct target or auto-start a holon by slug |
| `holons::disconnect(channel)` | Stop any process started by `connect()` |
| `holons::channel_target(channel)` | Read the resolved direct target for a connected channel |
| `holons::holon_rpc_client` | Holon-RPC client |

## Current scope

- Runtime transports: `tcp://`, `unix://`, `stdio://`, `mem://`
- `ws://` and `wss://` are metadata-only at the transport layer
- Discovery scans local, `$OPBIN`, and cache roots
- `connect()` supports both direct targets and slug-based startup on POSIX

## Current gaps vs Go

- No full gRPC `serve` lifecycle helper yet.
- No Holon-RPC server module yet.
- No generated service-specific client bindings; recipes still own RPC wiring.

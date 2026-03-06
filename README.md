# Reticulum-rs

A Rust implementation of the [Reticulum Network Stack](https://reticulum.network/), targeting protocol compatibility with the [Python reference implementation](https://github.com/markqvist/Reticulum).

> **WARNING: This code has NOT been security reviewed and CANNOT be trusted for
> production use.** If you need Reticulum, use the
> [Python implementation](https://github.com/markqvist/Reticulum). If you want
> to experiment with or contribute to a Rust implementation, also consider the
> [upstream fork](https://github.com/BeechatNetworkSystemsLtd/Reticulum-rs)
> this project was originally based on.

## Background

This project began as an experiment to see what an AI coding assistant (Claude Code) could produce when left unsupervised in a loop to port software from one language to another, given a protocol specification and reference implementation for concrete feedback. The large majority of the code was written this way.

The initial results were not great. Since then, both the methods and the tooling have improved significantly. A mostly-working [lxmf-rs](https://github.com/splee/lxmf-rs) library has been built on top of this crate with a strong end-to-end interoperability test suite using Docker, so for the areas of the Reticulum protocol that LXMF uses, the functionality and wire protocol appear compatible with the Python implementation.

That said, much of the original AI-generated code is still in place, and **no security audit has been performed**. Given that Reticulum's design goals place a strong emphasis on security and privacy, this is a serious gap. There are no guarantees that this code is secure or bug-free.

## Status

- Protocol compatibility with the Python implementation has been validated for the subset of features used by LXMF (announcements, links, resources, packets)
- Integration tests verify interoperability by running both Python and Rust implementations side by side
- CLI tools (`rnsd`, `rnstatus`, `rnpath`, `rnid`, `rnprobe`) are implemented to match their Python equivalents
- TCP interface is the primary transport; UDP and serial interfaces exist but are less tested

## Building

Requires Rust edition 2021+ and `protoc` (for compiling `.proto` files used by the Kaonic/gRPC transport).

```bash
cargo build --release
```

## Testing

```bash
# Unit tests
cargo test --lib

# Integration tests (requires Python Reticulum installed)
cargo test --test integration

# All tests
cargo test
```

[cargo-nextest](https://nexte.st/) is recommended for faster test runs:

```bash
cargo nextest run --fail-fast
```

## CLI Tools

| Binary     | Description                      |
|------------|----------------------------------|
| `rnsd`     | Reticulum daemon                 |
| `rnstatus` | Network status                   |
| `rnpath`   | Path discovery                   |
| `rnid`     | Identity management              |
| `rnprobe`  | Network probing                  |
| `rncp`     | File transfer                    |
| `rnx`      | Remote command execution         |

## License

MIT - see [LICENSE](LICENSE).

Originally based on work by [Beechat Network Systems Ltd.](https://beechat.network/)

# SideSwap Rust Sources

This repository contains **`sideswap_rust`**, a Rust library and toolkit for interacting with [SideSwap](https://sideswap.io/),
a service and platform operating on Liquid (a Bitcoin sidechain).
It provides functionality for building, signing, and managing Liquid-based transactions and swaps.

## Components

- **[Dealers](docs/dealer.md)**: Self-hosted programs (market makers) that provide liquidity on SideSwap markets.
- **[SideSwap Manager](sideswap_manager)**: A self-hosted program for managing Liquid Bitcoin assets.
- **[SideSwap Swap Protocol](docs/protocol.md)**: Technical documentation describing the swapping mechanism.
- **[API Reference](https://sideswap.io/docs/)**: Official SideSwap documentation and references.

## Getting Started

1. **Installation**: Add `sideswap_rust` as a dependency in your Rust project's `Cargo.toml`, or clone this repository and build from source using `cargo build`.
2. **Usage**: Refer to the [API reference](https://sideswap.io/docs/) and the internal documentation (e.g., in `docs/`) for examples on creating and signing transactions, performing swaps, or running a dealer.

For more detailed information, consult the individual component documentation linked above.

# Contributing

Thanks for your interest in contributing to Taproot.

## Development setup

Install the stable Rust toolchain. On Ubuntu or another Debian-based Linux distribution, install the FUSE development headers and `pkg-config` used by the CI workflow:

```bash
sudo apt-get update
sudo apt-get install -y libfuse3-dev pkg-config
```

## Checks

Before opening a pull request, run the same core checks as CI from the repository root:

```bash
cargo fmt --check
cargo clippy -- -D warnings
cargo test --locked
cargo build --locked
```

Add or update tests when changing behavior. Keep changes focused, and include a short description of the behavior changed and the checks you ran in your pull request.

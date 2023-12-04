#!/bin/bash
cargo clean
RUST_LOG=info cargo run --bin server

# second option:
# cargo build --release
# ./target/release/server

# third option:
# cargo build --release --bin server
# cargo install --bin server path .
# server
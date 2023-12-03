#!/bin/bash
cargo run --bin client -- --url "http://127.0.0.1:8080/"

# second option:
# cargo build --release
# ./target/release/client

# third option:
# cargo build --release --bin client
# cargo install --bin client --path .
# client --url "http://127.0.0.1:8080/"


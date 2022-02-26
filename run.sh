#!/usr/bin/env zsh -f
export RUST_LOG="kt=trace"
cargo run -- "$@"
#!/usr/bin/env zsh -f
export RUST_LOG="kt=trace"

cargo run -q -- show --in test_data/rsa-2048-private-pk8.der
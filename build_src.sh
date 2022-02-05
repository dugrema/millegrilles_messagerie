#!/usr/bin/env bash

echo "Build target rust"
cargo b --release --package millegrilles_messagerie --bin millegrilles_messagerie

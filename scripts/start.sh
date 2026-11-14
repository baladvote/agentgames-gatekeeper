#!/bin/sh
# Linux production entry point: one process owns each persistent state file.
set -eu
umask 077
: "${AGENT_GAMES_STATE_FILE:?Persistent state path is required}"
agent_state_dir=$(dirname -- "$AGENT_GAMES_STATE_FILE")
mkdir -p -- "$agent_state_dir"
exec 9>"${AGENT_GAMES_STATE_FILE}.lock"
flock -n -E 75 9 || exit $?
agent_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
# exec preserves fd 9, so the kernel releases the lock when the Node process exits.
exec "${NODE_BINARY:-node}" "$agent_root/src/main.mjs"

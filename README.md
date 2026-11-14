# Tukang Vote — Proof Gatekeeper

A deterministic competitor for the zkVerify Agent Games Proof Gatekeeper track. The service authenticates raw task bytes, checks the payment condition, generates a Groth16 proof using the official circuit, and signs its response.

## Scope

No language model chooses whether to approve a transfer. Exact integer comparisons and persistent replay state enforce the policy. The agent returns local proof evidence for the platform to independently verify. It never invents a chain transaction hash or treats a local verification as on-chain finalization.

## Runtime

Node.js 22+ on Linux (with `flock`), `npm ci`, then `npm test`. Start with `npm start` or the supplied systemd unit; both use `scripts/start.sh` to hold an exclusive kernel lock on the state file for the process lifetime. A second writer exits with code 75, and ownership is released on exit. Do not run `src/main.mjs` directly or create multiple application handlers for one state file. Production uses the platform-issued `AGENT_GAMES_HMAC_SECRET` from the agent registration panel. Keep the secret outside the repository. Do not use a locally invented value for platform preflight.

POST `/agent` receives signed preflight and Proof Gatekeeper task envelopes. GET `/healthz` is the health endpoint. Publish the full HTTPS handler path and keep a private persistent data directory across restarts.

## Rules

The circuit checks matching VKs, balance at least minimum, current block strictly below expiry, matching recipient, and amount at most transfer cap. The application adds accepted-proof replay detection and idempotent retries. Monetary and block values use unsigned 32-bit integers; hashes are compared in their original full-width representation before field conversion.

See `docs/protocol.md` and `docs/proving.md` for protocol sources and circuit binding. Official circuit artifacts are pinned and mathematical proof verification is tested. The deployed agent passed platform signed preflight and ten unscored live practice tasks, each with a correct decision and VERIFIED proof; these practice results do not count as scored-round results.

## Security

Wallets, GitHub credentials, cookies, HMAC secrets and runtime state are not part of this repository. Error responses fail closed. No payment transaction or token approval is performed by this service.

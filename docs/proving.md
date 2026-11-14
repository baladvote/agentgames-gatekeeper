# Local Groth16 proving

`src/prover.mjs` exports:

- `proveTask(envelope, decision)`: returns a promise for `{ proof, public_signals }` after checking task binding and verifying the generated Groth16 proof locally.
- `expectedPublicInputs(envelope, decision)`: returns the twelve canonical decimal public inputs, excluding the private-salt commitment output. This helper validates encoding; `proveTask` additionally checks that the requested decision is provable.
- `closeProver()`: waits for earlier queued operations, releases the cached curve, and allows a later call to initialize a new curve. Use at shutdown or test teardown, not after each request.

`decision` must be exactly `APPROVE` or `REJECT`. The prover has no policy-module dependency, network calls, replay state, or transaction submission. `input.proof_tx` is optional and is not a circuit input; the returned evidence never invents a `proof_tx`. Authentication, envelope type/timestamps, deadlines, replay, request admission and signing belong to the caller.

## Exact task and field encoding

The original `task_id` must be at most 160 characters and end in a UUID with the shape `8-4-4-4-12` hexadecimal digits, preceded by `_` or the start of the identifier. Validation happens **before** removing hyphens. Trailing whitespace/newlines, incomplete UUIDs, misplaced hyphens, unsupported placeholder IDs and directly concatenated prefixes reject. The accepted UUID shape follows the organizer reference, without adding UUID-version restrictions.

After validation:

```js
BigInt('0x' + task_id.slice(-36).replaceAll('-', ''))
```

For example, `gk_practice_12345678-1234-4abc-8def-1234567890ab` encodes as `24197857161011659757068287043102609579`. Prefixes are not hashed. Textual IDs with the same UUID suffix have the same circuit `taskId`; full task-ID uniqueness remains an external replay check.

The BN254 scalar modulus is:

```text
21888242871839275222246405745257275088548364400416034343698204186575808495617
```

VK tokens are validated as `0x`/`0X` plus 1–64 hex digits. Recipients must have the complete 40 hex digits of a 20-byte address. Equality compares integer values, so case and leading hash zeroes do not change identity. Only the circuit encoding reduces VK values modulo the field; approval additionally requires equality of the original full VK integers. A VK mismatch that aliases modulo the field cannot produce a rejection proof unless another circuit condition fails. Such a task must never be approved just because the reduced hashes match.

`minimum`, `public_balance`, `expiry_block`, `current_block`, `amount`, and `max_transfer` must be unsigned 32-bit values. The local adapter accepts decimal digit strings (including leading zeroes, bounded to 1024 characters) or safe integer numbers. It rejects coercible objects, BigInt input values, negatives, fractions, exponent/hex notation, whitespace, and values above `4294967295` before any field reduction. This adapter is intentionally compatible with the local policy's numeric representation; it does not require the narrower string-versus-number split in the reference's transport schema.

The public signal order is:

| Index | Signal |
| ---: | --- |
| 0 | `Poseidon([salt, taskId])`, circuit commitment output |
| 1 | `registeredVkHash` |
| 2 | `proofVkHash` |
| 3 | `minimum` |
| 4 | `publicBalance` |
| 5 | `expiryBlock` |
| 6 | `currentBlock` |
| 7 | `recipient` |
| 8 | `conditionRecipient` |
| 9 | `amount` |
| 10 | `maxTransfer` |
| 11 | `decision`: 1 for APPROVE, 0 for REJECT |
| 12 | UUID-derived `taskId` |

Every returned signal must be a canonical decimal field element. Indices 1–12 must exactly match the snapshot of the validated task taken when `proveTask` is called. Signal 0 is constrained by the circuit and verified with the proof; it is not an independently prescribed envelope value. A fresh local `randomBytes(32)` salt is reduced modulo the field for each proof. The salt and witness are not logged, returned, or written to disk.

## Circuit and runtime limits

Approval requires matching VK fields, `publicBalance >= minimum`, **`expiryBlock > currentBlock`**, matching recipient fields, and `amount <= maxTransfer`. Expiry equality requires REJECT. A wrong decision fails before witness generation. The circuit only constrains differences in its 32-bit comparators, so external bounds on all six operands are necessary. It has no `amount <= publicBalance` condition.

A rejection caused solely by replay, authentication, wall-clock deadline, or another external policy check is not necessarily provable: if all five circuit predicates pass, a REJECT witness cannot be generated. The caller must handle that failure rather than attach an approval proof to a rejection response.

The implementation uses `snarkjs@0.7.6` and `ffjavascript@0.3.1`. It initializes `buildBn128(true)` once and assigns the curve to `globalThis.curve_bn128`. The default snarkjs curve lookup then reuses that single-thread instance for proving and verification. Passing `{ singleThread: true }` on every proving call would bypass this ffjavascript cache and rebuild a curve each time, so the cached path deliberately omits that option. Witness generation uses `{ memorySize: 128 }` in WebAssembly pages.

Proofs and shutdown are serialized to protect shared curve state and make cold-start shutdown reliable. Validation occurs before queueing, and only validated decimal snapshots are queued. The caller should bound accepted concurrent requests and enforce deadlines; this module is not a cancellable worker or an admission controller. Applications should not independently replace or terminate the shared BN128 cache while proofs run.

## Artifacts and provenance

`circuits/` contains only the unmodified official WASM, proving key, and the verification key previously exported from that proving key. The copy was hash-checked against `circuit-research/research-artifact-manifest.json`; the tests also freshly export the verification key and compare it with the bundled JSON.

| Artifact | SHA-256 |
| --- | --- |
| `gatekeeper.wasm` | `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `gatekeeper_final.zkey` | `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `verification_key.json` | `7ed1cbaa8e77f7bd68f471ef571e3e2cc7b15ab754a158f80c785249bc8b39e7` |

Original artifact sources:

- <https://agentgames.zkverify.io/circuits/gatekeeper.wasm>
- <https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey>

UUID encoding, envelope-to-witness mapping and public input order were checked against the organizer account's public [proof-gatekeeper-reference](https://github.com/smilewithkhushi/proof-gatekeeper-reference) at commit `b1656fb50fe4e3252f1e26dd28d04e99a23d2154`, specifically [src/protocol.ts](https://github.com/smilewithkhushi/proof-gatekeeper-reference/blob/b1656fb50fe4e3252f1e26dd28d04e99a23d2154/src/protocol.ts), [README.md](https://github.com/smilewithkhushi/proof-gatekeeper-reference/blob/b1656fb50fe4e3252f1e26dd28d04e99a23d2154/README.md), and [docs/protocol-notes.md](https://github.com/smilewithkhushi/proof-gatekeeper-reference/blob/b1656fb50fe4e3252f1e26dd28d04e99a23d2154/docs/protocol-notes.md). That repository attributes the encoding to the platform's `lib/gatekeeper/traps.ts` and public-signal reduction to `lib/zk/verify-proof.ts`. This resolves the older research directory's previously unresolved textual task-ID encoding; that directory remains a historical research snapshot.

**License/provenance note:** The referenced commit has no tracked LICENSE file and its package manifest declares no license. It is cited as protocol implementation evidence; this project does not assert that it is MIT-licensed or that public availability grants a redistribution license. The local prover is an implementation of the observed protocol behavior, not a vendored copy of that service. The official circuit downloads likewise carry no license declaration in these downloaded files. Installed `snarkjs` and `ffjavascript` package manifests declare `GPL-3.0`; their upstream license files remain in the installed packages.

## Verification

From the project root:

```sh
/root/apps/runtime/node22/bin/node --test test/prover.test.mjs
```

Tests generate real approval and rejection proofs against these artifacts. Coverage includes every stateless trap, strict expiry equality, uint32 and full-address boundaries, malformed UUIDs, wrong decisions, full-VK field aliases, changed public signals, fresh salt commitments, concurrent calls, snapshot binding, and curve lifecycle. The tests do not mock proof generation, invent transaction hashes, or submit to a chain.

The parent integration run subsequently verified this implementation against actual platform practice: **10/10 decisions were CORRECT with proof VERIFIED**. This confirms the UUID-to-`taskId` mapping through live platform acceptance, in addition to the local proof tests. No practice logs or task identifiers are reproduced here; platform proof verification is not a claim of an on-chain transaction or finalization.

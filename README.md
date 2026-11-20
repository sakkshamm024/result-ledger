# Result Ledger: tamper-proof exam results (Code Fuzion H8)

Every published mark is hashed into an append-only, signed ledger. Students verify a result from the QR on their marksheet, and any change leaves a visible, signed trail.

## Run
```
npm install
npm start          # prints three admin tokens (a1, a2, a3). Open http://localhost:3000
npm test           # 18 attack-style checks
```
Needs Node 22.13+ (uses built-in `node:sqlite` and `crypto`). Only dependency: `qrcode`.

## How it works
1. **Canonical record.** `['v1', batch, student_id, course, marks, version, supersedes, reason, approvals]` as fixed-order JSON, so field order never changes a hash.
2. **Merkle tree per batch.** Leaf = SHA-256(0x00 ‖ record), node = SHA-256(0x01 ‖ left ‖ right). Unpaired nodes are promoted, never duplicated.
3. **Hash chain.** Each batch header holds the previous head hash; the head is signed with Ed25519 (the ledger key).
4. **Checkpoints outside the database.** Each signed head plus its leaf hashes is appended to `data/checkpoints.jsonl` and served at `/api/checkpoints`. In production publish this file to a public repo or object store.
5. **Corrections.** Never overwrite. A new record (version+1) links to the old leaf, carries a reason and needs signatures from two distinct admins over `SHA-256(student, course, marks, reason, supersedes)`. The old version stays and is shown as superseded.
6. **QR.** Encodes a URL with student, course and the leaf hash. The verify page recomputes the leaf and Merkle path in the browser and compares the root with the signed checkpoint. A QR whose hash matches no issued result is flagged as forged.
7. **Audit** (`/api/audit`). Recomputes everything from the rows and compares with the external checkpoints. It reports the exact batch, row and reason for edits, deleted rows, inserted rows, forged leaf hashes, broken chain links and invalid approvals.

## Attacks covered in `test.js`
Forged marks · forged QR · publish without token · duplicate publish · correction with one approval · same admin approving twice · correction without reason · direct SQL edit · edit plus forged leaf hash · deleted row · inserted row.

## Known limits (be honest in the demo)
- Admin keys live on the server for the demo; production should sign on each admin's own device or HSM.
- Ed25519 signatures are verified by the server and auditor, not yet in the browser.
- An attacker who controls both the database and the checkpoint file can rewrite history, so the checkpoint file must be published somewhere they cannot reach.
- `node:sqlite` storage needs a persistent disk (Render, Railway, Fly). Vercel's filesystem is ephemeral, so Vercel would need Postgres instead.

## AI-use declaration (fill in)
Tool(s): ______  Parts generated with AI: ______  Parts written by hand: ______

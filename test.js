const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path');
const { DatabaseSync } = require('node:sqlite');
const { start } = require('./server'), L = require('./lib/ledger');

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'h8-')), srv = await start(0, dir);
  const base = `http://localhost:${srv.address().port}`, T = Object.fromEntries(Object.entries(srv.keys.admins).map(([k, v]) => [k, v.token]));
  const call = async (p, body, tok) => { const r = await fetch(base + p, { method: body ? 'POST' : 'GET', headers: { 'x-token': tok || '', 'content-type': 'application/json' }, body: body && JSON.stringify(body) }); return { s: r.status, j: await r.json() }; };
  let n = 0; const ok = (name, fn) => { fn(); console.log('PASS', ++n, name); };

  // Merkle unit checks for every tree size, including odd sizes
  for (let size = 1; size <= 9; size++) {
    const leaves = Array.from({ length: size }, (_, i) => L.leafHash({ batch: 1, student_id: 'S' + i, course: 'C', marks: i, version: 1 }));
    const root = L.merkleRoot(leaves);
    leaves.forEach((lf, i) => assert.strictEqual(L.rootFromProof(lf, L.merkleProof(leaves, i)), root));
  }
  ok('Merkle proofs verify for tree sizes 1-9', () => {});

  const csv = 'student_id,course,marks\n' + Array.from({ length: 7 }, (_, i) => `REG1100${i},CSE101,${50 + i}`).join('\n');
  assert.strictEqual((await call('/api/publish', { csv })).s, 401); ok('publish without admin token rejected', () => {});
  assert.strictEqual((await call('/api/publish', { csv }, T.a1)).s, 200); ok('publish batch of 7', () => {});
  assert.strictEqual((await call('/api/publish', { csv }, T.a1)).s, 400); ok('re-publishing same results rejected', () => {});
  assert.strictEqual((await call('/api/publish', { csv: 'REG1,CSE,150' }, T.a1)).s, 400); ok('invalid marks rejected', () => {});

  const res = (await call('/api/result?s=REG11003&c=CSE101')).j.results[0], cp = (await call('/api/checkpoints')).j;
  ok('proof recomputes to the signed root', () => {
    assert.strictEqual(L.leafHash(res.record), res.leaf);
    assert.strictEqual(L.rootFromProof(res.leaf, res.proof), cp.checkpoints[0].root);
    assert.ok(L.verify(cp.ledger_pub, cp.checkpoints[0].head, cp.checkpoints[0].sig));
  });
  ok('forged marks fail verification', () => assert.notStrictEqual(L.leafHash({ ...res.record, marks: 99 }), res.leaf));
  assert.ok((await call('/api/audit')).j.ok); ok('clean ledger audits OK', () => {});

  // Corrections need two DISTINCT admins
  const prop = (await call('/api/corrections', { student_id: 'REG11003', course: 'CSE101', marks: 77, reason: 'Re-evaluation outcome' }, T.a1)).j;
  assert.strictEqual((await call('/api/corrections', { student_id: 'REG11003', course: 'CSE101', marks: 77, reason: '' }, T.a1)).s, 400); ok('correction without reason rejected', () => {});
  assert.strictEqual((await call(`/api/corrections/${prop.id}/approve`, {}, T.a1)).j.status, 'waiting for a second admin');
  assert.strictEqual((await call(`/api/corrections/${prop.id}/approve`, {}, T.a1)).s, 409); ok('same admin cannot approve twice', () => {});
  assert.strictEqual((await call('/api/result?s=REG11003&c=CSE101')).j.results.length, 1); ok('one approval changes nothing', () => {});
  assert.strictEqual((await call(`/api/corrections/${prop.id}/approve`, {}, T.a2)).j.status, 'published'); ok('second distinct admin publishes correction', () => {});
  const after = (await call('/api/result?s=REG11003&c=CSE101')).j.results;
  ok('both versions kept, original marked superseded', () => {
    assert.strictEqual(after.length, 2); assert.ok(after[0].superseded && !after[1].superseded);
    assert.strictEqual(after[0].record.marks, 53); assert.strictEqual(after[1].record.marks, 77);
    assert.ok(L.approvalsValid(after[1].record, cp.admin_pubs));
  });
  assert.ok((await call('/api/audit')).j.ok); ok('audit still clean after correction', () => {});

  // Direct DB attacks that bypass the app
  const raw = new DatabaseSync(path.join(dir, 'ledger.db'));
  raw.exec("UPDATE records SET marks=99 WHERE student_id='REG11001'");
  let a = (await call('/api/audit')).j;
  ok('direct marks edit pinpointed', () => assert.ok(!a.ok && a.issues.some(i => i.student === 'REG11001' && /edited directly/.test(i.problem))));
  const tampered = L.leafHash({ batch: 1, student_id: 'REG11001', course: 'CSE101', marks: 99, version: 1 });
  raw.exec(`UPDATE records SET leaf='${tampered}' WHERE student_id='REG11001'`);
  a = (await call('/api/audit')).j;
  ok('edit plus forged leaf hash still pinpointed via external checkpoint', () => assert.ok(a.issues.some(i => i.student === 'REG11001')));
  raw.exec("UPDATE records SET marks=53 WHERE student_id='REG11001'; UPDATE records SET leaf=(SELECT leaf FROM records WHERE student_id='REG11002') WHERE student_id='REG11001'");
  raw.exec("DELETE FROM records WHERE student_id='REG11005'");
  a = (await call('/api/audit')).j;
  ok('deleted row detected', () => assert.ok(a.issues.some(i => /row count/.test(i.problem))));
  raw.exec("INSERT INTO records(batch,idx,student_id,course,marks,version,supersedes,reason,approvals,leaf) VALUES(1,9,'FAKE001','CSE101',100,1,NULL,'','[]','00')");
  a = (await call('/api/audit')).j;
  ok('inserted fake row detected', () => assert.ok(a.issues.some(i => i.student === 'FAKE001' || /row count/.test(i.problem))));
  console.log(`\nAll ${n} checks passed`); srv.close(); process.exit(0);
})().catch(e => { console.error('FAIL', e); process.exit(1); });

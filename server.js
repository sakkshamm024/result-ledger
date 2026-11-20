const http = require('http'), fs = require('fs'), path = require('path');
const { DatabaseSync } = require('node:sqlite');
const QRCode = require('qrcode');
const L = require('./lib/ledger');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png'
};

function parseMarks(v) {
  if (v === null || v === undefined || typeof v === 'boolean') return null;
  const s = String(v).trim();
  if (!s) return null;
  const n = Number(s);
  if (!Number.isFinite(n) || n < 0 || n > 100) return null;
  return n;
}

function start(port = process.env.PORT || 3000, dataDir = process.env.DATA_DIR || path.join(__dirname, 'data')) {
  fs.mkdirSync(dataDir, { recursive: true });
  const keyFile = path.join(dataDir, 'keys.json'), cpFile = path.join(dataDir, 'checkpoints.jsonl');
  if (!fs.existsSync(keyFile)) {
    const admins = {};
    for (const id of ['a1', 'a2', 'a3']) admins[id] = { ...L.newKey(), token: require('crypto').randomBytes(8).toString('hex') };
    fs.writeFileSync(keyFile, JSON.stringify({ ledger: L.newKey(), admins }, null, 1));
  }
  const keys = JSON.parse(fs.readFileSync(keyFile));
  // Optional fixed tokens via env (e.g. ADMIN_TOKENS="a1:tok1,a2:tok2,a3:tok3") for cloud deployment
  if (process.env.ADMIN_TOKENS) {
    for (const pair of process.env.ADMIN_TOKENS.split(',')) {
      const [id, tok] = pair.split(':').map(x => x.trim());
      if (id && tok && keys.admins[id]) keys.admins[id].token = tok;
    }
  }
  const adminPubs = Object.fromEntries(Object.entries(keys.admins).map(([k, v]) => [k, v.pub]));
  const db = new DatabaseSync(path.join(dataDir, 'ledger.db'));
  db.exec(`CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, batch INT, idx INT, student_id TEXT, course TEXT,
      marks REAL, version INT, supersedes TEXT, reason TEXT, approvals TEXT, leaf TEXT);
    CREATE TABLE IF NOT EXISTS batches(n INTEGER PRIMARY KEY, root TEXT, prev TEXT, count INT, ts TEXT, head TEXT, sig TEXT);
    CREATE TABLE IF NOT EXISTS pending(id INTEGER PRIMARY KEY, student_id TEXT, course TEXT, marks REAL, reason TEXT,
      supersedes TEXT, digest TEXT, approvals TEXT, done INT DEFAULT 0);`);

  const toRec = r => ({ batch: r.batch, student_id: r.student_id, course: r.course, marks: r.marks, version: r.version,
    supersedes: r.supersedes, reason: r.reason, approvals: JSON.parse(r.approvals || '[]') });
  const checkpoints = () => fs.existsSync(cpFile) ? fs.readFileSync(cpFile, 'utf8').split('\n').filter(Boolean).map(JSON.parse) : [];
  const latest = (s, c) => db.prepare('SELECT * FROM records WHERE student_id=? AND course=? ORDER BY version DESC LIMIT 1').get(s, c);

  // Append one signed batch: records -> leaves -> Merkle root -> chained, signed header -> external checkpoint file.
  function addBatch(rows) {
    const last = db.prepare('SELECT * FROM batches ORDER BY n DESC LIMIT 1').get();
    const n = last ? last.n + 1 : 1, prev = last ? last.head : L.GENESIS, ts = new Date().toISOString();
    const recs = rows.map(r => ({ ...r, batch: n }));
    const leaves = recs.map(L.leafHash), root = L.merkleRoot(leaves);
    const head = L.headHash(n, root, prev, recs.length, ts), sig = L.sign(keys.ledger.priv, head);
    db.exec('BEGIN');
    try {
      recs.forEach((r, i) => db.prepare('INSERT INTO records(batch,idx,student_id,course,marks,version,supersedes,reason,approvals,leaf) VALUES(?,?,?,?,?,?,?,?,?,?)')
        .run(n, i, r.student_id, r.course, Number(r.marks), r.version, r.supersedes || null, r.reason || '', JSON.stringify(r.approvals || []), leaves[i]));
      db.prepare('INSERT INTO batches VALUES(?,?,?,?,?,?,?)').run(n, root, prev, recs.length, ts, head, sig);
      db.exec('COMMIT');
    } catch (e) { db.exec('ROLLBACK'); throw e; }
    fs.appendFileSync(cpFile, JSON.stringify({ n, root, prev, count: recs.length, ts, head, sig, leaves }) + '\n');
    return { n, root, head, count: recs.length };
  }

  function parseCsv(text) {
    const rawLines = String(text || '').split(/\r?\n/);
    const seen = new Set(), rows = [];
    let started = false;
    rawLines.forEach((raw, idx) => {
      if (!raw.trim()) return;
      const cols = raw.split(',').map(x => x.trim().replace(/^"|"$/g, ''));
      if (!started && cols[0].toLowerCase().startsWith('student')) { started = true; return; }
      started = true;
      const [s, c, m] = cols, lineNo = idx + 1;
      const marks = parseMarks(m);
      if (!/^[A-Za-z0-9._-]{1,40}$/.test(s || '')) throw new Error(`line ${lineNo}: bad student id`);
      if (!c || c.length > 40) throw new Error(`line ${lineNo}: missing or invalid course`);
      if (marks === null) throw new Error(`line ${lineNo}: marks must be 0-100`);
      if (seen.has(s + '|' + c) || latest(s, c)) throw new Error(`line ${lineNo}: ${s}/${c} already published (use a correction)`);
      seen.add(s + '|' + c);
      rows.push({ student_id: s, course: c, marks, version: 1, supersedes: null, reason: '', approvals: [] });
    });
    if (!rows.length) throw new Error('no rows');
    return rows;
  }

  function audit() {
    const issues = [], cps = Object.fromEntries(checkpoints().map(c => [c.n, c]));
    const batches = db.prepare('SELECT * FROM batches ORDER BY n').all();
    const rows = db.prepare('SELECT * FROM records ORDER BY batch, idx').all();
    const dbN = new Set(batches.map(b => b.n));
    for (const n of Object.keys(cps)) if (!dbN.has(+n)) issues.push({ batch: +n, problem: 'batch deleted from database' });
    for (const r of rows) if (!cps[r.batch]) issues.push({ batch: r.batch, idx: r.idx, student: r.student_id, course: r.course, problem: 'row in a batch that was never published' });
    let prevHead = L.GENESIS;
    for (const b of batches) {
      const cp = cps[b.n];
      if (!cp) { issues.push({ batch: b.n, problem: 'batch has no external checkpoint' }); continue; }
      const diffFields = ['root', 'prev', 'count', 'ts', 'head', 'sig'].filter(k => b[k] !== cp[k]);
      if (diffFields.length) issues.push({ batch: b.n, problem: `batch header differs from signed checkpoint (${diffFields.join(', ')})` });
      if (!L.verify(keys.ledger.pub, cp.head, cp.sig)) issues.push({ batch: b.n, problem: 'checkpoint signature invalid' });
      if (L.headHash(cp.n, cp.root, cp.prev, cp.count, cp.ts) !== cp.head) issues.push({ batch: b.n, problem: 'checkpoint head does not match its header' });
      if (cp.prev !== prevHead) issues.push({ batch: b.n, problem: 'hash chain broken: prev does not match earlier head' });
      if (!Array.isArray(cp.leaves) || cp.leaves.length !== cp.count || L.merkleRoot(cp.leaves) !== cp.root) {
        issues.push({ batch: b.n, problem: 'checkpoint leaf list does not match checkpoint Merkle root' });
      }
      prevHead = cp.head;
      const br = rows.filter(r => r.batch === b.n);
      if (br.length !== cp.count) issues.push({ batch: b.n, problem: `row count ${br.length} but ${cp.count} were published` });
      const seenIdx = new Set(), recomputedLeaves = [];
      for (const r of br) {
        const where = { batch: b.n, idx: r.idx, student: r.student_id, course: r.course };
        const calcLeaf = L.leafHash(toRec(r));
        recomputedLeaves.push(calcLeaf);
        if (r.idx < 0 || r.idx >= cp.count) {
          issues.push({ ...where, problem: `unexpected row inserted at out-of-range index ${r.idx}` });
          continue;
        }
        if (seenIdx.has(r.idx)) issues.push({ ...where, problem: `duplicate row index ${r.idx} inserted in database` });
        seenIdx.add(r.idx);
        if (calcLeaf !== cp.leaves[r.idx]) issues.push({ ...where, problem: 'row contents do not match the published hash (edited directly in the database)' });
        else if (r.leaf !== cp.leaves[r.idx]) issues.push({ ...where, problem: 'stored leaf hash was altered' });
        if (r.version > 1) {
          const prior = db.prepare('SELECT * FROM records WHERE student_id=? AND course=? AND version=?').get(r.student_id, r.course, r.version - 1);
          if (!prior || prior.leaf !== r.supersedes) issues.push({ ...where, problem: 'correction does not link to the previous version' });
          if (!L.approvalsValid(toRec(r), adminPubs)) issues.push({ ...where, problem: 'correction lacks two valid distinct admin signatures' });
        }
      }
      for (let i = 0; i < cp.count; i++) {
        if (!seenIdx.has(i)) issues.push({ batch: b.n, idx: i, problem: `row at index ${i} deleted from database (expected leaf ${cp.leaves[i].slice(0, 12)}...)` });
      }
      if (recomputedLeaves.length && L.merkleRoot(recomputedLeaves) !== cp.root) {
        issues.push({ batch: b.n, problem: 'recomputed Merkle root does not match signed checkpoint root' });
      }
    }
    // Audit open pending corrections for direct DB tampering before publication
    for (const pe of db.prepare('SELECT * FROM pending WHERE done=0').all()) {
      const expected = L.correctionDigest({ student_id: pe.student_id, course: pe.course, marks: pe.marks, reason: pe.reason, supersedes: pe.supersedes });
      let badSig = false;
      try {
        for (const [aid, sig] of JSON.parse(pe.approvals || '[]')) {
          if (!adminPubs[aid] || !L.verify(adminPubs[aid], expected, sig)) badSig = true;
        }
      } catch { badSig = true; }
      if (expected !== pe.digest || badSig) {
        issues.push({ batch: 0, student: pe.student_id, course: pe.course, problem: `pending correction #${pe.id} tampered directly in database` });
      }
    }
    return { ok: !issues.length, batches: batches.length, records: rows.length, issues, checked_at: new Date().toISOString() };
  }

  const who = req => Object.entries(keys.admins).find(([, v]) => v.token === req.headers['x-token'])?.[0];
  const send = (res, code, body, type = 'application/json') => { res.writeHead(code, { 'Content-Type': type, 'Cache-Control': 'no-store' }); res.end(type === 'application/json' ? JSON.stringify(body) : body); };
  const readBody = req => new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => {
      d += c;
      if (d.length > 2e6) { req.destroy(); reject(new Error('Request body too large')); }
    });
    req.on('end', () => {
      if (!d.trim()) return resolve({});
      try { resolve(JSON.parse(d)); } catch { reject(new Error('Invalid JSON body')); }
    });
    req.on('error', reject);
  });

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), p = u.pathname;
    try {
      if (p === '/api/publish' && req.method === 'POST') {
        if (!who(req)) return send(res, 401, { error: 'Admin token required' });
        return send(res, 200, addBatch(parseCsv((await readBody(req)).csv || '')));
      }
      if (p === '/api/result') {
        const s = (u.searchParams.get('s') || '').trim(), c = (u.searchParams.get('c') || '').trim();
        if (!s) return send(res, 400, { error: 'Student ID required' });
        const rows = db.prepare('SELECT * FROM records WHERE student_id=? ' + (c ? 'AND course=? ' : '') + 'ORDER BY course, version')
          .all(...(c ? [s, c] : [s]));
        const out = rows.map(r => {
          const leaves = db.prepare('SELECT leaf FROM records WHERE batch=? ORDER BY idx').all(r.batch).map(x => x.leaf);
          const b = db.prepare('SELECT * FROM batches WHERE n=?').get(r.batch);
          const nx = db.prepare('SELECT 1 x FROM records WHERE student_id=? AND course=? AND version>?').get(r.student_id, r.course, r.version);
          return { record: toRec(r), leaf: r.leaf, proof: L.merkleProof(leaves, r.idx), batch: b, superseded: !!nx };
        });
        return send(res, 200, { results: out });
      }
      if (p === '/api/checkpoints') return send(res, 200, { ledger_pub: keys.ledger.pub, admin_pubs: adminPubs, checkpoints: checkpoints() });
      if (p === '/api/audit') return send(res, 200, audit());
      if (p === '/api/records') {
        const a = who(req); if (!a) return send(res, 401, { error: 'Admin token required' });
        return send(res, 200, {
          admin: a,
          records: db.prepare('SELECT batch,student_id,course,marks,version,leaf FROM records ORDER BY id').all(),
          pending: db.prepare('SELECT * FROM pending WHERE done=0').all().map(x => ({ ...x, approvals: JSON.parse(x.approvals).map(ap => ap[0]) }))
        });
      }
      if (p === '/api/corrections' && req.method === 'POST') {
        const a = who(req); if (!a) return send(res, 401, { error: 'Admin token required' });
        const b = await readBody(req);
        const sid = String(b.student_id || '').trim(), course = String(b.course || '').trim();
        const cur = latest(sid, course);
        if (!cur) return send(res, 404, { error: 'No published result for that student and course' });
        const marks = parseMarks(b.marks);
        if (marks === null) return send(res, 400, { error: 'Marks must be 0-100' });
        if (!b.reason || String(b.reason).trim().length < 5) return send(res, 400, { error: 'A reason of at least 5 characters is required' });
        const c = { student_id: sid, course, marks, reason: String(b.reason).trim(), supersedes: cur.leaf };
        const r = db.prepare('INSERT INTO pending(student_id,course,marks,reason,supersedes,digest,approvals) VALUES(?,?,?,?,?,?,?)')
          .run(c.student_id, c.course, c.marks, c.reason, c.supersedes, L.correctionDigest(c), '[]');
        return send(res, 200, { id: Number(r.lastInsertRowid), needs: 'two distinct admin approvals' });
      }
      const m = p.match(/^\/api\/corrections\/(\d+)\/approve$/);
      if (m && req.method === 'POST') {
        const a = who(req); if (!a) return send(res, 401, { error: 'Admin token required' });
        const pe = db.prepare('SELECT * FROM pending WHERE id=? AND done=0').get(+m[1]);
        if (!pe) return send(res, 404, { error: 'No open correction with that id' });
        const expectedDigest = L.correctionDigest({
          student_id: pe.student_id, course: pe.course, marks: pe.marks, reason: pe.reason, supersedes: pe.supersedes
        });
        if (expectedDigest !== pe.digest) {
          return send(res, 409, { error: 'Pending correction record tampered in database (digest mismatch)' });
        }
        const ap = JSON.parse(pe.approvals);
        for (const [adminId, sig] of ap) {
          if (!adminPubs[adminId] || !L.verify(adminPubs[adminId], expectedDigest, sig)) {
            return send(res, 409, { error: `Existing approval signature for ${adminId} is invalid` });
          }
        }
        if (ap.some(x => x[0] === a)) return send(res, 409, { error: `${a} already approved; a different admin must approve` });
        const cur = latest(pe.student_id, pe.course);
        if (!cur || cur.leaf !== pe.supersedes) return send(res, 409, { error: 'Result changed since this correction was proposed' });
        ap.push([a, L.sign(keys.admins[a].priv, expectedDigest)]);
        if (ap.length < 2) {
          db.prepare('UPDATE pending SET approvals=? WHERE id=?').run(JSON.stringify(ap), pe.id);
          return send(res, 200, { status: 'waiting for a second admin', approved_by: ap.map(x => x[0]) });
        }
        ap.sort((x, y) => x[0].localeCompare(y[0]));
        const newRec = {
          student_id: pe.student_id, course: pe.course, marks: pe.marks,
          version: cur.version + 1, supersedes: pe.supersedes, reason: pe.reason, approvals: ap
        };
        if (!L.approvalsValid(newRec, adminPubs)) {
          return send(res, 409, { error: 'Correction failed two-admin cryptographic verification' });
        }
        const out = addBatch([newRec]);
        db.prepare('UPDATE pending SET done=1, approvals=? WHERE id=?').run(JSON.stringify(ap), pe.id);
        return send(res, 200, { status: 'published', ...out });
      }
      if (p === '/api/qr') { const t = u.searchParams.get('text') || ''; return t.length > 600 ? send(res, 400, { error: 'too long' }) : send(res, 200, await QRCode.toString(t, { type: 'svg', margin: 1 }), 'image/svg+xml'); }
      const f = path.join(__dirname, 'public', p === '/' ? 'index.html' : path.normalize(p).replace(/^(\.\.[/\\])+/, ''));
      if (f.startsWith(path.join(__dirname, 'public')) && fs.existsSync(f) && fs.statSync(f).isFile()) {
        return send(res, 200, fs.readFileSync(f), MIME[path.extname(f).toLowerCase()] || 'application/octet-stream');
      }
      send(res, 404, { error: 'not found' });
    } catch (e) { send(res, 400, { error: e.message }); }
  });
  server.keys = keys; server.db = db; server.dataDir = dataDir;
  return new Promise(r => server.listen(port, () => r(server)));
}

module.exports = { start };
if (require.main === module) start().then(s => {
  console.log(`Ledger running on :${s.address().port}`);
  console.log('Admin tokens (header x-token):', Object.fromEntries(Object.entries(s.keys.admins).map(([k, v]) => [k, v.token])));
});
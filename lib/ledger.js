// Crypto core. Everything here is pure functions so it can be unit-tested and explained in a viva.
const crypto = require('crypto');
const sha = (...parts) => {
  const h = crypto.createHash('sha256');
  parts.forEach(p => h.update(p));
  return h.digest();
};
const hex = b => b.toString('hex');

// Canonical form: a fixed-order JSON array, so field order can never change a hash.
const canon = r => JSON.stringify(['v1', r.batch, r.student_id, r.course, Number(r.marks),
  r.version, r.supersedes || null, r.reason || '', r.approvals || []]);

// Domain separation (0x00 leaf, 0x01 node) stops a leaf being passed off as an inner node.
const leafHash = r => hex(sha(Buffer.from([0]), canon(r)));
const nodeHash = (l, r) => sha(Buffer.from([1]), l, r);

function levels(leaves) {
  const L = [leaves.map(h => Buffer.from(h, 'hex'))];
  while (L.at(-1).length > 1) {
    const cur = L.at(-1), nx = [];
    for (let i = 0; i < cur.length; i += 2) nx.push(i + 1 < cur.length ? nodeHash(cur[i], cur[i + 1]) : cur[i]);
    L.push(nx);
  }
  return L;
}
const merkleRoot = leaves => leaves.length ? hex(levels(leaves).at(-1)[0]) : hex(sha('empty'));

// Inclusion proof = sibling hashes from leaf to root. An unpaired node is promoted, never duplicated.
function merkleProof(leaves, idx) {
  const L = levels(leaves), proof = [];
  for (let d = 0; d < L.length - 1; d++) {
    const sib = idx ^ 1;
    if (sib < L[d].length) proof.push({ side: idx % 2 ? 'L' : 'R', hash: hex(L[d][sib]) });
    idx >>= 1;
  }
  return proof;
}
function rootFromProof(leaf, proof) {
  let h = Buffer.from(leaf, 'hex');
  for (const s of proof) {
    const sib = Buffer.from(s.hash, 'hex');
    h = s.side === 'L' ? nodeHash(sib, h) : nodeHash(h, sib);
  }
  return hex(h);
}

// Batch header commits to the previous head, which forms the hash chain.
const headHash = (n, root, prev, count, ts) => hex(sha(JSON.stringify(['hdr', n, root, prev, count, ts])));
const GENESIS = '0'.repeat(64);

const newKey = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return { pub: publicKey.export({ type: 'spki', format: 'pem' }), priv: privateKey.export({ type: 'pkcs8', format: 'pem' }) };
};
const sign = (privPem, msgHex) => hex(crypto.sign(null, Buffer.from(msgHex, 'hex'), privPem));
const verify = (pubPem, msgHex, sigHex) => {
  try { return crypto.verify(null, Buffer.from(msgHex, 'hex'), pubPem, Buffer.from(sigHex, 'hex')); } catch { return false; }
};

// What an admin signs when approving a correction.
const correctionDigest = c => hex(sha(JSON.stringify(['corr', c.student_id, c.course, Number(c.marks), c.reason, c.supersedes])));

// A correction record is valid only with 2+ DISTINCT admins whose signatures check out.
function approvalsValid(rec, adminPubs) {
  const digest = correctionDigest(rec);
  const ok = new Set();
  for (const [admin, sig] of rec.approvals || []) if (adminPubs[admin] && verify(adminPubs[admin], digest, sig)) ok.add(admin);
  return ok.size >= 2;
}

module.exports = { canon, leafHash, merkleRoot, merkleProof, rootFromProof, headHash, GENESIS, newKey, sign, verify, correctionDigest, approvalsValid };

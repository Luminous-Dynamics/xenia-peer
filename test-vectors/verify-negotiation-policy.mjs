import fs from 'node:fs';
import crypto from 'node:crypto';

const vector = JSON.parse(fs.readFileSync(new URL('./negotiation-policy-v1.json', import.meta.url), 'utf8'));
const DOMAIN = Buffer.from(vector.domain_hex, 'hex');

function u16be(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}

function component(s) {
  const b = Buffer.from(s, 'utf8');
  if (b.length === 0 || b.length > 0xffff) throw new Error('invalid component length');
  return Buffer.concat([u16be(b.length), b]);
}

function canonicalPairs(pairs) {
  return [...pairs].sort((a, b) => {
    const an = Buffer.from(a[0], 'utf8');
    const bn = Buffer.from(b[0], 'utf8');
    const byName = Buffer.compare(an, bn);
    if (byName !== 0) return byName;
    return Buffer.compare(Buffer.from(a[1], 'utf8'), Buffer.from(b[1], 'utf8'));
  });
}

function encodeList(pairs) {
  const canonical = canonicalPairs(pairs);
  const parts = [u32be(canonical.length)];
  for (const [name, version] of canonical) {
    parts.push(component(name), component(version));
  }
  return Buffer.concat(parts);
}

function encodePolicy(policy) {
  if (policy.mode !== 0 && policy.mode !== 1) throw new Error('unknown policy mode');
  if (policy.mode === 0 && policy.allowed.length !== 0) throw new Error('minimum mode must not carry allow-list entries');
  return Buffer.concat([
    DOMAIN,
    Buffer.from([policy.mode]),
    encodeList(policy.required),
    encodeList(policy.allowed),
  ]);
}

for (const name of ['minimum', 'allow_list']) {
  const policy = vector[name];
  const bytes = encodePolicy(policy);
  const digest = crypto.createHash('sha256').update(bytes).digest('hex');
  if (digest !== policy.sha256) {
    throw new Error(`${name} policy hash mismatch: ${digest} != ${policy.sha256}`);
  }
}

console.log('negotiation-policy-v1 vectors reproduced independently');

import fs from 'node:fs';
import crypto from 'node:crypto';

const vector = JSON.parse(
  fs.readFileSync(new URL('./handshake-v2-message-contract.json', import.meta.url), 'utf8'),
);

const OFFER_DOMAIN = Buffer.from('xenia.capability-offer.v1\0', 'utf8');
const SELECTED_DOMAIN = Buffer.from('xenia.negotiated-context.v1\0', 'utf8');
const BINDING_DOMAIN = Buffer.from('xenia.capability-negotiation-binding.v1\0', 'utf8');
const V5_DOMAIN = Buffer.from('xenia.negotiated-session-context.v5\0', 'utf8');

function sha256(bytes) {
  return crypto.createHash('sha256').update(bytes).digest();
}
function u16be(n) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(n);
  return out;
}
function u32be(n) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(n);
  return out;
}
function u32le(n) {
  const out = Buffer.alloc(4);
  out.writeUInt32LE(n);
  return out;
}
function u64le(n) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64LE(BigInt(n));
  return out;
}
function lp16(bytes) {
  return Buffer.concat([u16be(bytes.length), bytes]);
}
function lp32(bytes) {
  return Buffer.concat([u32be(bytes.length), bytes]);
}
function fill(byte, length) {
  return Buffer.alloc(length, byte);
}
function expectHex(actual, expected, label) {
  const got = Buffer.from(actual).toString('hex');
  if (got !== expected) throw new Error(`${label}: ${got} != ${expected}`);
}
function expectLength(actual, expected, label) {
  if (actual.length !== expected) throw new Error(`${label} length: ${actual.length} != ${expected}`);
}

function canonicalOffer(entries) {
  const sorted = [...entries].sort((a, b) => Buffer.compare(a.name, b.name));
  const parts = [OFFER_DOMAIN, u32be(sorted.length)];
  for (const entry of sorted) {
    parts.push(lp16(entry.name), u16be(entry.versions.length));
    for (const version of entry.versions) parts.push(lp16(version));
  }
  return Buffer.concat(parts);
}

function selectedContext(entries) {
  const sorted = [...entries].sort((a, b) => {
    const byName = Buffer.compare(a.name, b.name);
    return byName !== 0 ? byName : Buffer.compare(a.version, b.version);
  });
  const parts = [SELECTED_DOMAIN, u32be(sorted.length)];
  for (const entry of sorted) parts.push(lp16(entry.name), lp16(entry.version));
  return Buffer.concat(parts);
}

function hostFinalizeTranscript(viewerTranscript, responseV5, finalizeV5, viewerEdSig, viewerMlDsaSig) {
  if (finalizeV5.every((byte) => byte === 0)) {
    throw new Error('host-finalize V5 context must not be all zero');
  }
  if (!responseV5.equals(finalizeV5)) {
    throw new Error('host-finalize V5 context does not match viewer-response V5 context');
  }
  return Buffer.concat([
    viewerTranscript,
    lp32(Buffer.from('host-finalize-v2')),
    lp32(viewerEdSig),
    lp32(viewerMlDsaSig),
    lp32(finalizeV5),
  ]);
}

const hostOffer = canonicalOffer([
  {
    name: Buffer.from('xenia.causal-authority'),
    versions: [Buffer.from('draft-04'), Buffer.from('draft-03')],
  },
  { name: Buffer.from('xenia.operator-rekey'), versions: [Buffer.from('v1')] },
]);
const viewerOffer = canonicalOffer([
  { name: Buffer.from('xenia.causal-authority'), versions: [Buffer.from('draft-04')] },
  { name: Buffer.from('xenia.operator-rekey'), versions: [Buffer.from('v1')] },
]);
const selected = selectedContext([
  { name: Buffer.from('xenia.causal-authority'), version: Buffer.from('draft-04') },
  { name: Buffer.from('xenia.operator-rekey'), version: Buffer.from('v1') },
]);
const selectedHash = sha256(selected);
expectHex(selectedHash, vector.selected_context_sha256, 'selected context');

const binding = sha256(Buffer.concat([
  BINDING_DOMAIN,
  sha256(hostOffer),
  sha256(viewerOffer),
  selectedHash,
]));
expectHex(binding, vector.negotiation_binding_sha256, 'negotiation binding');

const baseV4 = Buffer.from(vector.base_v4_context_hash, 'hex');
const v5 = sha256(Buffer.concat([V5_DOMAIN, baseV4, binding]));
expectHex(v5, vector.final_v5_context_hash, 'V5 context');

// Bincode 1.3 default encoding used by the Rust contract:
// enum discriminant = u32 little-endian; Vec<u8> length = u64 little-endian;
// fixed byte arrays are emitted directly.
const hostHello = Buffer.concat([
  u32le(vector.message_variants.host_hello_v2),
  fill(0x11, 32),
  fill(0x22, 1952),
  fill(0x33, 1184),
  fill(0x44, 32),
  baseV4,
  u64le(hostOffer.length), hostOffer,
]);
const viewerEdSig = fill(0xbb, 64);
const viewerMlDsaSig = fill(0xcc, 3309);
const viewerResponse = Buffer.concat([
  u32le(vector.message_variants.viewer_response_v2),
  fill(0x66, 32),
  fill(0x77, 1952),
  fill(0x88, 1088),
  fill(0x99, 32),
  u64le(viewerOffer.length), viewerOffer,
  v5,
  viewerEdSig,
  viewerMlDsaSig,
]);
const finalizeV5 = Buffer.from(v5);
const hostFinalize = Buffer.concat([
  u32le(vector.message_variants.host_finalize_v2),
  finalizeV5,
  fill(0xdd, 64),
  fill(0xee, 3309),
]);

for (const [name, bytes] of [
  ['host_hello_v2', hostHello],
  ['viewer_response_v2', viewerResponse],
  ['host_finalize_v2', hostFinalize],
]) {
  expectLength(bytes, vector.messages[name].bytes, name);
  expectHex(sha256(bytes), vector.messages[name].sha256, `${name} SHA-256`);
}

const prefix = Buffer.concat([
  lp32(Buffer.from('xenia-handshake-signature-v2')),
  lp32(Buffer.from('xenia-handshake-transcript-v2')),
  lp32(Buffer.from('hybrid-pq-transcript-v1')),
  lp32(Buffer.from('ml-kem-768-fips203')),
  lp32(Buffer.from('ed25519-rfc8032+ml-dsa-65-fips204')),
  lp32(Buffer.from('hkdf-sha256')),
]);
const viewerTranscript = Buffer.concat([
  prefix,
  lp32(Buffer.from('viewer-response-v2')),
  lp32(hostHello),
  lp32(fill(0x66, 32)),
  lp32(fill(0x77, 1952)),
  lp32(fill(0x88, 1088)),
  lp32(fill(0x99, 32)),
  lp32(viewerOffer),
  lp32(v5),
]);
const hostTranscript = hostFinalizeTranscript(
  viewerTranscript,
  v5,
  finalizeV5,
  viewerEdSig,
  viewerMlDsaSig,
);

expectLength(viewerTranscript, vector.signature_transcripts.viewer_response_v2.bytes, 'viewer transcript');
expectHex(
  sha256(viewerTranscript),
  vector.signature_transcripts.viewer_response_v2.sha256,
  'viewer transcript SHA-256',
);
expectLength(hostTranscript, vector.signature_transcripts.host_finalize_v2.bytes, 'host transcript');
expectHex(
  sha256(hostTranscript),
  vector.signature_transcripts.host_finalize_v2.sha256,
  'host transcript SHA-256',
);

const mismatchedFinalizeV5 = Buffer.from(finalizeV5);
mismatchedFinalizeV5[0] ^= 0x01;
let mismatchRejected = false;
try {
  hostFinalizeTranscript(viewerTranscript, v5, mismatchedFinalizeV5, viewerEdSig, viewerMlDsaSig);
} catch (error) {
  mismatchRejected = error.message.includes('does not match');
}
if (!mismatchRejected) {
  throw new Error('host-finalize V5 mismatch was not rejected');
}

let zeroFinalizeRejected = false;
try {
  hostFinalizeTranscript(viewerTranscript, v5, Buffer.alloc(32), viewerEdSig, viewerMlDsaSig);
} catch (error) {
  zeroFinalizeRejected = error.message.includes('all zero');
}
if (!zeroFinalizeRejected) {
  throw new Error('all-zero host-finalize V5 was not rejected');
}

console.log('handshake-v2 message, signature-transcript, and finalize-V5 binding vectors reproduced independently');

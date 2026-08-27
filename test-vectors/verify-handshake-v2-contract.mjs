import fs from "node:fs";
import crypto from "node:crypto";
import assert from "node:assert/strict";

const fixture = JSON.parse(
  fs.readFileSync(new URL("./handshake-v2-contract.json", import.meta.url), "utf8"),
);

const maxEnvelope = fixture.transport.max_handshake_envelope_bytes;
const maxOffer = fixture.transport.max_capability_offer_bytes;
assert.equal(maxEnvelope, 16 * 1024);
assert.equal(maxOffer, 8 * 1024);

for (const [name, fixed] of Object.entries(fixture.candidate_bincode_fixed_bytes)) {
  const total = name === "host_finalize_v2" ? fixed : fixed + maxOffer;
  assert.ok(total <= maxEnvelope, `${name} exceeds handshake envelope ceiling`);
  const expectedHeadroom = fixture.candidate_headroom_at_max_offer[name];
  assert.equal(maxEnvelope - total, expectedHeadroom, `${name} headroom drift`);
}

// ViewerResponseV2 is the tightest message because it carries ML-DSA-65
// signature material plus the viewer offer. Keep an explicit safety margin so
// future fields cannot silently consume the entire unauthenticated parser budget.
assert.ok(
  fixture.candidate_headroom_at_max_offer.viewer_response_v2 >= 1024,
  "ViewerResponseV2 must retain at least 1 KiB envelope headroom",
);

const domain = Buffer.concat([
  Buffer.from("xenia.negotiated-session-context.v5", "utf8"),
  Buffer.from([0]),
]);
const baseV4 = Buffer.from(fixture.v5.base_v4_hash_hex, "hex");
const negotiationBinding = Buffer.from(
  fixture.v5.negotiation_binding_hash_hex,
  "hex",
);
assert.equal(baseV4.length, 32);
assert.equal(negotiationBinding.length, 32);

const preimage = Buffer.concat([domain, baseV4, negotiationBinding]);
assert.equal(preimage.toString("hex"), fixture.v5.preimage_hex);
const digest = crypto.createHash("sha256").update(preimage).digest("hex");
assert.equal(digest, fixture.v5.sha256);

console.log(`V2 max offer: ${maxOffer} bytes`);
console.log(
  `ViewerResponseV2 headroom: ${fixture.candidate_headroom_at_max_offer.viewer_response_v2} bytes`,
);
console.log(`V5 context vector: ${digest}`);
console.log("handshake-v2 contract: PASS");

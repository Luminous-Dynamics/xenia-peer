import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const vector = JSON.parse(
  readFileSync(new URL("./authority-activation-receipt-v1.json", import.meta.url), "utf8"),
);

const bytes = (hex) => Buffer.from(hex, "hex");
const sha256 = (...parts) => {
  const hash = createHash("sha256");
  for (const part of parts) hash.update(part);
  return hash.digest();
};
const assertHex = (label, actual, expected) => {
  const got = Buffer.from(actual).toString("hex");
  if (got !== expected) throw new Error(`${label}: ${got} != ${expected}`);
};

const transcript = bytes(vector.handshake_transcript_hash_hex);
const baseV4 = bytes(vector.base_v4_context_hash_hex);
const binding = bytes(vector.negotiation_binding_hash_hex);
const policy = bytes(vector.local_policy_hash_hex);
const hostIdentity = bytes(vector.host_identity_fingerprint_hex);

const v5 = sha256(
  Buffer.from("xenia.negotiated-session-context.v5\0", "utf8"),
  baseV4,
  binding,
);
assertHex("V5", v5, vector.final_v5_context_hash_hex);

const lineage = sha256(
  Buffer.from("xenia.authority-lineage.v1\0", "utf8"),
  transcript,
  v5,
  hostIdentity,
);
assertHex("lineage_id", lineage, vector.lineage_id_hex);

const activation = sha256(
  Buffer.from("xenia.authority-activation.v1\0", "utf8"),
  lineage,
  policy,
);
assertHex("activation_id", activation, vector.activation_id_hex);

const canonical = Buffer.concat([
  Buffer.from("xenia.authority-activation-receipt.v1\0", "utf8"),
  Buffer.from([vector.schema_version]),
  transcript,
  baseV4,
  v5,
  bytes(vector.host_offer_hash_hex),
  bytes(vector.viewer_offer_hash_hex),
  bytes(vector.selected_context_hash_hex),
  binding,
  policy,
  hostIdentity,
  lineage,
  activation,
]);
if (canonical.length !== vector.canonical_receipt_length) {
  throw new Error(`canonical receipt length: ${canonical.length} != ${vector.canonical_receipt_length}`);
}
assertHex("receipt_digest", sha256(canonical), vector.receipt_digest_hex);

console.log("PASS: native authority activation receipt v1 vector reproduced independently");

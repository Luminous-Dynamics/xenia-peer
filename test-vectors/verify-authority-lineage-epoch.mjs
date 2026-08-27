import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const vector = JSON.parse(
  readFileSync(new URL("./authority-lineage-epoch-v1.json", import.meta.url), "utf8"),
);

const bytes = (hex) => Buffer.from(hex, "hex");
const sha256 = (data) => createHash("sha256").update(data).digest("hex");

function encodeEpoch(epoch) {
  const keyEpoch = Buffer.alloc(8);
  keyEpoch.writeBigUInt64BE(BigInt(epoch.key_epoch));
  return Buffer.concat([
    Buffer.from("xenia.authority-lineage-epoch-evidence.v1\0", "utf8"),
    Buffer.from([vector.schema_version]),
    bytes(vector.lineage_id_hex),
    bytes(vector.activation_id_hex),
    keyEpoch,
    bytes(epoch.previous_epoch_hash_hex),
    bytes(epoch.current_epoch_hash_hex),
  ]);
}

for (const [name, epoch] of Object.entries({ epoch0: vector.epoch0, epoch1: vector.epoch1 })) {
  const canonical = encodeEpoch(epoch);
  if (canonical.length !== epoch.canonical_length) {
    throw new Error(`${name} length: ${canonical.length} != ${epoch.canonical_length}`);
  }
  const digest = sha256(canonical);
  if (digest !== epoch.evidence_digest_hex) {
    throw new Error(`${name} digest: ${digest} != ${epoch.evidence_digest_hex}`);
  }
}

if (vector.epoch1.key_epoch !== vector.epoch0.key_epoch + 1) {
  throw new Error("epoch1 is not contiguous");
}
if (vector.epoch1.previous_epoch_hash_hex !== vector.epoch0.current_epoch_hash_hex) {
  throw new Error("epoch1 does not reference epoch0 chain head");
}
if (vector.epoch1.current_epoch_hash_hex === vector.epoch1.previous_epoch_hash_hex) {
  throw new Error("epoch1 did not advance the chain head");
}

console.log("PASS: native authority lineage epoch evidence v1 reproduced independently");

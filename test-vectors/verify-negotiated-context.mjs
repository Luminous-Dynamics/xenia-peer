import fs from "node:fs";
import crypto from "node:crypto";
import assert from "node:assert/strict";

const fixture = JSON.parse(
  fs.readFileSync(new URL("./negotiated-context-v1.json", import.meta.url), "utf8"),
);

assert.equal(fixture.hash_algorithm, "sha256");

const OFFER_DOMAIN = Buffer.concat([
  Buffer.from("xenia.capability-offer.v1", "utf8"),
  Buffer.from([0]),
]);
const SELECTED_DOMAIN = Buffer.concat([
  Buffer.from("xenia.negotiated-context.v1", "utf8"),
  Buffer.from([0]),
]);
const BINDING_DOMAIN = Buffer.concat([
  Buffer.from("xenia.capability-negotiation-binding.v1", "utf8"),
  Buffer.from([0]),
]);

function u16be(value) {
  const out = Buffer.alloc(2);
  out.writeUInt16BE(value);
  return out;
}

function u32be(value) {
  const out = Buffer.alloc(4);
  out.writeUInt32BE(value);
  return out;
}

function sha256(bytes) {
  return crypto.createHash("sha256").update(bytes).digest();
}

function normalizeOffer(entries) {
  assert.ok(entries.length <= 64, "too many capability names");
  const normalized = entries.map((entry) => {
    const name = Buffer.from(entry.name_utf8, "utf8");
    const versions = entry.versions_by_preference_utf8.map((version) =>
      Buffer.from(version, "utf8"),
    );
    assert.ok(name.length > 0 && name.length <= 128, "invalid capability name length");
    assert.ok(versions.length > 0 && versions.length <= 16, "invalid version count");
    for (const version of versions) {
      assert.ok(version.length > 0 && version.length <= 32, "invalid version length");
    }
    const seenVersions = new Set(versions.map((version) => version.toString("hex")));
    assert.equal(seenVersions.size, versions.length, "duplicate offered version");
    return { name, versions };
  });

  normalized.sort((a, b) => Buffer.compare(a.name, b.name));
  for (let i = 1; i < normalized.length; i += 1) {
    assert.notEqual(
      Buffer.compare(normalized[i - 1].name, normalized[i].name),
      0,
      "duplicate capability name",
    );
  }
  return normalized;
}

function encodeOffer(entries) {
  const normalized = normalizeOffer(entries);
  const chunks = [OFFER_DOMAIN, u32be(normalized.length)];
  for (const entry of normalized) {
    chunks.push(u16be(entry.name.length), entry.name, u16be(entry.versions.length));
    for (const version of entry.versions) {
      chunks.push(u16be(version.length), version);
    }
  }
  return { normalized, bytes: Buffer.concat(chunks) };
}

function negotiate(hostEntries, viewerEntries) {
  const host = normalizeOffer(hostEntries);
  const viewer = normalizeOffer(viewerEntries);
  const viewerByName = new Map(viewer.map((entry) => [entry.name.toString("hex"), entry]));
  const selected = [];

  for (const hostEntry of host) {
    const viewerEntry = viewerByName.get(hostEntry.name.toString("hex"));
    if (!viewerEntry) continue;
    const viewerVersions = new Set(viewerEntry.versions.map((version) => version.toString("hex")));
    const version = hostEntry.versions.find((candidate) =>
      viewerVersions.has(candidate.toString("hex")),
    );
    if (version) selected.push({ name: hostEntry.name, version });
  }
  return selected;
}

function encodeSelected(selected) {
  const normalized = [...selected].sort((a, b) => {
    const byName = Buffer.compare(a.name, b.name);
    return byName !== 0 ? byName : Buffer.compare(a.version, b.version);
  });
  for (let i = 1; i < normalized.length; i += 1) {
    assert.notEqual(
      Buffer.compare(normalized[i - 1].name, normalized[i].name),
      0,
      "multiple selected versions for one capability name",
    );
  }

  const chunks = [SELECTED_DOMAIN, u32be(normalized.length)];
  for (const entry of normalized) {
    chunks.push(
      u16be(entry.name.length),
      entry.name,
      u16be(entry.version.length),
      entry.version,
    );
  }
  return Buffer.concat(chunks);
}

const host = encodeOffer(fixture.host_offer);
const viewer = encodeOffer(fixture.viewer_offer);
assert.equal(host.bytes.toString("hex"), fixture.expected.host_offer_canonical_hex);
assert.equal(sha256(host.bytes).toString("hex"), fixture.expected.host_offer_sha256);
assert.equal(viewer.bytes.toString("hex"), fixture.expected.viewer_offer_canonical_hex);
assert.equal(sha256(viewer.bytes).toString("hex"), fixture.expected.viewer_offer_sha256);

const selected = negotiate(fixture.host_offer, fixture.viewer_offer);
const selectedBytes = encodeSelected(selected);
assert.equal(selectedBytes.toString("hex"), fixture.expected.selected_canonical_hex);
const selectedHash = sha256(selectedBytes);
assert.equal(selectedHash.toString("hex"), fixture.expected.selected_sha256);
assert.deepEqual(
  selected.map((entry) => ({
    name_utf8: entry.name.toString("utf8"),
    version_utf8: entry.version.toString("utf8"),
  })),
  fixture.expected.selected,
);

const bindingPreimage = Buffer.concat([
  BINDING_DOMAIN,
  sha256(host.bytes),
  sha256(viewer.bytes),
  selectedHash,
]);
assert.equal(bindingPreimage.toString("hex"), fixture.expected.binding_preimage_hex);
assert.equal(sha256(bindingPreimage).toString("hex"), fixture.expected.binding_sha256);

// Capability entry order must not affect offer identity.
const reversedHost = encodeOffer([...fixture.host_offer].reverse());
assert.equal(reversedHost.bytes.toString("hex"), fixture.expected.host_offer_canonical_hex);

// Version preference order is authenticated and must change the offer hash.
const reversedPreference = structuredClone(fixture.host_offer);
reversedPreference[0].versions_by_preference_utf8.reverse();
assert.notEqual(
  sha256(encodeOffer(reversedPreference).bytes).toString("hex"),
  fixture.expected.host_offer_sha256,
);

// A peer that does not offer draft-04 cannot negotiate draft-04.
const downgradedViewer = structuredClone(fixture.viewer_offer);
downgradedViewer[0].versions_by_preference_utf8 = ["draft-03"];
const downgraded = negotiate(fixture.host_offer, downgradedViewer);
assert.equal(
  downgraded.some(
    (entry) =>
      entry.name.toString("utf8") === "xenia.causal-authority" &&
      entry.version.toString("utf8") === "draft-04",
  ),
  false,
);

// Duplicate exact versions must fail closed rather than silently normalizing.
const duplicateVersion = structuredClone(fixture.host_offer);
duplicateVersion[0].versions_by_preference_utf8 = ["draft-04", "draft-04"];
assert.throws(() => encodeOffer(duplicateVersion), /duplicate offered version/);

console.log("negotiated capability offers + selection + binding: PASS");

// Copyright (c) 2024-2026 Tristan Stoltz / Luminous Dynamics
// SPDX-License-Identifier: Apache-2.0 OR MIT
//
// Ported from `symthaea/src/swarm/rdp_codec.rs`. Relicensed to
// Apache-2.0 OR MIT for this crate by the copyright holder (same
// author); see ADR-002 for the library-vs-binary licensing split.
// Faithful port of the 64x64 grayscale-tile HDC-delta codec, minus
// the Symthaea-specific types and the consciousness-coupled framing.
// The original port materialized Symthaea's full 16,384-dim
// `ContinuousHV` per tile per frame; since 2026-07-05 this crate
// instead uses an exact 8-dimensional reduction of the same math
// (see the "Tile features + band weighting" module comment below) —
// there's still no need to drag in `symthaea-core` as a dependency.

//! HDC hybrid tile-delta codec.
//!
//! Research-grade compression for desktop content. Not competitive
//! with H.264 on video frames; decisively better than H.264 on
//! low-motion text / UI / code editors thanks to sparse-tile
//! transmission + HDC-based change detection.
//!
//! ## Pipeline
//!
//! ```text
//!     Capture (RGBA)
//!         ↓
//!     64×64 tile grid
//!         ↓  (per tile)
//!     HDC encoding → weighted cosine sim vs prev frame's tile features
//!         ↓
//!     if sim > threshold (0.92 default) → skip
//!         ↓ else
//!     Classify (Text / Photo / Video / Static) via pixel stats
//!         ↓
//!     Extract tile pixels as RGB (TILE_SIZE² × 3 bytes, no alpha)
//!         ↓
//!     Emit tile-delta packet: (keyframe flag, frame_id, changed
//!     tiles [(index, rgb_bytes)…])
//! ```
//!
//! On the decoder side the previous full frame is held in a buffer;
//! each new packet patches in the changed tiles. First packet of a
//! stream is a **keyframe** covering every tile, and one is also
//! forced periodically thereafter (`DEFAULT_KEYFRAME_INTERVAL_MS`) as
//! an error-recovery safety net — the per-tile change detector is a
//! coarse statistical comparison, not an exact pixel hash, and can
//! occasionally miss a real change (alias it as "unchanged").
//!
//! Output is full RGB (decoded back out as RGBA with A=255). Change
//! detection and content classification (used only for future
//! adaptive encoding, not yet consumed) still run on HDC features
//! computed from the original RGB pixels — only the *transmitted*
//! tile payload changed from grayscale to RGB.
//!
//! ## Wire format
//!
//! Each [`EncodedPacket`] body is a bincode-v1 serialization of
//! [`HdcPacket`]. The packet type (keyframe vs delta) is encoded
//! into the `tag` byte; every keyframe carries all
//! `tile_cols * tile_rows` tiles and is a valid self-contained
//! start-of-stream.

use crate::{
    CodecError, DecodedFrame, Decoder, EncodeParams, EncodedPacket, Encoder,
    PixelFormat as XvPixelFormat,
};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════════
// Tile features + band weighting
// ═══════════════════════════════════════════════════════════════════
//
// The original (ported-from-Symthaea) design materialized a dense
// `TILE_HDC_DIM`-length "position HV" per tile, multiplied 8 scalar
// pixel-statistics features into 8 equal-width bands of it, and took
// the cosine similarity of that 16,384-element vector against the
// previous frame's. That's exact but needlessly expensive: this
// codec only ever compares a tile against *itself* at a later frame
// (`HdcEncoder::prev_tiles[idx]` is indexed by tile position and never
// cross-compared against a different position), so the same position
// vector `pos` is reused on both sides of every similarity call.
//
// For two vectors built as `hv_a[i] = pos[i] * w_a[band(i)]` and
// `hv_b[i] = pos[i] * w_b[band(i)]` sharing the same `pos`:
//
//   dot(hv_a, hv_b) = Σ_i pos[i]² · w_a[band(i)] · w_b[band(i)]
//                   = Σ_band w_a[band] · w_b[band] · S[band]
//
// where `S[band] = Σ_{i in band} pos[i]²` depends only on the tile's
// position and is constant across every frame. So `S` can be computed
// **once per tile at encoder construction** (`N_BANDS` = 8 numbers,
// not `TILE_HDC_DIM` = 16,384), and the per-frame hot loop only ever
// needs the 8 scalar features — an exact (not approximate)
// ~2,048x reduction in the per-tile, per-frame comparison cost.
// Verified live 2026-07-05: at 1008×2244 (576 tiles), the pre-fix
// dense-vector path measured 276–2083ms/frame even in `--release`
// (see `examples/hdc_throughput.rs`) — unusable above ~1-3fps.

/// Number of pixel-statistics feature bands (see module comment).
/// Matches the original design's 8 bands of `TILE_HDC_DIM`.
const N_BANDS: usize = 8;

/// The 8 pixel-statistics features computed per tile. Order must
/// match [`generate_band_sumsq`]'s per-band weighting.
#[derive(Clone, Copy, Debug)]
struct TileFeatures {
    mean_lum: f32,
    contrast: f32,
    mean_r: f32,
    mean_g: f32,
    mean_b: f32,
    edge_density: f32,
    lum_contrast: f32,
    rb_diff: f32,
}

impl TileFeatures {
    const ZERO: Self = Self {
        mean_lum: 0.0,
        contrast: 0.0,
        mean_r: 0.0,
        mean_g: 0.0,
        mean_b: 0.0,
        edge_density: 0.0,
        lum_contrast: 0.0,
        rb_diff: 0.0,
    };

    fn as_array(&self) -> [f32; N_BANDS] {
        [
            self.mean_lum,
            self.contrast,
            self.mean_r,
            self.mean_g,
            self.mean_b,
            self.edge_density,
            self.lum_contrast,
            self.rb_diff,
        ]
    }
}

/// Cosine similarity between two tiles' feature vectors, weighted by
/// the shared tile position's per-band sum-of-squares (`band_sumsq`).
/// Exactly equivalent to comparing the two tiles' full
/// `TILE_HDC_DIM`-length position-modulated HVs (see module comment).
/// Returns `0.0` for the degenerate zero-norm case (both features
/// zero, e.g. the encoder's initial `prev_tiles` state).
fn weighted_cosine_similarity(
    a: &TileFeatures,
    b: &TileFeatures,
    band_sumsq: &[f32; N_BANDS],
) -> f32 {
    let (av, bv) = (a.as_array(), b.as_array());
    let mut dot = 0.0f32;
    let mut n_a = 0.0f32;
    let mut n_b = 0.0f32;
    for band in 0..N_BANDS {
        let s = band_sumsq[band];
        dot += av[band] * bv[band] * s;
        n_a += av[band] * av[band] * s;
        n_b += bv[band] * bv[band] * s;
    }
    let denom = (n_a * n_b).sqrt();
    if denom <= f32::EPSILON {
        0.0
    } else {
        dot / denom
    }
}

// ═══════════════════════════════════════════════════════════════════
// Codec constants + types
// ═══════════════════════════════════════════════════════════════════

/// Tile edge in pixels. 64×64 is Symthaea's canonical trade-off
/// between granularity and per-tile overhead.
pub const TILE_SIZE: usize = 64;

/// Conceptual HDC vector dimension inherited from Symthaea's default
/// (smaller would mean faster similarity compute but coarser change
/// detection). Since 2026-07-05 this is a construction-time-only cost
/// (see the "Tile features + band weighting" module comment above,
/// `generate_band_sumsq`) — the per-frame hot loop no longer
/// materializes a vector of this length at all.
pub const TILE_HDC_DIM: usize = 16_384;

/// Default cosine-similarity threshold above which a tile is
/// considered unchanged. Tuned on screen recordings; lower = more
/// aggressive change detection (more bandwidth), higher = more
/// static-skipping.
pub const DEFAULT_CHANGE_THRESHOLD: f32 = 0.92;

/// Max delta patches per packet. Mirrors Symthaea's
/// `rdp_protocol::MAX_DELTA_PATCHES`; keeps a single sealed
/// envelope under the replay-window-friendly size limit.
pub const MAX_DELTA_PATCHES: usize = 512;

/// Default interval between forced keyframes, in presentation-time
/// milliseconds. HDC's per-tile change detection is a coarse
/// 8-feature statistical comparison (see `encode_tile_hdc`), not an
/// exact pixel hash — genuinely different content can occasionally
/// alias to a similar-enough feature vector and be misclassified as
/// unchanged. Without periodic re-sync, a single missed tile-change
/// stays wrong for the rest of the session (verified live 2026-07-04:
/// a real window rearrangement left stale tiles on screen indefinitely).
/// A time-based (not frame-count-based) interval is used because HDC's
/// own frame rate is inherently irregular — it only encodes when the
/// damage-driven capture backend actually delivers a changed frame.
pub const DEFAULT_KEYFRAME_INTERVAL_MS: u64 = 10_000;

/// Content type detected by HDC classification. Used for future
/// adaptive encoding (e.g. lower-fidelity for text, JPEG for photos);
/// currently all non-skipped tiles emit as full RGB regardless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TileContentType {
    /// Static UI / icons / backgrounds — skippable.
    Static,
    /// Text / code. Needs sharp edges; near-lossless encoding.
    Text,
    /// Natural image / photo. JPEG-quality is fine.
    Photo,
    /// Video / animation. High-motion region.
    Video,
}

/// Per-tile change patch carried in a delta packet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TilePatch {
    /// Linear tile index = `row * tile_cols + col`.
    pub index: u16,
    /// Cosine-similarity surprise score `1.0 - similarity`. Higher
    /// means more changed. Receivers can prioritize by this value.
    pub surprise: f32,
    /// RGB pixel bytes (3 bytes/pixel, no alpha), `TILE_SIZE *
    /// TILE_SIZE * 3` of them for edge-aligned tiles (shorter at the
    /// right/bottom image edges where the tile is clipped).
    pub values: Vec<u8>,
    /// Detected content type for adaptive future encoding.
    pub content_type: TileContentType,
    /// Logical width of this tile (in pixels; equals
    /// `TILE_SIZE` except at image edges where the tile is clipped).
    pub tile_w: u16,
    /// Logical height (see `tile_w`).
    pub tile_h: u16,
}

/// A complete encoded HDC frame payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HdcPacket {
    /// `0x01` = keyframe (all tiles), `0x02` = delta (changed tiles).
    pub tag: u8,
    /// Image width in pixels.
    pub width: u32,
    /// Image height in pixels.
    pub height: u32,
    /// Number of tile columns.
    pub tile_cols: u16,
    /// Number of tile rows.
    pub tile_rows: u16,
    /// Serial frame id; monotonically increases per encoded frame.
    pub frame_id: u64,
    /// Source-time presentation timestamp in milliseconds.
    pub pts_ms: u64,
    /// Changed tile patches. For a keyframe this covers every tile
    /// in row-major order.
    pub patches: Vec<TilePatch>,
}

// ═══════════════════════════════════════════════════════════════════
// Per-tile state tracked across frames
// ═══════════════════════════════════════════════════════════════════

#[derive(Clone, Copy)]
struct TileState {
    features: TileFeatures,
    content_type: TileContentType,
    static_count: u32,
}

// ═══════════════════════════════════════════════════════════════════
// Encoder
// ═══════════════════════════════════════════════════════════════════

/// HDC hybrid-tile encoder. One instance per session.
pub struct HdcEncoder {
    params: EncodeParams,
    tile_cols: u16,
    tile_rows: u16,
    prev_tiles: Vec<TileState>,
    band_sumsq: Vec<[f32; N_BANDS]>,
    frame_count: u64,
    change_threshold: f32,
    static_threshold: u32,
    keyframe_interval_ms: u64,
    last_keyframe_pts_ms: u64,
}

impl HdcEncoder {
    /// Construct a new HDC encoder sized to the given frame params.
    /// Pixel format must be RGBA or BGRA; both are handled correctly
    /// (channel order is normalized to true RGB on the wire).
    pub fn new(params: EncodeParams) -> Self {
        // Tile grid dimensions (ceil-divide at image edges).
        let tile_cols = params.width.div_ceil(TILE_SIZE as u32) as u16;
        let tile_rows = params.height.div_ceil(TILE_SIZE as u32) as u16;
        let n_tiles = tile_cols as usize * tile_rows as usize;

        // Deterministic per-band position weighting, seeded per-tile
        // so each tile index gets a unique "where am I" weighting.
        // One-time construction cost only (see module comment above).
        let seed = (params.width as u64) * 0x100000000 + (params.height as u64);
        let band_sumsq: Vec<[f32; N_BANDS]> =
            (0..n_tiles).map(|i| generate_band_sumsq(i, seed)).collect();

        let prev_tiles = vec![
            TileState {
                features: TileFeatures::ZERO,
                content_type: TileContentType::Static,
                static_count: 0,
            };
            n_tiles
        ];

        Self {
            params,
            tile_cols,
            tile_rows,
            prev_tiles,
            band_sumsq,
            frame_count: 0,
            change_threshold: DEFAULT_CHANGE_THRESHOLD,
            static_threshold: params.target_fps.max(1), // ~1s of stillness = Static
            keyframe_interval_ms: DEFAULT_KEYFRAME_INTERVAL_MS,
            last_keyframe_pts_ms: 0,
        }
    }

    /// Adjust the change-detection threshold at runtime. Valid
    /// range `[0.5, 0.999]`.
    pub fn set_change_threshold(&mut self, t: f32) {
        self.change_threshold = t.clamp(0.5, 0.999);
    }

    /// Adjust the forced-keyframe interval at runtime (presentation-time
    /// milliseconds). `0` disables periodic re-sync entirely (not
    /// recommended — see `DEFAULT_KEYFRAME_INTERVAL_MS`'s doc comment).
    pub fn set_keyframe_interval_ms(&mut self, interval_ms: u64) {
        self.keyframe_interval_ms = interval_ms;
    }
}

impl Encoder for HdcEncoder {
    fn encode(&mut self, raw: &[u8], pts_ms: u64) -> Result<Vec<EncodedPacket>, CodecError> {
        let expected = self.params.frame_size();
        if raw.len() != expected {
            return Err(CodecError::InputMismatch(format!(
                "hdc: expected {} bytes for {}x{} {:?}, got {}",
                expected,
                self.params.width,
                self.params.height,
                self.params.pixel_format,
                raw.len()
            )));
        }

        // Periodic re-sync: force a keyframe on the first frame, or once
        // `keyframe_interval_ms` has elapsed since the last one, to bound
        // how long a missed/aliased tile-change detection can leave
        // stale content on screen. `pts_ms` is presentation time, not
        // wall-clock capture time, but the two track closely enough for
        // this purpose (a coarse periodic safety net, not a precise
        // timer). `saturating_sub` handles a `pts_ms` that resets/goes
        // backward (e.g. after an encoder rebuild on a resolution
        // change) by simply forcing a keyframe rather than underflowing.
        let is_keyframe = self.frame_count == 0
            || (self.keyframe_interval_ms > 0
                && pts_ms.saturating_sub(self.last_keyframe_pts_ms) >= self.keyframe_interval_ms);
        if is_keyframe {
            self.last_keyframe_pts_ms = pts_ms;
        }
        let width = self.params.width;
        let height = self.params.height;
        let mut patches: Vec<TilePatch> = Vec::new();

        for row in 0..self.tile_rows as usize {
            for col in 0..self.tile_cols as usize {
                let idx = row * self.tile_cols as usize + col;
                let tile_x = col * TILE_SIZE;
                let tile_y = row * TILE_SIZE;

                // Compute the current tile's pixel-statistics features.
                let tile_features = encode_tile_hdc(
                    raw,
                    width as usize,
                    height as usize,
                    tile_x,
                    tile_y,
                    TILE_SIZE,
                );

                let sim = weighted_cosine_similarity(
                    &self.prev_tiles[idx].features,
                    &tile_features,
                    &self.band_sumsq[idx],
                );
                let sim = if sim.is_finite() { sim } else { 0.0 };
                let changed = sim <= self.change_threshold;

                if changed {
                    self.prev_tiles[idx].static_count = 0;
                    let content = classify_tile_content(
                        raw,
                        width as usize,
                        height as usize,
                        tile_x,
                        tile_y,
                        TILE_SIZE,
                    );
                    self.prev_tiles[idx].content_type = content;
                } else {
                    self.prev_tiles[idx].static_count += 1;
                    if self.prev_tiles[idx].static_count >= self.static_threshold {
                        self.prev_tiles[idx].content_type = TileContentType::Static;
                    }
                }
                self.prev_tiles[idx].features = tile_features;

                // Emit the patch if it's a keyframe OR the tile
                // changed. Keyframes cover everything regardless.
                if is_keyframe || changed {
                    let (values, tile_w, tile_h) = extract_tile_rgb(
                        raw,
                        width as usize,
                        height as usize,
                        tile_x,
                        tile_y,
                        TILE_SIZE,
                        self.params.pixel_format == XvPixelFormat::Bgra,
                    );
                    patches.push(TilePatch {
                        index: idx as u16,
                        surprise: 1.0 - sim,
                        values,
                        content_type: self.prev_tiles[idx].content_type,
                        tile_w,
                        tile_h,
                    });

                    // Delta packets cap patches to keep each sealed
                    // envelope reasonably sized. A full keyframe is
                    // exempt — it always carries every tile even if
                    // that means a larger first packet.
                    if !is_keyframe && patches.len() >= MAX_DELTA_PATCHES {
                        break;
                    }
                }
            }
            if !is_keyframe && patches.len() >= MAX_DELTA_PATCHES {
                break;
            }
        }

        let frame_id = self.frame_count;
        self.frame_count += 1;

        let packet = HdcPacket {
            tag: if is_keyframe { 0x01 } else { 0x02 },
            width,
            height,
            tile_cols: self.tile_cols,
            tile_rows: self.tile_rows,
            frame_id,
            pts_ms,
            patches,
        };

        let bytes = bincode::serialize(&packet)
            .map_err(|e| CodecError::Backend(format!("hdc encode bincode: {e}")))?;

        Ok(vec![EncodedPacket {
            bytes,
            pts_ms,
            is_keyframe,
        }])
    }

    fn flush(&mut self) -> Result<Vec<EncodedPacket>, CodecError> {
        Ok(Vec::new())
    }

    fn params(&self) -> EncodeParams {
        self.params
    }
}

// ═══════════════════════════════════════════════════════════════════
// Decoder
// ═══════════════════════════════════════════════════════════════════

/// HDC decoder. Holds a full-frame canvas and patches incoming
/// deltas into it.
pub struct HdcDecoder {
    canvas: Vec<u8>,
    width: u32,
    height: u32,
    tile_cols: u16,
    tile_rows: u16,
    // Have we seen a keyframe yet? Deltas before the first
    // keyframe are rejected.
    primed: bool,
}

impl HdcDecoder {
    /// Construct a fresh decoder with no canvas. The first keyframe
    /// allocates the canvas and subsequent deltas patch into it.
    pub fn new() -> Self {
        Self {
            canvas: Vec::new(),
            width: 0,
            height: 0,
            tile_cols: 0,
            tile_rows: 0,
            primed: false,
        }
    }
}

impl Default for HdcDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for HdcDecoder {
    fn decode(&mut self, packet: &EncodedPacket) -> Result<Vec<DecodedFrame>, CodecError> {
        let pkt: HdcPacket = bincode::deserialize(&packet.bytes)
            .map_err(|e| CodecError::DecodeFailed(format!("hdc decode bincode: {e}")))?;

        // Reshape canvas to the packet's declared dimensions. A
        // stream can carry dimensions changes across keyframes.
        let canvas_len = (pkt.width as usize) * (pkt.height as usize) * 4;
        if pkt.tag == 0x01 {
            // Keyframe: (re)allocate canvas fresh.
            if self.canvas.len() != canvas_len {
                self.canvas = vec![0u8; canvas_len];
            } else {
                self.canvas.fill(0);
            }
            self.width = pkt.width;
            self.height = pkt.height;
            self.tile_cols = pkt.tile_cols;
            self.tile_rows = pkt.tile_rows;
            self.primed = true;
        } else if pkt.tag == 0x02 {
            if !self.primed {
                return Err(CodecError::DecodeFailed(
                    "hdc: delta received before first keyframe".into(),
                ));
            }
            if pkt.width != self.width || pkt.height != self.height {
                return Err(CodecError::DecodeFailed(
                    "hdc: delta declared different dimensions than current canvas".into(),
                ));
            }
        } else {
            return Err(CodecError::DecodeFailed(format!(
                "hdc: unknown packet tag {:#x}",
                pkt.tag
            )));
        }

        // Patch each tile into the canvas.
        for patch in &pkt.patches {
            let idx = patch.index as usize;
            if idx >= (self.tile_cols as usize) * (self.tile_rows as usize) {
                return Err(CodecError::DecodeFailed(format!(
                    "hdc: tile index {} out of range",
                    idx
                )));
            }
            let row = idx / self.tile_cols as usize;
            let col = idx % self.tile_cols as usize;
            let tile_x = col * TILE_SIZE;
            let tile_y = row * TILE_SIZE;
            let tw = patch.tile_w as usize;
            let th = patch.tile_h as usize;
            if patch.values.len() != tw * th * 3 {
                return Err(CodecError::DecodeFailed(format!(
                    "hdc: tile {} has {} bytes, declared {}×{}×3",
                    idx,
                    patch.values.len(),
                    tw,
                    th
                )));
            }
            for dy in 0..th {
                for dx in 0..tw {
                    let src_off = (dy * tw + dx) * 3;
                    let dst_off = ((tile_y + dy) * self.width as usize + (tile_x + dx)) * 4;
                    if dst_off + 3 < self.canvas.len() {
                        self.canvas[dst_off] = patch.values[src_off];
                        self.canvas[dst_off + 1] = patch.values[src_off + 1];
                        self.canvas[dst_off + 2] = patch.values[src_off + 2];
                        self.canvas[dst_off + 3] = 255;
                    }
                }
            }
        }

        Ok(vec![DecodedFrame {
            width: self.width,
            height: self.height,
            pixel_format: XvPixelFormat::Rgba,
            pixels: self.canvas.clone(),
            pts_ms: pkt.pts_ms,
        }])
    }

    fn flush(&mut self) -> Result<Vec<DecodedFrame>, CodecError> {
        Ok(Vec::new())
    }

    fn output_format(&self) -> XvPixelFormat {
        XvPixelFormat::Rgba
    }
}

// ═══════════════════════════════════════════════════════════════════
// Internal helpers — ported from Symthaea's rdp_codec.rs
// ═══════════════════════════════════════════════════════════════════

/// Deterministic per-band sum-of-squares weighting for one tile
/// position. Same seed => same weighting. Used to domain-separate
/// tiles so two visually-identical tiles at different positions
/// compare with different band weights (exactly reproduces the
/// original dense-position-HV design's behavior — see the "Tile
/// features + band weighting" module comment above — at 1/2,048th
/// the per-tile cost, and only at encoder-construction time, never
/// per frame).
fn generate_band_sumsq(index: usize, seed: u64) -> [f32; N_BANDS] {
    let combined = seed
        .wrapping_add(index as u64)
        .wrapping_mul(0x517cc1b727220a95);
    let band_size = TILE_HDC_DIM / N_BANDS;
    let mut sumsq = [0.0f32; N_BANDS];
    let mut state = combined;
    for i in 0..TILE_HDC_DIM {
        let hash = blake3::hash(&state.to_le_bytes());
        let bytes = hash.as_bytes();
        let u =
            u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f32 / u32::MAX as f32;
        let v = (u - 0.5) * 2.0; // centered in [-1, 1]
        sumsq[i / band_size] += v * v;
        state = state.wrapping_add(1);
    }
    sumsq
}

/// Feature-extract a tile's pixel content into its 8 pixel-statistics
/// features (luminance mean, contrast, RGB means, edge density, and
/// two interaction terms). These correspond 1:1 with the original
/// design's 8 equal-width position-HV bands (see module comment).
fn encode_tile_hdc(
    pixels: &[u8],
    img_width: usize,
    img_height: usize,
    tile_x: usize,
    tile_y: usize,
    tile_size: usize,
) -> TileFeatures {
    let mut lum_sum = 0.0f32;
    let mut lum_sq_sum = 0.0f32;
    let mut r_sum = 0.0f32;
    let mut g_sum = 0.0f32;
    let mut b_sum = 0.0f32;
    let mut edge_energy = 0.0f32;
    let mut pixel_count = 0u32;

    for dy in 0..tile_size {
        let y = tile_y + dy;
        if y >= img_height {
            break;
        }
        for dx in 0..tile_size {
            let x = tile_x + dx;
            if x >= img_width {
                break;
            }
            let offset = (y * img_width + x) * 4;
            if offset + 3 >= pixels.len() {
                break;
            }
            let r = pixels[offset] as f32 / 255.0;
            let g = pixels[offset + 1] as f32 / 255.0;
            let b = pixels[offset + 2] as f32 / 255.0;
            let lum = 0.299 * r + 0.587 * g + 0.114 * b;

            lum_sum += lum;
            lum_sq_sum += lum * lum;
            r_sum += r;
            g_sum += g;
            b_sum += b;
            pixel_count += 1;

            if dx > 0 {
                let prev_offset = (y * img_width + x - 1) * 4;
                if prev_offset + 3 < pixels.len() {
                    let prev_lum = 0.299 * pixels[prev_offset] as f32 / 255.0
                        + 0.587 * pixels[prev_offset + 1] as f32 / 255.0
                        + 0.114 * pixels[prev_offset + 2] as f32 / 255.0;
                    edge_energy += (lum - prev_lum).abs();
                }
            }
        }
    }

    let n = pixel_count.max(1) as f32;
    let mean_lum = lum_sum / n;
    let variance = (lum_sq_sum / n - mean_lum * mean_lum).max(0.0);
    let contrast = variance.sqrt();
    let mean_r = r_sum / n;
    let mean_g = g_sum / n;
    let mean_b = b_sum / n;
    let edge_density = edge_energy / n;

    TileFeatures {
        mean_lum,
        contrast,
        mean_r,
        mean_g,
        mean_b,
        edge_density,
        lum_contrast: mean_lum * contrast,
        rb_diff: (mean_r - mean_b).abs(),
    }
}

/// Classify a tile's content type from its pixel statistics.
/// Heuristics: low-variance = Static, high-edge-density = Text,
/// balanced = Photo, high-lum-variance = Video.
fn classify_tile_content(
    pixels: &[u8],
    img_width: usize,
    img_height: usize,
    tile_x: usize,
    tile_y: usize,
    tile_size: usize,
) -> TileContentType {
    let mut lum_sum = 0.0f32;
    let mut lum_sq_sum = 0.0f32;
    let mut edge_count = 0u32;
    let mut n = 0u32;

    for dy in 0..tile_size {
        let y = tile_y + dy;
        if y >= img_height {
            break;
        }
        for dx in 0..tile_size {
            let x = tile_x + dx;
            if x >= img_width {
                break;
            }
            let offset = (y * img_width + x) * 4;
            if offset + 3 >= pixels.len() {
                break;
            }
            let r = pixels[offset] as f32 / 255.0;
            let g = pixels[offset + 1] as f32 / 255.0;
            let b = pixels[offset + 2] as f32 / 255.0;
            let lum = 0.299 * r + 0.587 * g + 0.114 * b;
            lum_sum += lum;
            lum_sq_sum += lum * lum;
            n += 1;

            if dx > 0 {
                let prev_offset = (y * img_width + x - 1) * 4;
                if prev_offset + 3 < pixels.len() {
                    let prev_lum = 0.299 * pixels[prev_offset] as f32 / 255.0
                        + 0.587 * pixels[prev_offset + 1] as f32 / 255.0
                        + 0.114 * pixels[prev_offset + 2] as f32 / 255.0;
                    if (lum - prev_lum).abs() > 0.15 {
                        edge_count += 1;
                    }
                }
            }
        }
    }

    if n < 2 {
        return TileContentType::Static;
    }
    let mean = lum_sum / n as f32;
    let variance = (lum_sq_sum / n as f32 - mean * mean).max(0.0);
    let edge_density = edge_count as f32 / n as f32;

    if variance < 0.005 {
        TileContentType::Static
    } else if edge_density > 0.15 {
        TileContentType::Text
    } else if variance > 0.1 {
        TileContentType::Video
    } else {
        TileContentType::Photo
    }
}

/// Extract a tile's pixels as 8-bit-per-channel RGB (row-major,
/// 3 bytes/pixel — no alpha, since decoded output always sets
/// A=255). Returns the bytes + the logical (width, height) of the
/// tile, which may be less than `tile_size` at the image's
/// right/bottom edge where the tile is clipped.
///
/// `bgra` must reflect the source frame's actual channel order —
/// unlike the old grayscale extraction (luminance is symmetric in
/// R/B), true RGB output needs the right order or red/blue channels
/// come out swapped for BGRA-sourced frames.
fn extract_tile_rgb(
    pixels: &[u8],
    img_width: usize,
    img_height: usize,
    tile_x: usize,
    tile_y: usize,
    tile_size: usize,
    bgra: bool,
) -> (Vec<u8>, u16, u16) {
    let tw = tile_size.min(img_width.saturating_sub(tile_x));
    let th = tile_size.min(img_height.saturating_sub(tile_y));
    let mut out = Vec::with_capacity(tw * th * 3);
    for dy in 0..th {
        let y = tile_y + dy;
        for dx in 0..tw {
            let x = tile_x + dx;
            let offset = (y * img_width + x) * 4;
            if offset + 3 >= pixels.len() {
                out.extend_from_slice(&[0, 0, 0]);
                continue;
            }
            let (c0, c1, c2) = (pixels[offset], pixels[offset + 1], pixels[offset + 2]);
            if bgra {
                // Source order is B,G,R -> emit R,G,B.
                out.push(c2);
                out.push(c1);
                out.push(c0);
            } else {
                // Source order is already R,G,B.
                out.push(c0);
                out.push(c1);
                out.push(c2);
            }
        }
    }
    (out, tw as u16, th as u16)
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn params(w: u32, h: u32) -> EncodeParams {
        EncodeParams {
            width: w,
            height: h,
            pixel_format: XvPixelFormat::Rgba,
            target_fps: 30,
            bitrate_kbps: 1000, // ignored by HDC
        }
    }

    fn constant_frame(w: u32, h: u32, v: u8) -> Vec<u8> {
        let mut p = vec![0u8; (w * h * 4) as usize];
        for i in 0..(w * h) as usize {
            p[i * 4] = v;
            p[i * 4 + 1] = v;
            p[i * 4 + 2] = v;
            p[i * 4 + 3] = 255;
        }
        p
    }

    fn gradient_frame(w: u32, h: u32, seed: u8) -> Vec<u8> {
        let mut p = vec![0u8; (w * h * 4) as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = (y * w as usize + x) * 4;
                p[i] = (x as u8).wrapping_add(seed);
                p[i + 1] = (y as u8).wrapping_add(seed);
                p[i + 2] = seed.wrapping_mul(3);
                p[i + 3] = 255;
            }
        }
        p
    }

    #[test]
    fn weighted_cosine_similarity_is_sane() {
        let uniform_weights = [1.0f32; N_BANDS];
        let a = TileFeatures {
            mean_lum: 1.0,
            contrast: 1.0,
            mean_r: 1.0,
            mean_g: 1.0,
            mean_b: 1.0,
            edge_density: 1.0,
            lum_contrast: 1.0,
            rb_diff: 1.0,
        };
        let b = a;
        let c = TileFeatures {
            mean_lum: -1.0,
            contrast: -1.0,
            mean_r: -1.0,
            mean_g: -1.0,
            mean_b: -1.0,
            edge_density: -1.0,
            lum_contrast: -1.0,
            rb_diff: -1.0,
        };
        assert!((weighted_cosine_similarity(&a, &b, &uniform_weights) - 1.0).abs() < 1e-6);
        assert!((weighted_cosine_similarity(&a, &c, &uniform_weights) + 1.0).abs() < 1e-6);
        assert_eq!(
            weighted_cosine_similarity(&a, &TileFeatures::ZERO, &uniform_weights),
            0.0
        );
    }

    #[test]
    fn weighted_cosine_similarity_matches_dense_hv_reduction() {
        // Directly verifies the module's core claim: comparing two
        // 8-feature TileFeatures with band_sumsq weights gives the
        // exact same result as materializing the original dense
        // TILE_HDC_DIM-length position-modulated vectors and taking
        // their plain cosine similarity.
        let band_sumsq = generate_band_sumsq(7, 0xABCD_1234);
        // Reconstruct the dense position vector this band_sumsq was
        // derived from, band-by-band, to build reference dense HVs.
        let seed = 0xABCD_1234u64;
        let index = 7usize;
        let combined = seed
            .wrapping_add(index as u64)
            .wrapping_mul(0x517cc1b727220a95);
        let band_size = TILE_HDC_DIM / N_BANDS;
        let mut pos = vec![0.0f32; TILE_HDC_DIM];
        let mut state = combined;
        for v in pos.iter_mut() {
            let hash = blake3::hash(&state.to_le_bytes());
            let bytes = hash.as_bytes();
            let u = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as f32
                / u32::MAX as f32;
            *v = (u - 0.5) * 2.0;
            state = state.wrapping_add(1);
        }

        let a = TileFeatures {
            mean_lum: 0.3,
            contrast: 0.1,
            mean_r: 0.5,
            mean_g: 0.2,
            mean_b: 0.4,
            edge_density: 0.05,
            lum_contrast: 0.03,
            rb_diff: 0.1,
        };
        let b = TileFeatures {
            mean_lum: 0.35,
            contrast: 0.12,
            mean_r: 0.45,
            mean_g: 0.25,
            mean_b: 0.38,
            edge_density: 0.06,
            lum_contrast: 0.042,
            rb_diff: 0.07,
        };

        let dense = |f: &TileFeatures| -> Vec<f32> {
            let w = f.as_array();
            pos.iter()
                .enumerate()
                .map(|(i, p)| p * w[i / band_size])
                .collect()
        };
        let dense_a = dense(&a);
        let dense_b = dense(&b);
        let dot: f32 = dense_a.iter().zip(dense_b.iter()).map(|(x, y)| x * y).sum();
        let na: f32 = dense_a.iter().map(|x| x * x).sum();
        let nb: f32 = dense_b.iter().map(|y| y * y).sum();
        let reference_sim = dot / (na * nb).sqrt();

        let fast_sim = weighted_cosine_similarity(&a, &b, &band_sumsq);
        assert!(
            (reference_sim - fast_sim).abs() < 1e-3,
            "reference={reference_sim} fast={fast_sim}"
        );
    }

    #[test]
    fn keyframe_then_delta_roundtrip() {
        // First frame → keyframe → decoder populates canvas.
        // Second identical frame → delta with zero patches.
        // Third different frame → delta patches the changed tiles.
        let w = 128;
        let h = 128;
        let p = params(w, h);
        let mut enc = HdcEncoder::new(p);
        let mut dec = HdcDecoder::new();

        let f0 = gradient_frame(w, h, 0);
        let pkt0 = enc.encode(&f0, 0).unwrap();
        assert_eq!(pkt0.len(), 1);
        assert!(pkt0[0].is_keyframe);
        let dec0 = dec.decode(&pkt0[0]).unwrap();
        assert_eq!(dec0.len(), 1);
        assert_eq!(dec0[0].width, w);
        assert_eq!(dec0[0].height, h);

        // Identical second frame: HDC sees similarity ~1.0 for every
        // tile, so delta has zero patches. Decoded canvas is still
        // the keyframe's canvas.
        let pkt1 = enc.encode(&f0, 33).unwrap();
        assert!(!pkt1[0].is_keyframe);
        let _ = dec.decode(&pkt1[0]).unwrap();

        // Different frame: many patches.
        let f2 = gradient_frame(w, h, 50);
        let pkt2 = enc.encode(&f2, 66).unwrap();
        assert!(!pkt2[0].is_keyframe);
        let dec2 = dec.decode(&pkt2[0]).unwrap();
        assert_eq!(dec2[0].width, w);
        assert_eq!(dec2[0].height, h);
    }

    #[test]
    fn constant_frame_after_keyframe_emits_no_patches() {
        let w = 128;
        let h = 128;
        let p = params(w, h);
        let mut enc = HdcEncoder::new(p);
        let f = constant_frame(w, h, 128);
        let pkt0 = enc.encode(&f, 0).unwrap();
        // Keyframe carries all tiles.
        let body0: HdcPacket = bincode::deserialize(&pkt0[0].bytes).unwrap();
        assert_eq!(
            body0.patches.len() as u16,
            body0.tile_cols * body0.tile_rows
        );
        // Second identical frame: all tiles above the similarity
        // threshold, so zero patches.
        let pkt1 = enc.encode(&f, 33).unwrap();
        let body1: HdcPacket = bincode::deserialize(&pkt1[0].bytes).unwrap();
        assert_eq!(body1.patches.len(), 0);
    }

    #[test]
    fn periodic_keyframe_forces_resync_even_with_no_visible_change() {
        // Regression test for a real bug found live 2026-07-04: without
        // periodic re-sync, a tile-change detector miss (or an
        // intentionally-unchanged screen) means the decoder's canvas
        // can never self-correct. A constant (never-changing) frame
        // should still get a fresh keyframe once keyframe_interval_ms
        // has elapsed, purely from the passage of presentation time.
        let w = 128;
        let h = 128;
        let p = params(w, h);
        let mut enc = HdcEncoder::new(p);
        enc.set_keyframe_interval_ms(1_000);
        let f = constant_frame(w, h, 64);

        let pkt0 = enc.encode(&f, 0).unwrap();
        assert!(pkt0[0].is_keyframe, "frame 0 is always a keyframe");

        // Still well inside the interval: identical content, zero patches.
        let pkt1 = enc.encode(&f, 500).unwrap();
        assert!(!pkt1[0].is_keyframe);
        let body1: HdcPacket = bincode::deserialize(&pkt1[0].bytes).unwrap();
        assert_eq!(body1.patches.len(), 0);

        // Past the interval: must force a fresh keyframe covering every
        // tile, even though the frame content hasn't changed at all.
        let pkt2 = enc.encode(&f, 1_500).unwrap();
        assert!(
            pkt2[0].is_keyframe,
            "expected a forced keyframe once keyframe_interval_ms elapsed"
        );
        let body2: HdcPacket = bincode::deserialize(&pkt2[0].bytes).unwrap();
        assert_eq!(
            body2.patches.len() as u16,
            body2.tile_cols * body2.tile_rows
        );

        // Interval resets from the forced keyframe, not the original one.
        let pkt3 = enc.encode(&f, 1_600).unwrap();
        assert!(!pkt3[0].is_keyframe);
    }

    #[test]
    fn zero_keyframe_interval_disables_periodic_resync() {
        let w = 64;
        let h = 64;
        let p = params(w, h);
        let mut enc = HdcEncoder::new(p);
        enc.set_keyframe_interval_ms(0);
        let f = constant_frame(w, h, 200);

        let _ = enc.encode(&f, 0).unwrap();
        // Even a huge pts_ms gap must not force a keyframe when the
        // interval is explicitly disabled.
        let pkt = enc.encode(&f, 1_000_000).unwrap();
        assert!(!pkt[0].is_keyframe);
    }

    #[test]
    fn encode_rejects_wrong_size() {
        let p = params(64, 64);
        let mut enc = HdcEncoder::new(p);
        let err = enc.encode(&[0u8; 32], 0).unwrap_err();
        assert!(matches!(err, CodecError::InputMismatch(_)));
    }

    #[test]
    fn delta_before_keyframe_fails() {
        let w = 64;
        let h = 64;
        let p = params(w, h);
        let mut enc = HdcEncoder::new(p);
        // Consume the keyframe; feed the NEXT (delta) packet to a
        // fresh decoder that hasn't seen it.
        let _ = enc.encode(&gradient_frame(w, h, 0), 0).unwrap();
        let delta = enc.encode(&gradient_frame(w, h, 1), 33).unwrap();
        let mut fresh = HdcDecoder::new();
        let err = fresh.decode(&delta[0]).unwrap_err();
        assert!(matches!(err, CodecError::DecodeFailed(_)));
    }

    #[test]
    fn band_sumsq_is_deterministic_per_seed() {
        let a = generate_band_sumsq(0, 42);
        let b = generate_band_sumsq(0, 42);
        assert_eq!(a, b);
        let c = generate_band_sumsq(1, 42);
        // Same seed, different index => different weighting.
        assert_ne!(a, c);
    }

    /// A frame with distinct, non-grayscale R/G/B channels (pure
    /// red on one half, pure blue on the other) — verifies the codec
    /// actually round-trips color, not just luminance. A pre-RGB-output
    /// codec would flatten both halves to different-but-colorless
    /// gray levels; this catches that regression directly.
    fn two_tone_rgba_frame(w: u32, h: u32) -> Vec<u8> {
        let mut p = vec![0u8; (w * h * 4) as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = (y * w as usize + x) * 4;
                if x < w as usize / 2 {
                    p[i] = 255; // R
                    p[i + 1] = 0;
                    p[i + 2] = 0;
                } else {
                    p[i] = 0;
                    p[i + 1] = 0;
                    p[i + 2] = 255; // B
                }
                p[i + 3] = 255;
            }
        }
        p
    }

    #[test]
    fn decoded_output_preserves_true_color_not_just_luminance() {
        let w = 128;
        let h = 128;
        let p = params(w, h);
        let mut enc = HdcEncoder::new(p);
        let mut dec = HdcDecoder::new();

        let frame = two_tone_rgba_frame(w, h);
        let pkt = enc.encode(&frame, 0).unwrap();
        let decoded = dec.decode(&pkt[0]).unwrap();
        let pixels = &decoded[0].pixels;

        // Sample a pixel well inside the red half.
        let red_off = (10 * w as usize + 10) * 4;
        assert_eq!(pixels[red_off], 255, "red channel");
        assert_eq!(pixels[red_off + 1], 0, "green channel");
        assert_eq!(pixels[red_off + 2], 0, "blue channel");

        // Sample a pixel well inside the blue half.
        let blue_off = (10 * w as usize + (w as usize - 10)) * 4;
        assert_eq!(pixels[blue_off], 0, "red channel");
        assert_eq!(pixels[blue_off + 1], 0, "green channel");
        assert_eq!(pixels[blue_off + 2], 255, "blue channel");
    }

    #[test]
    fn bgra_input_normalizes_to_true_rgb_on_the_wire() {
        // Same two-tone image, but stored in BGRA byte order (as if
        // sourced from a BGRA capture backend). Swap R<->B on top of
        // the RGBA test fixture to build a real BGRA buffer.
        let w = 128;
        let h = 128;
        let mut frame = two_tone_rgba_frame(w, h);
        for chunk in frame.chunks_exact_mut(4) {
            chunk.swap(0, 2);
        }

        let mut p = params(w, h);
        p.pixel_format = XvPixelFormat::Bgra;
        let mut enc = HdcEncoder::new(p);
        let mut dec = HdcDecoder::new();

        let pkt = enc.encode(&frame, 0).unwrap();
        let decoded = dec.decode(&pkt[0]).unwrap();
        let pixels = &decoded[0].pixels;

        // Decoded output is always RGBA regardless of input order —
        // must match the same true colors as the RGBA-input test.
        let red_off = (10 * w as usize + 10) * 4;
        assert_eq!(pixels[red_off], 255, "red channel");
        assert_eq!(pixels[red_off + 1], 0, "green channel");
        assert_eq!(pixels[red_off + 2], 0, "blue channel");

        let blue_off = (10 * w as usize + (w as usize - 10)) * 4;
        assert_eq!(pixels[blue_off], 0, "red channel");
        assert_eq!(pixels[blue_off + 1], 0, "green channel");
        assert_eq!(pixels[blue_off + 2], 255, "blue channel");
    }
}

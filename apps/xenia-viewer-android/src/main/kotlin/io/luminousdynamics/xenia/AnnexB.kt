package io.luminousdynamics.xenia

/**
 * Minimal Annex-B NAL-unit scanning, ported from
 * `xenia-wire/xenia-viewer-web/src/h264.rs`'s `is_keyframe_chunk`
 * (same logic, Kotlin instead of Rust -- `xenia-mobile-ffi` doesn't
 * expose this over the FFI boundary, and duplicating ~15 lines here
 * is simpler than adding new FFI surface just for it).
 *
 * `xenia_video::h264::H264Encoder` emits Annex-B (start-code-prefixed)
 * packets, and every keyframe access unit carries its SPS/PPS inline
 * (the desktop's own `H264Decoder` learns dimensions from the
 * in-stream SPS rather than needing them supplied upfront) --
 * Android's `MediaCodec` can do the same, so [H264Decoder] only needs
 * to know *when* a chunk is a real keyframe access unit to safely
 * start decoding from it.
 */
object AnnexB {
    /** `true` if this Annex-B chunk contains an IDR slice (NAL type 5). */
    fun isKeyframeChunk(bytes: ByteArray): Boolean {
        var i = 0
        while (i + 2 < bytes.size) {
            if (bytes[i] == 0.toByte() && bytes[i + 1] == 0.toByte() && bytes[i + 2] == 1.toByte()) {
                val contentStart = i + 3
                if (contentStart < bytes.size && (bytes[contentStart].toInt() and 0x1F) == 5) {
                    return true
                }
                i += 3
            } else {
                i += 1
            }
        }
        return false
    }
}

package io.luminousdynamics.xenia

import android.media.MediaCodec
import android.media.MediaFormat
import android.util.Log
import android.view.Surface

/**
 * Wraps Android's hardware `MediaCodec` for Annex-B H.264 decode,
 * configured with an output [Surface] rather than raw byte-buffer
 * output. That's a deliberate choice over manually pulling YUV
 * buffers and converting them to RGB in Kotlin: color-format handling
 * (NV12 vs. I420 vs. device-specific variants, plane strides) is a
 * real correctness minefield across devices, whereas Surface output
 * lets the platform's own hardware decoder handle color conversion
 * and composition directly -- simpler and faster, and the standard
 * way real Android video players use `MediaCodec`.
 *
 * Lazily configures on the first real keyframe access unit (SPS+PPS+
 * IDR all together -- see [AnnexB]'s doc for why that's always true
 * here): `MediaCodec` picks up SPS/PPS from the in-band Annex-B stream
 * the same way the desktop's own `xenia_video::h264::H264Decoder`
 * does, so there's no need to extract them separately as
 * `MediaFormat` csd-0/csd-1.
 */
class H264Decoder(private val surface: Surface, private val width: Int, private val height: Int) {
    private var codec: MediaCodec? = null

    /** Feed one Annex-B chunk (one or more NALs from one wire frame). */
    fun feed(nal: ByteArray, isKeyframe: Boolean) {
        if (codec == null) {
            if (!isKeyframe) return // wait for a real keyframe to start
            codec = startCodec()
        }
        val c = codec ?: return

        try {
            val inIndex = c.dequeueInputBuffer(10_000)
            if (inIndex >= 0) {
                val buf = c.getInputBuffer(inIndex)
                if (buf != null) {
                    buf.clear()
                    buf.put(nal)
                    c.queueInputBuffer(inIndex, 0, nal.size, System.nanoTime() / 1000, 0)
                }
            }
            val info = MediaCodec.BufferInfo()
            var outIndex = c.dequeueOutputBuffer(info, 0)
            while (outIndex >= 0) {
                c.releaseOutputBuffer(outIndex, true) // true = render to the Surface
                outIndex = c.dequeueOutputBuffer(info, 0)
            }
        } catch (e: Exception) {
            // Best-effort: a malformed/truncated chunk shouldn't crash the
            // viewer -- drop it and let the next real keyframe resync,
            // matching the daemon's own periodic-keyframe philosophy for
            // its other codecs.
            Log.w("XeniaH264", "dropped a frame", e)
        }
    }

    fun release() {
        try {
            codec?.stop()
        } catch (_: Exception) {
            // Already stopped/never started -- fine.
        }
        codec?.release()
        codec = null
    }

    private fun startCodec(): MediaCodec? {
        return try {
            val format = MediaFormat.createVideoFormat("video/avc", width, height)
            val mc = MediaCodec.createDecoderByType("video/avc")
            mc.configure(format, surface, null, 0)
            mc.start()
            mc
        } catch (e: Exception) {
            Log.e("XeniaH264", "MediaCodec configure/start failed", e)
            null
        }
    }
}

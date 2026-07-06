package io.luminousdynamics.xenia

/**
 * JNI bindings to the native `xenia-mobile-ffi` Rust library.
 *
 * All functions map 1:1 to the `extern "C"` surface in
 * `xenia-mobile-ffi/src/lib.rs`. The session handle is an opaque
 * pointer (Long) -- callers must not interpret or fabricate handle
 * values.
 *
 * `pollFrame` returns the packed header+RGBA byte array described in
 * `xenia_jni.c`'s doc comment (width/height/pts_ms header, then RGBA
 * payload), or `null` if no frame is queued yet. [XeniaSession]
 * unpacks it.
 */
internal object NativeBindings {
    init {
        System.loadLibrary("xenia_jni")
    }

    const val CODEC_PASSTHROUGH: Int = 0
    const val CODEC_HDC: Int = 1
    const val CODEC_H264: Int = 2

    const val STATE_CONNECTING: Int = 0
    const val STATE_CONNECTED: Int = 1
    const val STATE_DISCONNECTED: Int = 2
    const val STATE_ERROR: Int = 3
    const val STATE_INVALID_HANDLE: Int = -1

    @JvmStatic external fun connect(hostPort: String, codec: Int): Long
    @JvmStatic external fun sessionState(handle: Long): Int
    @JvmStatic external fun lastError(handle: Long): String?
    @JvmStatic external fun pollFrame(handle: Long): ByteArray?
    @JvmStatic external fun sendPointer(handle: Long, x: Float, y: Float, button: Int, pressed: Boolean)
    @JvmStatic external fun sendTouch(handle: Long, index: Int, x: Float, y: Float, phase: Int, pressure: Float)
    @JvmStatic external fun sendKey(handle: Long, code: Int, pressed: Boolean, modifiers: Int)
    @JvmStatic external fun disconnect(handle: Long)
}

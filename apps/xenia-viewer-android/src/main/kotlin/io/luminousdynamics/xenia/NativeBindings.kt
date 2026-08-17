package io.luminousdynamics.xenia

/**
 * JNI bindings to the native `xenia-mobile-ffi` Rust library.
 *
 * All functions map 1:1 to the `extern "C"` surface in
 * `xenia-mobile-ffi/src/lib.rs`. The session handle is an opaque
 * process-local registry id (Long), not a native pointer. Callers should still
 * treat it as opaque; stale or fabricated ids are rejected by Rust.
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

    // Event kinds returned by pollFileTransferEvent's packed header
    // (byte 0) -- mirrors XENIA_FT_EVENT_* in xenia-mobile-ffi/src/lib.rs.
    const val FT_EVENT_INCOMING_OFFER: Int = 1
    const val FT_EVENT_PROGRESS: Int = 2
    const val FT_EVENT_DONE: Int = 3

    const val SEND_FILE_OK: Int = 0
    const val SEND_FILE_INVALID_ARGUMENT: Int = 1
    const val SEND_FILE_INVALID_HANDLE: Int = 2
    const val SEND_FILE_QUEUE_FULL: Int = 3
    const val SEND_FILE_SESSION_CLOSED: Int = 4
    const val SEND_FILE_TOO_LARGE: Int = 5
    const val SEND_FILE_INVALID_RESERVATION: Int = 6
    const val SEND_FILE_RESERVATION_SIZE_MISMATCH: Int = 7
    const val SEND_FILE_IO_ERROR: Int = 8

    @JvmStatic external fun connect(hostPort: String, codec: Int, recvDir: String?, stagingDir: String?, maxFileBytes: Long): Long
    @JvmStatic external fun sessionState(handle: Long): Int
    @JvmStatic external fun lastError(handle: Long): String?
    @JvmStatic external fun pollFrame(handle: Long): ByteArray?
    @JvmStatic external fun sendPointer(handle: Long, x: Float, y: Float, button: Int, pressed: Boolean)
    @JvmStatic external fun sendPointerMove(handle: Long, x: Float, y: Float)
    @JvmStatic external fun sendPointerButton(handle: Long, x: Float, y: Float, button: Int, pressed: Boolean)
    @JvmStatic external fun sendTouch(handle: Long, index: Int, x: Float, y: Float, phase: Int, pressure: Float)
    @JvmStatic external fun sendKey(handle: Long, code: Int, pressed: Boolean, modifiers: Int)
    @JvmStatic external fun pollClipboard(handle: Long): String?
    @JvmStatic external fun sendClipboard(handle: Long, text: String?)
    @JvmStatic external fun fileTransferAdmissionSnapshot(handle: Long): IntArray?
    @JvmStatic external fun fileTransferAdmissionSnapshotV2(handle: Long): LongArray?
    @JvmStatic external fun trySendFile(handle: Long, name: String, data: ByteArray): Int
    /** Returns [status, token]; expectedLen=-1 means provider length unknown. */
    @JvmStatic external fun beginSendFileStream(handle: Long, name: String, expectedLen: Long): LongArray?
    @JvmStatic external fun appendSendFileStream(handle: Long, token: Long, data: ByteArray, dataLen: Int): Int
    @JvmStatic external fun finishSendFileStream(handle: Long, token: Long): Int
    @JvmStatic external fun cancelSendFileStream(handle: Long, token: Long): Boolean
    /** Legacy Boolean wrapper retained for ABI/source compatibility. */
    @JvmStatic external fun sendFile(handle: Long, name: String, data: ByteArray): Boolean
    @JvmStatic external fun pollFileTransferEvent(handle: Long): ByteArray?
    @JvmStatic external fun disconnect(handle: Long)
}

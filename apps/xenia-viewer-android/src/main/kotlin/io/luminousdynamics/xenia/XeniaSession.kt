package io.luminousdynamics.xenia

import android.graphics.Bitmap
import java.io.InputStream
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/**
 * One thing that happened to a file transfer, mirroring
 * `xenia_mobile_ffi::engine::FileTransferEvent` (see
 * `NativeBindings.pollFileTransferEvent`'s doc comment for the wire
 * packing this is unpacked from). File transfer is symmetric --
 * either side can send or receive any given `transferId` -- so
 * [Progress]/[Done] carry `outgoing` to disambiguate which role this
 * side is playing for that transfer.
 */
sealed class FileTransferEvent {
    /** The host offered a file; auto-accepted/rejected based on
     * whether [XeniaSession] was constructed with a non-null
     * `recvDir` (mirrors `xenia-viewer`'s own flag-driven, no-prompt
     * consent model -- see the project plan). */
    data class IncomingOffer(
        val transferId: Long,
        val name: String,
        val totalBytes: Long,
        val accepted: Boolean,
        val reason: String,
    ) : FileTransferEvent()

    data class Progress(
        val transferId: Long,
        val name: String,
        val doneBytes: Long,
        val totalBytes: Long,
        val outgoing: Boolean,
    ) : FileTransferEvent()

    data class Done(
        val transferId: Long,
        val name: String,
        val outgoing: Boolean,
        val ok: Boolean,
        val detail: String,
    ) : FileTransferEvent()
}

/** Mirrors [NativeBindings]'s `STATE_*` constants as a Kotlin enum. */
enum class SessionState { CONNECTING, CONNECTED, DISCONNECTED, ERROR, INVALID }

/** Exact local admission result for a user-triggered outbound file command. */
enum class FileSendResult {
    ACCEPTED,
    INVALID_ARGUMENT,
    INVALID_HANDLE,
    QUEUE_FULL,
    SESSION_CLOSED,
    TOO_LARGE,
    INVALID_RESERVATION,
    RESERVATION_SIZE_MISMATCH,
    IO_ERROR,
    UNKNOWN;

    companion object {
        internal fun fromNative(code: Int): FileSendResult = when (code) {
            NativeBindings.SEND_FILE_OK -> ACCEPTED
            NativeBindings.SEND_FILE_INVALID_ARGUMENT -> INVALID_ARGUMENT
            NativeBindings.SEND_FILE_INVALID_HANDLE -> INVALID_HANDLE
            NativeBindings.SEND_FILE_QUEUE_FULL -> QUEUE_FULL
            NativeBindings.SEND_FILE_SESSION_CLOSED -> SESSION_CLOSED
            NativeBindings.SEND_FILE_TOO_LARGE -> TOO_LARGE
            NativeBindings.SEND_FILE_INVALID_RESERVATION -> INVALID_RESERVATION
            NativeBindings.SEND_FILE_RESERVATION_SIZE_MISMATCH -> RESERVATION_SIZE_MISMATCH
            NativeBindings.SEND_FILE_IO_ERROR -> IO_ERROR
            else -> UNKNOWN
        }
    }
}

data class FileTransferAdmissionSnapshot(
    val activeReserved: Int,
    val activeCopying: Int,
    val availableCommandSlots: Int,
    val commandCapacity: Int,
)

data class FileTransferAdmissionSnapshotV2(
    val activeReserved: Long,
    val activeCopying: Long,
    val activeStreaming: Long,
    val activeStreamBytes: Long,
    val availableCommandSlots: Long,
    val commandCapacity: Long,
)

/** Header layout `xenia_jni.c`'s `pollFrame` packs (see its doc comment). */
private const val FRAME_HEADER_LEN = 17
private const val FILE_STREAM_CHUNK_BYTES = 64 * 1024

/**
 * Owns one native viewer session: connects on construction, polls
 * for decoded frames and state changes on a background coroutine, and
 * forwards touch input back to the daemon. Consent is entirely
 * host(desktop)-side (see the project plan) -- this class never shows
 * an approve/deny prompt of its own, only reflects [state].
 *
 * For `CODEC_PASSTHROUGH`/`CODEC_HDC`, polled frames are already
 * decoded RGBA and get turned into a [Bitmap] on [frame]. For
 * `CODEC_H264`, polled frames are raw Annex-B NAL bytes -- the daemon
 * side's H.264 decoder needs `ffmpeg-next`, not portable to Android,
 * so this session instead feeds them into an [H264Decoder] (Android's
 * own hardware `MediaCodec`) that it constructs lazily once both
 * prerequisites are available: [h264Surface] (set by the UI once its
 * `SurfaceView` is ready) and the first frame's declared width/height
 * (only known once a frame actually arrives). Frames are fed
 * synchronously inside the poll loop, not via a `StateFlow`, so
 * `MediaCodec` never silently misses one -- Compose recomposition can
 * conflate rapid `StateFlow` updates, which would desync a codec that
 * needs every frame in order.
 */
class XeniaSession(
    hostPort: String,
    val codec: Int,
    private val scope: CoroutineScope,
    recvDir: String?,
    stagingDir: String?,
    maxFileBytes: Long,
) {
    private val handle: Long = NativeBindings.connect(hostPort, codec, recvDir, stagingDir, maxFileBytes)

    private val _state = MutableStateFlow(SessionState.CONNECTING)
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val _frame = MutableStateFlow<Bitmap?>(null)
    val frame: StateFlow<Bitmap?> = _frame.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    /** Latest host-to-viewer clipboard text. The UI applies this to
     * the Android system clipboard when it changes (see
     * `xenia_poll_clipboard`'s doc comment for why a host-side
     * *clear* isn't distinguished from "nothing new" here). Requires
     * the daemon to be running with `--clipboard host-to-viewer` or
     * `bidirectional`. */
    private val _clipboard = MutableStateFlow<String?>(null)
    val clipboard: StateFlow<String?> = _clipboard.asStateFlow()

    /** File-transfer offers/progress/completion, as they happen. A
     * `SharedFlow` (not `StateFlow`) since these are one-shot events
     * for potentially several distinct transfers in flight, not a
     * single "current value" -- a UI collecting this should react to
     * each emission rather than reading a snapshot. `extraBufferCapacity`
     * so the poll loop's `tryEmit` never has to drop an event under
     * normal collection (a slow/absent collector still can't back up
     * the poll loop itself, which is the point of `tryEmit` over `emit`). */
    private val _fileTransferEvents = MutableSharedFlow<FileTransferEvent>(extraBufferCapacity = 32)
    val fileTransferEvents: SharedFlow<FileTransferEvent> = _fileTransferEvents.asSharedFlow()

    /** Set by the UI once its `SurfaceView`'s `Surface` is ready. Only
     * meaningful when `codec == NativeBindings.CODEC_H264`. [H264Decoder]
     * itself is constructed lazily on the first polled frame (see
     * [handlePacked]) since it needs the declared width/height, which
     * only arrive with that first frame -- not available yet when the
     * `Surface` itself becomes ready. */
    @Volatile
    var h264Surface: android.view.Surface? = null
    private var h264Decoder: H264Decoder? = null

    /** Must be called whenever the `SurfaceView`'s `Surface` is
     * destroyed (its `SurfaceHolder.Callback.surfaceDestroyed`) -- a
     * `Surface` can be torn down any time the window isn't visible
     * (backgrounding the Activity, e.g. launching the system document
     * picker for [sendFile]'s file-choosing UI), and a `MediaCodec`
     * still configured to render into that now-abandoned `Surface`
     * fails every subsequent frame forever (confirmed live: repeated
     * `BufferQueue has been abandoned` / `queueBuffer failed: 13` in
     * logcat after backgrounding for the file picker, with video
     * frozen permanently even though the underlying file transfer and
     * network session were both healthy). [handlePacked] recreates a
     * fresh [H264Decoder] on the next keyframe once a new `Surface`
     * arrives, since it only builds one `if (h264Decoder == null)`.
     */
    fun releaseH264Decoder() {
        h264Decoder?.release()
        h264Decoder = null
    }

    private var pollJob: Job? = null

    init {
        if (handle == 0L) {
            _state.value = SessionState.ERROR
            _lastError.value = "invalid host:port"
        } else {
            pollJob = scope.launch(Dispatchers.Default) { pollLoop() }
        }
    }

    private suspend fun pollLoop() {
        while (true) {
            when (NativeBindings.sessionState(handle)) {
                NativeBindings.STATE_CONNECTING -> _state.value = SessionState.CONNECTING
                NativeBindings.STATE_CONNECTED -> _state.value = SessionState.CONNECTED
                NativeBindings.STATE_DISCONNECTED -> {
                    _state.value = SessionState.DISCONNECTED
                    return
                }
                NativeBindings.STATE_ERROR -> {
                    _state.value = SessionState.ERROR
                    _lastError.value = NativeBindings.lastError(handle)
                    return
                }
                else -> {
                    _state.value = SessionState.INVALID
                    return
                }
            }

            NativeBindings.pollFrame(handle)?.let { packed -> handlePacked(packed) }
            NativeBindings.pollClipboard(handle)?.let { text -> _clipboard.value = text }
            NativeBindings.pollFileTransferEvent(handle)?.let { packed ->
                unpackFileTransferEvent(packed)?.let { event -> _fileTransferEvents.tryEmit(event) }
            }

            // ~60fps poll cadence. JNI calls here are cheap (a mutex
            // lock + pop from a bounded queue); the real frame rate
            // is governed by the daemon's capture/encode/network path,
            // not this loop.
            delay(16)
        }
    }

    private fun handlePacked(packed: ByteArray) {
        if (packed.size < FRAME_HEADER_LEN) return
        val isEncoded = packed[16].toInt() != 0
        if (isEncoded) {
            val nal = packed.copyOfRange(FRAME_HEADER_LEN, packed.size)
            val isKeyframe = AnnexB.isKeyframeChunk(nal)
            if (h264Decoder == null) {
                val surface = h264Surface ?: return // UI not ready yet -- drop until it is
                if (!isKeyframe) return // need a real keyframe to configure MediaCodec
                val width = readU32LE(packed, 0)
                val height = readU32LE(packed, 4)
                h264Decoder = H264Decoder(surface, width, height)
            }
            h264Decoder?.feed(nal, isKeyframe)
        } else {
            unpackRgbaFrame(packed)?.let { _frame.value = it }
        }
    }

    /** Send a normalized tap/drag point. `phase`: 0=Down, 1=Move, 2=Up. */
    fun sendTouch(x: Float, y: Float, phase: Int) {
        if (handle != 0L) NativeBindings.sendTouch(handle, 0, x, y, phase, 1.0f)
    }

    /** Legacy ambiguous pointer API retained for older native callers. New UI
     * code must use [sendPointerMove] or [sendPointerButton]. */
    fun sendPointer(x: Float, y: Float, button: Int, pressed: Boolean) {
        if (handle != 0L) NativeBindings.sendPointer(handle, x, y, button, pressed)
    }

    /** Send pointer motion with no button-state transition. */
    fun sendPointerMove(x: Float, y: Float) {
        if (handle != 0L) NativeBindings.sendPointerMove(handle, x, y)
    }

    /** Send an explicit pointer-button press/release transition. */
    fun sendPointerButton(x: Float, y: Float, button: Int, pressed: Boolean) {
        if (handle != 0L) NativeBindings.sendPointerButton(handle, x, y, button, pressed)
    }

    /** Send a key event. `code` is an evdev/Linux keycode (see
     * [EvdevKeys]); `modifiers` bit0=Shift, bit1=Ctrl, bit2=Alt,
     * bit3=Meta. */
    fun sendKey(code: Int, pressed: Boolean, modifiers: Int = 0) {
        if (handle != 0L) NativeBindings.sendKey(handle, code, pressed, modifiers)
    }

    /** Send a viewer-to-host clipboard update (`null` = cleared).
     * Requires the daemon to be running with `--clipboard
     * bidirectional`. */
    fun sendClipboardUpdate(text: String?) {
        if (handle != 0L) NativeBindings.sendClipboard(handle, text)
    }

    /** File transfer APIs. [trySendFile] is the legacy whole-ByteArray path;
     * current Storage Access Framework UI uses [trySendFileStream] so only one
     * 64 KiB Java/JNI chunk is live at a time while native code stages+hashes
     * the source. Only one outgoing transfer is in flight at a time. */
    fun fileTransferAdmissionSnapshot(): FileTransferAdmissionSnapshot? {
        if (handle == 0L) return null
        val values = NativeBindings.fileTransferAdmissionSnapshot(handle) ?: return null
        if (values.size != 4) return null
        return FileTransferAdmissionSnapshot(
            activeReserved = values[0],
            activeCopying = values[1],
            availableCommandSlots = values[2],
            commandCapacity = values[3],
        )
    }

    fun fileTransferAdmissionSnapshotV2(): FileTransferAdmissionSnapshotV2? {
        if (handle == 0L) return null
        val values = NativeBindings.fileTransferAdmissionSnapshotV2(handle) ?: return null
        if (values.size != 6) return null
        return FileTransferAdmissionSnapshotV2(
            activeReserved = values[0],
            activeCopying = values[1],
            activeStreaming = values[2],
            activeStreamBytes = values[3],
            availableCommandSlots = values[4],
            commandCapacity = values[5],
        )
    }

    fun trySendFile(name: String, data: ByteArray): FileSendResult {
        if (handle == 0L) return FileSendResult.INVALID_HANDLE
        return FileSendResult.fromNative(NativeBindings.trySendFile(handle, name, data))
    }

    /** Preferred SAF/mobile path: keep only one 64 KiB Java/native chunk in
     * memory while native code stages and hashes the file into app-private
     * storage. `expectedLen=null` is supported for providers that do not expose
     * a stable OpenableColumns.SIZE; native staging still enforces the 100 MiB
     * ceiling incrementally. This method performs blocking stream I/O and must
     * be called from a background/IO dispatcher. */
    fun trySendFileStream(
        name: String,
        input: InputStream,
        expectedLen: Long?,
    ): FileSendResult {
        if (handle == 0L) return FileSendResult.INVALID_HANDLE
        val begin = NativeBindings.beginSendFileStream(handle, name, expectedLen ?: -1L)
            ?: return FileSendResult.INVALID_ARGUMENT
        if (begin.size != 2) return FileSendResult.INVALID_ARGUMENT
        val admission = FileSendResult.fromNative(begin[0].toInt())
        val token = begin[1]
        if (admission != FileSendResult.ACCEPTED || token == 0L) {
            return if (admission == FileSendResult.ACCEPTED) {
                FileSendResult.INVALID_RESERVATION
            } else {
                admission
            }
        }
        var finished = false
        try {
            val buffer = ByteArray(FILE_STREAM_CHUNK_BYTES)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                val append = FileSendResult.fromNative(
                    NativeBindings.appendSendFileStream(handle, token, buffer, read)
                )
                if (append != FileSendResult.ACCEPTED) return append
            }
            val result = FileSendResult.fromNative(
                NativeBindings.finishSendFileStream(handle, token)
            )
            finished = result == FileSendResult.ACCEPTED
            return result
        } catch (_: java.io.IOException) {
            return FileSendResult.IO_ERROR
        } catch (_: SecurityException) {
            return FileSendResult.IO_ERROR
        } finally {
            if (!finished) NativeBindings.cancelSendFileStream(handle, token)
        }
    }

    /** Legacy Boolean convenience retained for callers that only need accepted/rejected. */
    fun sendFile(name: String, data: ByteArray): Boolean {
        return trySendFile(name, data) == FileSendResult.ACCEPTED
    }

    fun disconnect() {
        pollJob?.cancel()
        h264Decoder?.release()
        if (handle != 0L) NativeBindings.disconnect(handle)
    }
}

/**
 * Unpack the header+RGBA byte array `xenia_jni.c`'s `pollFrame`
 * returns (see its doc comment for the exact layout) into a Bitmap.
 * Native-endian (little-endian on all real Android hardware) is
 * assumed for the header fields -- this is a same-process JNI
 * marshalling format, not a network wire format.
 */
private fun unpackRgbaFrame(packed: ByteArray): Bitmap? {
    val width = readU32LE(packed, 0)
    val height = readU32LE(packed, 4)
    val expectedRgbaLen = width.toLong() * height.toLong() * 4L
    if (packed.size.toLong() - FRAME_HEADER_LEN != expectedRgbaLen || width == 0 || height == 0) return null

    val pixelCount = width * height
    val argb = IntArray(pixelCount)
    var src = FRAME_HEADER_LEN
    for (i in 0 until pixelCount) {
        val r = packed[src].toInt() and 0xFF
        val g = packed[src + 1].toInt() and 0xFF
        val b = packed[src + 2].toInt() and 0xFF
        val a = packed[src + 3].toInt() and 0xFF
        argb[i] = (a shl 24) or (r shl 16) or (g shl 8) or b
        src += 4
    }

    val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
    bitmap.setPixels(argb, 0, width, 0, 0, width, height)
    return bitmap
}

private fun readU32LE(bytes: ByteArray, offset: Int): Int {
    return (bytes[offset].toInt() and 0xFF) or
        ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
        ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
        ((bytes[offset + 3].toInt() and 0xFF) shl 24)
}

private fun readU64LE(bytes: ByteArray, offset: Int): Long {
    var value = 0L
    for (i in 0 until 8) {
        value = value or ((bytes[offset + i].toLong() and 0xFF) shl (8 * i))
    }
    return value
}

private fun readU16LE(bytes: ByteArray, offset: Int): Int {
    return (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)
}

/**
 * Unpack the header+strings byte array `xenia_jni.c`'s
 * `pollFileTransferEvent` returns (see its doc comment for the exact
 * 32-byte-header layout) into a [FileTransferEvent]. Returns `null`
 * for an unrecognized `kind` (defensive -- shouldn't happen since the
 * kind byte comes from the same enum on both sides of this JNI call).
 */
private fun unpackFileTransferEvent(packed: ByteArray): FileTransferEvent? {
    if (packed.size < 32) return null
    val kind = packed[0].toInt()
    val outgoing = packed[1].toInt() != 0
    val accepted = packed[2].toInt() != 0
    val ok = packed[3].toInt() != 0
    val transferId = readU64LE(packed, 4)
    val doneBytes = readU64LE(packed, 12)
    val totalBytes = readU64LE(packed, 20)
    val nameLen = readU16LE(packed, 28)
    val detailLen = readU16LE(packed, 30)
    var offset = 32
    if (packed.size < offset + nameLen + detailLen) return null
    val name = String(packed, offset, nameLen, Charsets.UTF_8)
    offset += nameLen
    val detail = String(packed, offset, detailLen, Charsets.UTF_8)

    return when (kind) {
        NativeBindings.FT_EVENT_INCOMING_OFFER ->
            FileTransferEvent.IncomingOffer(transferId, name, totalBytes, accepted, detail)
        NativeBindings.FT_EVENT_PROGRESS ->
            FileTransferEvent.Progress(transferId, name, doneBytes, totalBytes, outgoing)
        NativeBindings.FT_EVENT_DONE ->
            FileTransferEvent.Done(transferId, name, outgoing, ok, detail)
        else -> null
    }
}

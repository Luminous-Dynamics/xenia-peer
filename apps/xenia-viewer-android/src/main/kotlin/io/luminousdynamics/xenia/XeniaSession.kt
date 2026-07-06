package io.luminousdynamics.xenia

import android.graphics.Bitmap
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Mirrors [NativeBindings]'s `STATE_*` constants as a Kotlin enum. */
enum class SessionState { CONNECTING, CONNECTED, DISCONNECTED, ERROR, INVALID }

/**
 * Owns one native viewer session: connects on construction, polls
 * for decoded frames and state changes on a background coroutine, and
 * forwards touch input back to the daemon. Consent is entirely
 * host(desktop)-side (see the project plan) -- this class never shows
 * an approve/deny prompt of its own, only reflects [state].
 */
class XeniaSession(hostPort: String, codec: Int, private val scope: CoroutineScope) {
    private val handle: Long = NativeBindings.connect(hostPort, codec)

    private val _state = MutableStateFlow(SessionState.CONNECTING)
    val state: StateFlow<SessionState> = _state.asStateFlow()

    private val _frame = MutableStateFlow<Bitmap?>(null)
    val frame: StateFlow<Bitmap?> = _frame.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

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

            NativeBindings.pollFrame(handle)?.let { packed -> _frame.value = unpackFrame(packed) }

            // ~60fps poll cadence. JNI calls here are cheap (a mutex
            // lock + pop from a bounded queue); the real frame rate
            // is governed by the daemon's capture/encode/network path,
            // not this loop.
            delay(16)
        }
    }

    /** Send a normalized tap/drag point. `phase`: 0=Down, 1=Move, 2=Up. */
    fun sendTouch(x: Float, y: Float, phase: Int) {
        if (handle != 0L) NativeBindings.sendTouch(handle, 0, x, y, phase, 1.0f)
    }

    fun disconnect() {
        pollJob?.cancel()
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
private fun unpackFrame(packed: ByteArray): Bitmap? {
    if (packed.size < 16) return null
    val width = readU32LE(packed, 0)
    val height = readU32LE(packed, 4)
    val expectedRgbaLen = width.toLong() * height.toLong() * 4L
    if (packed.size.toLong() - 16L != expectedRgbaLen || width == 0 || height == 0) return null

    val pixelCount = width * height
    val argb = IntArray(pixelCount)
    var src = 16
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

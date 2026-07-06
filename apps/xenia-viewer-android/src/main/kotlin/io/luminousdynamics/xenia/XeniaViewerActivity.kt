package io.luminousdynamics.xenia

import android.content.ClipData
import android.content.ClipboardManager
import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Caps both directions; also a hard in-memory buffering cap (the
 * whole file lives in a `ByteArray`/`Vec<u8>` on both ends -- see
 * `xenia_mobile_ffi::engine::ViewerEngine::connect`'s doc comment).
 * Lower than the desktop default (200 MiB) since phones have less RAM
 * to spare for this. */
private const val MAX_FILE_TRANSFER_BYTES = 100L * 1024 * 1024

/**
 * Viewer: a connect screen (host:port + codec), then a full-screen
 * rendering of the remote desktop with tap/drag/type -> `InputEvent`,
 * plus bidirectional clipboard sync and file transfer. No consent UI
 * for any of this (host-side only, see the project plan) -- incoming
 * file offers are auto-accepted into an app-private directory exactly
 * like `xenia-viewer`'s own flag-driven model. Passthrough/HDC render
 * via a Compose `Image` (see [ViewerScreen]); H.264 renders via a real
 * `SurfaceView` + Android's hardware `MediaCodec` (see [H264Decoder])
 * since that decode doesn't happen in Rust at all on this platform.
 */
class XeniaViewerActivity : ComponentActivity() {
    private var session: XeniaSession? = null
    private var pendingFilePick: ((Uri) -> Unit)? = null

    private val filePickerLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            val callback = pendingFilePick
            pendingFilePick = null
            if (uri != null) callback?.invoke(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // App-private directory (a real filesystem path, not a SAF
        // Uri) for files the host sends us -- `ViewerEngine` writes
        // to it directly via `std::fs::write`, matching
        // `xenia-viewer`'s own `--recv-file-dir` semantics.
        val recvDir = getExternalFilesDir("received")?.apply { mkdirs() }
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    XeniaViewerScreen(
                        onConnect = { hostPort, codec ->
                            val s = XeniaSession(
                                hostPort,
                                codec,
                                lifecycleScope,
                                recvDir?.absolutePath,
                                MAX_FILE_TRANSFER_BYTES,
                            )
                            session = s
                            s
                        },
                        onPickFile = { onPicked ->
                            pendingFilePick = onPicked
                            filePickerLauncher.launch(arrayOf("*/*"))
                        },
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        session?.disconnect()
        super.onDestroy()
    }
}

@Composable
private fun XeniaViewerScreen(onConnect: (String, Int) -> XeniaSession, onPickFile: ((Uri) -> Unit) -> Unit) {
    var activeSession by remember { mutableStateOf<XeniaSession?>(null) }

    val current = activeSession
    if (current == null) {
        ConnectScreen(onConnect = { hostPort, codec -> activeSession = onConnect(hostPort, codec) })
    } else {
        ViewerScreen(session = current, onPickFile = onPickFile)
    }
}

@Composable
private fun ConnectScreen(onConnect: (String, Int) -> Unit) {
    var hostPort by remember { mutableStateOf("") }
    // Default to H.264: it's the one codec proven reliable on real
    // desktop-resolution content this project (passthrough is
    // bandwidth-heavy at real resolutions; HDC's live-phone
    // reliability is still pending re-verification, task #32).
    var selectedCodec by remember { mutableIntStateOf(NativeBindings.CODEC_H264) }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("Xenia Viewer", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Connect to a real xenia-peer daemon. Consent is granted on " +
                "the desktop -- nothing to approve here.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp, bottom = 24.dp),
        )
        OutlinedTextField(
            value = hostPort,
            onValueChange = { hostPort = it },
            label = { Text("host:port") },
            singleLine = true,
            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(modifier = Modifier.padding(top = 12.dp)) {
            CodecChoiceButton(
                label = "H.264 (hw)",
                selected = selectedCodec == NativeBindings.CODEC_H264,
                onClick = { selectedCodec = NativeBindings.CODEC_H264 },
            )
            CodecChoiceButton(
                label = "Passthrough",
                selected = selectedCodec == NativeBindings.CODEC_PASSTHROUGH,
                onClick = { selectedCodec = NativeBindings.CODEC_PASSTHROUGH },
                modifier = Modifier.padding(start = 8.dp),
            )
        }
        Button(
            onClick = { onConnect(hostPort, selectedCodec) },
            enabled = hostPort.isNotBlank(),
            modifier = Modifier.padding(top = 16.dp),
        ) {
            Text("Connect")
        }
    }
}

@Composable
private fun CodecChoiceButton(
    label: String,
    selected: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (selected) {
        Button(onClick = onClick, modifier = modifier) { Text(label) }
    } else {
        OutlinedButton(onClick = onClick, modifier = modifier) { Text(label) }
    }
}

/** Absolute tap-to-cursor-position (existing Phase 1 model) vs. a
 * relative drag-based virtual trackpad -- tap-to-click alone has no
 * hover/precision-cursor concept, which matters once you're actually
 * trying to use a real desktop rather than just proving the pipeline
 * works (see the project plan's Phase 3 scope). */
private enum class InputMode { TAP, TRACKPAD }

@Composable
private fun ViewerScreen(session: XeniaSession, onPickFile: ((Uri) -> Unit) -> Unit) {
    val state by session.state.collectAsState()
    val error by session.lastError.collectAsState()
    var inputMode by remember { mutableStateOf(InputMode.TAP) }
    var keyboardActive by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    ClipboardBridge(session)

    Box(modifier = Modifier.fillMaxSize()) {
        if (session.codec == NativeBindings.CODEC_H264) {
            H264ViewerSurface(session, inputMode)
        } else {
            BitmapViewer(session, inputMode)
        }

        if (state != SessionState.CONNECTED) {
            Column(
                modifier = Modifier.fillMaxSize(),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    when (state) {
                        SessionState.CONNECTING -> "Connecting… waiting for the desktop to grant consent"
                        SessionState.ERROR -> "Error: ${error ?: "unknown"}"
                        SessionState.DISCONNECTED -> "Disconnected"
                        else -> "…"
                    },
                    modifier = Modifier.padding(top = 64.dp),
                )
            }
        }

        if (state == SessionState.CONNECTED) {
            FileTransferStatusBar(
                session = session,
                modifier = Modifier.align(Alignment.TopCenter).padding(top = 16.dp),
            )
            Row(
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 16.dp),
            ) {
                CodecChoiceButton(
                    label = "Tap",
                    selected = inputMode == InputMode.TAP,
                    onClick = { inputMode = InputMode.TAP },
                )
                CodecChoiceButton(
                    label = "Trackpad",
                    selected = inputMode == InputMode.TRACKPAD,
                    onClick = { inputMode = InputMode.TRACKPAD },
                    modifier = Modifier.padding(start = 8.dp),
                )
                CodecChoiceButton(
                    label = "Keyboard",
                    selected = keyboardActive,
                    onClick = { keyboardActive = !keyboardActive },
                    modifier = Modifier.padding(start = 8.dp),
                )
                CodecChoiceButton(
                    label = "Send",
                    selected = false,
                    onClick = {
                        onPickFile { uri ->
                            coroutineScope.launch {
                                val picked = withContext(Dispatchers.IO) { readPickedFile(context, uri) }
                                if (picked != null) session.sendFile(picked.first, picked.second)
                            }
                        }
                    },
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            if (keyboardActive) {
                VirtualKeyboardCapture(session)
            }
        }
    }
}

/**
 * Read a Storage Access Framework-picked file fully into memory (SAF
 * `Uri`s aren't plain filesystem paths, so this has to go through
 * `ContentResolver`, unlike receiving -- see [XeniaViewerActivity]'s
 * `recvDir`, which is a real path `ViewerEngine` writes to directly).
 * Returns `null` if the stream can't be opened, the display name can't
 * be resolved to anything usable, or the file exceeds
 * [MAX_FILE_TRANSFER_BYTES] (rejected client-side too, not just by the
 * peer, to avoid buffering an oversized file into memory for no reason).
 */
private fun readPickedFile(context: android.content.Context, uri: Uri): Pair<String, ByteArray>? {
    val name = queryDisplayName(context, uri) ?: uri.lastPathSegment ?: return null
    val bytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() } ?: return null
    if (bytes.size.toLong() > MAX_FILE_TRANSFER_BYTES) return null
    return name to bytes
}

private fun queryDisplayName(context: android.content.Context, uri: Uri): String? {
    context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
        val idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (idx >= 0 && cursor.moveToFirst()) return cursor.getString(idx)
    }
    return null
}

/**
 * Transient status line for the most recent [FileTransferEvent] --
 * offer decision, send/receive progress percentage, or final result.
 * Deliberately shows only the latest event rather than a scrollable
 * history/queue: this is a lightweight status indicator, not a
 * transfer manager UI.
 */
@Composable
private fun FileTransferStatusBar(session: XeniaSession, modifier: Modifier = Modifier) {
    var statusText by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(session) {
        session.fileTransferEvents.collect { event ->
            statusText = when (event) {
                is FileTransferEvent.IncomingOffer ->
                    if (event.accepted) "Receiving ${event.name}…" else "Rejected ${event.name}: ${event.reason}"
                is FileTransferEvent.Progress -> {
                    val pct = if (event.totalBytes > 0) (event.doneBytes * 100 / event.totalBytes) else 0
                    val verb = if (event.outgoing) "Sending" else "Receiving"
                    "$verb ${event.name}: $pct%"
                }
                is FileTransferEvent.Done -> {
                    val verb = if (event.outgoing) "Sent" else "Received"
                    if (event.ok) "$verb ${event.name}" else "Failed: ${event.name} (${event.detail})"
                }
            }
        }
    }
    statusText?.let { text ->
        Surface(
            color = MaterialTheme.colorScheme.surface,
            modifier = modifier,
        ) {
            Text(text, modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp))
        }
    }
}

/**
 * Bridges the OS clipboard both ways: applies host-to-viewer updates
 * ([XeniaSession.clipboard]) to the real Android clipboard, and
 * listens for local clipboard changes to send back
 * ([XeniaSession.sendClipboardUpdate]). Requires the daemon to be
 * running with `--clipboard host-to-viewer` or `bidirectional` --
 * with clipboard sync off, this is a harmless no-op (nothing ever
 * arrives to apply, and the daemon drops anything sent).
 */
@Composable
private fun ClipboardBridge(session: XeniaSession) {
    val context = LocalContext.current
    val clipboardManager = remember {
        context.getSystemService(ClipboardManager::class.java)
    }
    val hostClipboard by session.clipboard.collectAsState()

    // Host -> viewer: apply whenever a new update arrives.
    LaunchedEffect(hostClipboard) {
        val text = hostClipboard ?: return@LaunchedEffect
        clipboardManager.setPrimaryClip(ClipData.newPlainText("xenia", text))
    }

    // Viewer -> host: forward local clipboard changes. Guard against
    // echoing back an update we ourselves just applied above (which
    // would otherwise bounce forever) by comparing against the text
    // we last received from the host.
    DisposableEffect(session) {
        val listener = ClipboardManager.OnPrimaryClipChangedListener {
            val clip = clipboardManager.primaryClip
            val text = if (clip != null && clip.itemCount > 0) {
                clip.getItemAt(0).coerceToText(context).toString()
            } else {
                null
            }
            if (text != session.clipboard.value) {
                session.sendClipboardUpdate(text)
            }
        }
        clipboardManager.addPrimaryClipChangedListener(listener)
        onDispose { clipboardManager.removePrimaryClipChangedListener(listener) }
    }
}

/**
 * Invisible IME-driven text capture: a `BasicTextField` kept at a
 * fixed one-space "sentinel" value so backspace always has something
 * to delete (detected as the field shrinking below the sentinel
 * length), with typed characters mapped to [EvdevKeys] key events and
 * the field reset to the sentinel after every change. This is the
 * standard pattern for remote-input Android apps that don't have (or
 * want to require) a physical keyboard -- most software keyboards
 * don't reliably emit individual `KeyEvent`s per keystroke (autocomplete/
 * predictive input can commit whole words at once), so capturing
 * *committed text* and diffing it is far more reliable than trying to
 * intercept raw `KeyEvent`s.
 *
 * The diff itself must NOT assume `new.text` is always `sentinel +
 * appended suffix` -- IMEs mutate mid-string via composing regions
 * (autocorrect, predictive commit) even for plain ASCII input, which
 * broke a naive `substring(sentinel.length)` diff in practice (typing
 * "hello" produced h, l x6, o -- the composing region rewrote "he" to
 * "h" then re-inserted characters, and the naive diff re-sent whatever
 * landed after the sentinel's fixed length instead of the actual
 * change). A real common-prefix/common-suffix diff against the
 * previous field value handles composing-region edits correctly no
 * matter where in the string they land.
 */
@Composable
private fun VirtualKeyboardCapture(session: XeniaSession) {
    val sentinel = " "
    var fieldValue by remember {
        mutableStateOf(TextFieldValue(sentinel, TextRange(sentinel.length)))
    }
    val focusRequester = remember { FocusRequester() }

    LaunchedEffect(Unit) { focusRequester.requestFocus() }

    BasicTextField(
        value = fieldValue,
        onValueChange = { new ->
            val old = fieldValue.text
            val text = new.text

            var prefix = 0
            while (prefix < old.length && prefix < text.length && old[prefix] == text[prefix]) prefix++
            var suffix = 0
            val maxSuffix = minOf(old.length - prefix, text.length - prefix)
            while (suffix < maxSuffix && old[old.length - 1 - suffix] == text[text.length - 1 - suffix]) suffix++

            val removedCount = old.length - prefix - suffix
            val inserted = text.substring(prefix, text.length - suffix)

            repeat(removedCount) {
                session.sendKey(EvdevKeys.BACKSPACE, true)
                session.sendKey(EvdevKeys.BACKSPACE, false)
            }
            for (c in inserted) {
                if (c == '\n') {
                    session.sendKey(EvdevKeys.ENTER, true)
                    session.sendKey(EvdevKeys.ENTER, false)
                    continue
                }
                val (code, needsShift) = EvdevKeys.charToKey(c) ?: continue
                val mods = if (needsShift) EvdevKeys.MOD_SHIFT else 0
                session.sendKey(code, true, mods)
                session.sendKey(code, false, mods)
            }

            fieldValue = if (text.length < sentinel.length) {
                TextFieldValue(sentinel, TextRange(sentinel.length))
            } else {
                new
            }
        },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.None),
        modifier = Modifier
            .size(1.dp) // present (so it can hold focus + the IME open) but invisible
            .focusRequester(focusRequester),
    )
}

/** Renders `passthrough`/`hdc` sessions: already-decoded RGBA turned
 * into a Bitmap by [XeniaSession], shown via a plain Compose `Image`. */
@Composable
private fun BitmapViewer(session: XeniaSession, inputMode: InputMode) {
    val frame by session.frame.collectAsState()
    var boxWidth by remember { mutableStateOf(1) }
    var boxHeight by remember { mutableStateOf(1) }

    val bitmap = frame ?: return
    Image(
        bitmap = bitmap.asImageBitmap(),
        contentDescription = "Remote screen",
        contentScale = ContentScale.Fit,
        modifier = Modifier
            .fillMaxSize()
            .onSizeChanged { boxWidth = it.width; boxHeight = it.height }
            .let {
                if (inputMode == InputMode.TAP) {
                    it.forwardTouchTo(session, inputMode) { boxWidth to boxHeight }
                } else {
                    it.forwardTrackpadTo(session, inputMode)
                }
            },
    )
}

/** Renders `h264` sessions: a real `SurfaceView` whose `Surface` feeds
 * Android's hardware `MediaCodec` directly (see [XeniaSession] and
 * [H264Decoder] for why this doesn't go through a Bitmap/Compose
 * `Image` like the other codecs). */
@Composable
private fun H264ViewerSurface(session: XeniaSession, inputMode: InputMode) {
    var surfaceWidth by remember { mutableStateOf(1) }
    var surfaceHeight by remember { mutableStateOf(1) }

    AndroidView(
        factory = { ctx ->
            SurfaceView(ctx).apply {
                holder.addCallback(
                    object : SurfaceHolder.Callback {
                        override fun surfaceCreated(holder: SurfaceHolder) {
                            session.h264Surface = holder.surface
                        }

                        override fun surfaceChanged(
                            holder: SurfaceHolder,
                            format: Int,
                            width: Int,
                            height: Int,
                        ) {
                        }

                        override fun surfaceDestroyed(holder: SurfaceHolder) {
                            session.h264Surface = null
                            // The old Surface is about to become invalid --
                            // release the MediaCodec bound to it now, rather
                            // than leaving it to fail forever on every frame
                            // once a *new* Surface arrives later (see
                            // releaseH264Decoder's doc comment for the real
                            // bug this fixes, caught via the Send-file
                            // picker backgrounding the Activity).
                            session.releaseH264Decoder()
                        }
                    },
                )
            }
        },
        modifier = Modifier
            .fillMaxSize()
            .onSizeChanged { surfaceWidth = it.width; surfaceHeight = it.height }
            .let {
                if (inputMode == InputMode.TAP) {
                    it.forwardTouchTo(session, inputMode) { surfaceWidth to surfaceHeight }
                } else {
                    it.forwardTrackpadTo(session, inputMode)
                }
            },
    )
}

/**
 * Forward raw down/move/up as `InputEvent::Touch` phases directly --
 * deliberately NOT using `detectTapGestures`/`detectDragGestures`,
 * which are higher-level gesture *recognizers* (click vs. long-press
 * vs. drag, with timing thresholds) built to run the pointer-event
 * stream to completion each; calling two of them back-to-back in one
 * `pointerInput` block would mean the first call never returns and
 * the second never starts. A remote-desktop client wants raw touch
 * forwarding, not gesture classification, so a manual down/move/up
 * loop is both simpler and semantically correct here. `sizeProvider`
 * is read fresh on every gesture rather than captured once, since the
 * emitting composable's own remembered width/height can still be `1`
 * (their initial value) on the very first gesture before `onSizeChanged`
 * has fired.
 *
 * Keys on both `session` and the caller's `InputMode`: `pointerInput`
 * only restarts its gesture-handling coroutine when a key changes, and
 * reuses the already-running one otherwise -- keying on `session`
 * alone meant toggling Tap/Trackpad mid-session never actually
 * switched which handler ran (confirmed live: the daemon kept logging
 * `Touch` events after switching to Trackpad mode, since the original
 * Tap-mode coroutine, started at first composition, just kept
 * looping). The caller passes its own `inputMode` in as `modeKey` so
 * both branches key on the same value and a switch in either
 * direction forces a restart.
 */
@Composable
private fun Modifier.forwardTouchTo(session: XeniaSession, modeKey: Any, sizeProvider: () -> Pair<Int, Int>): Modifier =
    pointerInput(session, modeKey) {
        awaitEachGesture {
            val (w0, h0) = sizeProvider()
            val down = awaitFirstDown()
            session.sendTouch((down.position.x / w0).coerceIn(0f, 1f), (down.position.y / h0).coerceIn(0f, 1f), 0)
            while (true) {
                val event = awaitPointerEvent()
                val change = event.changes.firstOrNull() ?: break
                val (w, h) = sizeProvider()
                val nx = (change.position.x / w).coerceIn(0f, 1f)
                val ny = (change.position.y / h).coerceIn(0f, 1f)
                if (!change.pressed) {
                    session.sendTouch(nx, ny, 2) // Up
                    break
                }
                session.sendTouch(nx, ny, 1) // Move
            }
        }
    }

/**
 * Relative drag-based virtual trackpad: dragging moves a persistent
 * virtual cursor by the drag *delta* (not to the touch point), and a
 * short tap (below [TRACKPAD_TAP_SLOP_PX] of total movement) clicks at
 * the cursor's *current* position -- the standard laptop-trackpad
 * interaction model, needed because tap-to-position alone has no way
 * to move the cursor without also "teleporting" it, making precise
 * work (text cursors, small UI targets) impractical. `InputEvent::Pointer`
 * (not `Touch`) is used here since it's the mouse-shaped event the
 * daemon-side injectors treat as a real cursor position + click,
 * matching how the desktop's own egui viewer drives the same wire
 * event.
 *
 * Known simplification: no on-screen cursor indicator is drawn.
 * Overlaying one on top of `H264ViewerSurface`'s `SurfaceView`
 * specifically has real z-ordering risk (`SurfaceView` content is
 * hardware-composited via a hole-punch, and a naive Compose-drawn
 * overlay isn't guaranteed to land above it without further work) --
 * not attempted here since the mode is still fully functional without
 * one, just less discoverable.
 */
@Composable
private fun Modifier.forwardTrackpadTo(session: XeniaSession, modeKey: Any): Modifier {
    var cursorX by remember(session) { mutableStateOf(0.5f) }
    var cursorY by remember(session) { mutableStateOf(0.5f) }

    return pointerInput(session, modeKey) {
        awaitEachGesture {
            val down = awaitFirstDown()
            var lastPos = down.position
            var totalMovement = 0f
            while (true) {
                val event = awaitPointerEvent()
                val change = event.changes.firstOrNull() ?: break
                if (!change.pressed) {
                    if (totalMovement < TRACKPAD_TAP_SLOP_PX) {
                        session.sendPointer(cursorX, cursorY, 0, true) // click down
                        session.sendPointer(cursorX, cursorY, 0, false) // click up
                    }
                    break
                }
                val dx = change.position.x - lastPos.x
                val dy = change.position.y - lastPos.y
                totalMovement += kotlin.math.abs(dx) + kotlin.math.abs(dy)
                lastPos = change.position
                cursorX = (cursorX + dx / size.width * TRACKPAD_SENSITIVITY).coerceIn(0f, 1f)
                cursorY = (cursorY + dy / size.height * TRACKPAD_SENSITIVITY).coerceIn(0f, 1f)
                session.sendPointer(cursorX, cursorY, 0, false) // motion, no button
            }
        }
    }
}

/** Empirical: how much faster the virtual cursor moves than the
 * physical finger drag, so a comfortable hand motion can reach the
 * full screen without needing multiple drag strokes. */
private const val TRACKPAD_SENSITIVITY = 2.5f

/** Total accumulated drag distance (pixels) below which a gesture
 * counts as "tap to click" rather than "drag to move the cursor." */
private const val TRACKPAD_TAP_SLOP_PX = 12f

package io.luminousdynamics.xenia

import android.os.Bundle
import android.view.SurfaceHolder
import android.view.SurfaceView
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.lifecycleScope

/**
 * Viewer: a connect screen (host:port + codec), then a full-screen
 * rendering of the remote desktop with tap/drag -> `InputEvent::Touch`.
 * No consent UI (host-side only, see the project plan). Passthrough/
 * HDC render via a Compose `Image` (see [ViewerScreen]); H.264 renders
 * via a real `SurfaceView` + Android's hardware `MediaCodec` (see
 * [H264Decoder]) since that decode doesn't happen in Rust at all on
 * this platform. No clipboard/file transfer yet (Phase 3).
 */
class XeniaViewerActivity : ComponentActivity() {
    private var session: XeniaSession? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    XeniaViewerScreen(
                        onConnect = { hostPort, codec ->
                            val s = XeniaSession(hostPort, codec, lifecycleScope)
                            session = s
                            s
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
private fun XeniaViewerScreen(onConnect: (String, Int) -> XeniaSession) {
    var activeSession by remember { mutableStateOf<XeniaSession?>(null) }

    val current = activeSession
    if (current == null) {
        ConnectScreen(onConnect = { hostPort, codec -> activeSession = onConnect(hostPort, codec) })
    } else {
        ViewerScreen(session = current)
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

@Composable
private fun ViewerScreen(session: XeniaSession) {
    val state by session.state.collectAsState()
    val error by session.lastError.collectAsState()

    Box(modifier = Modifier.fillMaxSize()) {
        if (session.codec == NativeBindings.CODEC_H264) {
            H264ViewerSurface(session)
        } else {
            BitmapViewer(session)
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
    }
}

/** Renders `passthrough`/`hdc` sessions: already-decoded RGBA turned
 * into a Bitmap by [XeniaSession], shown via a plain Compose `Image`. */
@Composable
private fun BitmapViewer(session: XeniaSession) {
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
            .forwardTouchTo(session) { boxWidth to boxHeight },
    )
}

/** Renders `h264` sessions: a real `SurfaceView` whose `Surface` feeds
 * Android's hardware `MediaCodec` directly (see [XeniaSession] and
 * [H264Decoder] for why this doesn't go through a Bitmap/Compose
 * `Image` like the other codecs). */
@Composable
private fun H264ViewerSurface(session: XeniaSession) {
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
                        }
                    },
                )
            }
        },
        modifier = Modifier
            .fillMaxSize()
            .onSizeChanged { surfaceWidth = it.width; surfaceHeight = it.height }
            .forwardTouchTo(session) { surfaceWidth to surfaceHeight },
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
 */
@Composable
private fun Modifier.forwardTouchTo(session: XeniaSession, sizeProvider: () -> Pair<Int, Int>): Modifier =
    pointerInput(session) {
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

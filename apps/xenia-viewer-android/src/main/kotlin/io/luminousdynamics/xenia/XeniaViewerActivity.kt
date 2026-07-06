package io.luminousdynamics.xenia

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.Image
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
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
import androidx.lifecycle.lifecycleScope

/**
 * v1 MVP viewer: a connect screen (host:port), then a full-screen
 * rendering of the remote desktop with tap/drag -> `InputEvent::Touch`.
 * No consent UI (host-side only, see the project plan); no clipboard,
 * file transfer, or H.264 yet (later phases).
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
        Button(
            // v1 MVP is passthrough-only (see the project plan's
            // phasing); HDC's own live-phone reliability is still
            // pending re-verification (task #32), and H.264 needs
            // Phase 2's MediaCodec work -- exposing a codec picker
            // here would offer choices that aren't actually ready.
            onClick = { onConnect(hostPort, NativeBindings.CODEC_PASSTHROUGH) },
            enabled = hostPort.isNotBlank(),
            modifier = Modifier.padding(top = 16.dp),
        ) {
            Text("Connect")
        }
    }
}

@Composable
private fun ViewerScreen(session: XeniaSession) {
    val state by session.state.collectAsState()
    val frame by session.frame.collectAsState()
    val error by session.lastError.collectAsState()

    Box(modifier = Modifier.fillMaxSize()) {
        var boxWidth by remember { mutableStateOf(1) }
        var boxHeight by remember { mutableStateOf(1) }

        val bitmap = frame
        if (bitmap != null) {
            Image(
                bitmap = bitmap.asImageBitmap(),
                contentDescription = "Remote screen",
                contentScale = ContentScale.Fit,
                modifier = Modifier
                    .fillMaxSize()
                    .onSizeChanged { boxWidth = it.width; boxHeight = it.height }
                    .pointerInput(session) {
                        // Forward raw down/move/up as InputEvent::Touch
                        // phases directly -- deliberately NOT using
                        // detectTapGestures/detectDragGestures, which
                        // are higher-level gesture *recognizers* (click
                        // vs. long-press vs. drag, with timing
                        // thresholds) built to run the pointer-event
                        // stream to completion each; calling two of
                        // them back-to-back in one pointerInput block
                        // would mean the first call never returns and
                        // the second never starts. A remote-desktop
                        // client wants raw touch forwarding, not
                        // gesture classification, so a manual
                        // down/move/up loop is both simpler and
                        // semantically correct here.
                        awaitEachGesture {
                            val down = awaitFirstDown()
                            session.sendTouch(
                                (down.position.x / boxWidth).coerceIn(0f, 1f),
                                (down.position.y / boxHeight).coerceIn(0f, 1f),
                                0, // Down
                            )
                            while (true) {
                                val event = awaitPointerEvent()
                                val change = event.changes.firstOrNull() ?: break
                                val nx = (change.position.x / boxWidth).coerceIn(0f, 1f)
                                val ny = (change.position.y / boxHeight).coerceIn(0f, 1f)
                                if (!change.pressed) {
                                    session.sendTouch(nx, ny, 2) // Up
                                    break
                                }
                                session.sendTouch(nx, ny, 1) // Move
                            }
                        }
                    },
            )
        } else {
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

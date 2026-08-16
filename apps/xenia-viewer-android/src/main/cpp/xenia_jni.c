/**
 * JNI C glue layer for xenia-mobile-ffi Android bindings.
 *
 * Maps Kotlin/Java calls from io.luminousdynamics.xenia.NativeBindings
 * to the Rust extern "C" FFI defined in xenia-mobile-ffi/src/lib.rs.
 * Session handles are passed as jlong (opaque process-local u64 registry ids,
 * widened). They are not native addresses.
 *
 * Frame marshalling: JNI has no way to return an arbitrary C struct
 * (XeniaFrame) directly, so `pollFrame` packs a small fixed header +
 * the payload into one jbyteArray instead of a multi-call/object
 * dance: bytes [0..4)=width (u32 LE), [4..8)=height (u32 LE),
 * [8..16)=pts_ms (u64 LE), [16]=is_encoded (0/1),
 * [17..)=RGBA pixels or raw Annex-B H.264 NAL bytes (see
 * is_encoded). Native-endian packing is safe here because both sides
 * of this JNI boundary run on the same device (little-endian ARM64)
 * -- this isn't a wire format. Returns null if no frame is queued yet.
 *
 * File-transfer event marshalling: `pollFileTransferEvent` packs a
 * fixed 32-byte header + two variable-length UTF-8 strings into one
 * jbyteArray (same rationale as frames -- JNI can't return an
 * arbitrary C struct with embedded pointers directly): [0]=kind,
 * [1]=outgoing, [2]=accepted, [3]=ok (all 0/1 bytes),
 * [4..12)=transfer_id (u64 LE), [12..20)=done_bytes (u64 LE),
 * [20..28)=total_bytes (u64 LE), [28..30)=name_len (u16 LE),
 * [30..32)=detail_len (u16 LE), then name bytes, then detail bytes.
 * Returns null if no event is queued yet.
 */

#include <jni.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations of Rust extern "C" functions (xenia-mobile-ffi/src/lib.rs)
 * ═══════════════════════════════════════════════════════════════════════════ */

uint64_t xenia_connect(const char *host_port, int32_t codec, const char *recv_dir, uint64_t max_file_bytes);
int32_t  xenia_session_state(uint64_t handle);
char    *xenia_last_error(uint64_t handle);
void     xenia_string_free(char *s);

typedef struct {
    uint32_t width;
    uint32_t height;
    uint64_t pts_ms;
    bool     is_encoded;
    uint8_t *rgba;
    size_t   rgba_len;
} XeniaFrame;

XeniaFrame xenia_poll_frame(uint64_t handle);
void       xenia_frame_free(XeniaFrame frame);

void xenia_send_pointer(uint64_t handle, float x, float y, uint8_t button, uint8_t pressed);
void xenia_send_pointer_move(uint64_t handle, float x, float y);
void xenia_send_pointer_button(uint64_t handle, float x, float y, uint8_t button, uint8_t pressed);
void xenia_send_touch(uint64_t handle, uint8_t index, float x, float y, uint8_t phase, float pressure);
void xenia_send_key(uint64_t handle, uint32_t code, uint8_t pressed, uint8_t modifiers);
char *xenia_poll_clipboard(uint64_t handle);
void  xenia_send_clipboard(uint64_t handle, const char *text);

int32_t xenia_try_send_file(uint64_t handle, const char *name, const uint8_t *data, size_t data_len);

typedef struct {
    int32_t  kind;
    uint64_t transfer_id;
    bool     outgoing;
    bool     accepted;
    bool     ok;
    uint64_t done_bytes;
    uint64_t total_bytes;
    char    *name;
    char    *detail;
} XeniaFileTransferEvent;

XeniaFileTransferEvent xenia_poll_file_transfer_event(uint64_t handle);
void                   xenia_file_transfer_event_free(XeniaFileTransferEvent event);

void xenia_disconnect(uint64_t handle);

/* Helper: convert a Rust-allocated C string (or NULL) to a jstring,
 * freeing the Rust allocation via xenia_string_free either way. */
static jstring rust_string_to_jstring(JNIEnv *env, char *rust_str) {
    if (rust_str == NULL) {
        return NULL;
    }
    jstring result = (*env)->NewStringUTF(env, rust_str);
    xenia_string_free(rust_str);
    return result;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * JNI bindings
 * ═══════════════════════════════════════════════════════════════════════════ */

JNIEXPORT jlong JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_connect(JNIEnv *env, jclass clazz,
                                                       jstring hostPort, jint codec,
                                                       jstring recvDir, jlong maxFileBytes) {
    (void)clazz;
    if (hostPort == NULL) {
        return 0;
    }
    const char *cstr = (*env)->GetStringUTFChars(env, hostPort, NULL);
    if (cstr == NULL) {
        return 0;
    }
    const char *recvDirStr = NULL;
    if (recvDir != NULL) {
        recvDirStr = (*env)->GetStringUTFChars(env, recvDir, NULL);
    }
    uint64_t handle = xenia_connect(cstr, (int32_t)codec, recvDirStr, (uint64_t)maxFileBytes);
    (*env)->ReleaseStringUTFChars(env, hostPort, cstr);
    if (recvDirStr != NULL) {
        (*env)->ReleaseStringUTFChars(env, recvDir, recvDirStr);
    }
    return (jlong)handle;
}

JNIEXPORT jint JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sessionState(JNIEnv *env, jclass clazz,
                                                            jlong handle) {
    (void)env; (void)clazz;
    return (jint)xenia_session_state((uint64_t)handle);
}

JNIEXPORT jstring JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_lastError(JNIEnv *env, jclass clazz,
                                                         jlong handle) {
    (void)clazz;
    return rust_string_to_jstring(env, xenia_last_error((uint64_t)handle));
}

JNIEXPORT jbyteArray JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_pollFrame(JNIEnv *env, jclass clazz,
                                                         jlong handle) {
    (void)clazz;
    XeniaFrame frame = xenia_poll_frame((uint64_t)handle);
    if (frame.rgba == NULL || frame.rgba_len == 0) {
        return NULL;
    }

    const size_t header_len = 17;
    jsize total_len = (jsize)(header_len + frame.rgba_len);
    jbyteArray result = (*env)->NewByteArray(env, total_len);
    if (result == NULL) {
        xenia_frame_free(frame);
        return NULL;
    }

    uint8_t header[17];
    memcpy(&header[0], &frame.width, 4);
    memcpy(&header[4], &frame.height, 4);
    memcpy(&header[8], &frame.pts_ms, 8);
    header[16] = frame.is_encoded ? 1 : 0;

    (*env)->SetByteArrayRegion(env, result, 0, (jsize)header_len, (const jbyte *)header);
    (*env)->SetByteArrayRegion(env, result, (jsize)header_len, (jsize)frame.rgba_len,
                                (const jbyte *)frame.rgba);

    xenia_frame_free(frame);
    return result;
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendPointer(JNIEnv *env, jclass clazz,
                                                           jlong handle, jfloat x, jfloat y,
                                                           jint button, jboolean pressed) {
    (void)env; (void)clazz;
    xenia_send_pointer((uint64_t)handle, x, y, (uint8_t)button, pressed ? 1 : 0);
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendPointerMove(JNIEnv *env, jclass clazz,
                                                               jlong handle, jfloat x, jfloat y) {
    (void)env; (void)clazz;
    xenia_send_pointer_move((uint64_t)handle, x, y);
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendPointerButton(JNIEnv *env, jclass clazz,
                                                                 jlong handle, jfloat x, jfloat y,
                                                                 jint button, jboolean pressed) {
    (void)env; (void)clazz;
    xenia_send_pointer_button((uint64_t)handle, x, y, (uint8_t)button, pressed ? 1 : 0);
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendTouch(JNIEnv *env, jclass clazz,
                                                         jlong handle, jint index, jfloat x,
                                                         jfloat y, jint phase, jfloat pressure) {
    (void)env; (void)clazz;
    xenia_send_touch((uint64_t)handle, (uint8_t)index, x, y, (uint8_t)phase, pressure);
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendKey(JNIEnv *env, jclass clazz,
                                                       jlong handle, jint code, jboolean pressed,
                                                       jint modifiers) {
    (void)env; (void)clazz;
    xenia_send_key((uint64_t)handle, (uint32_t)code, pressed ? 1 : 0, (uint8_t)modifiers);
}

JNIEXPORT jstring JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_pollClipboard(JNIEnv *env, jclass clazz,
                                                             jlong handle) {
    (void)clazz;
    char *text = xenia_poll_clipboard((uint64_t)handle);
    return rust_string_to_jstring(env, text);
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendClipboard(JNIEnv *env, jclass clazz,
                                                             jlong handle, jstring text) {
    (void)clazz;
    if (text == NULL) {
        xenia_send_clipboard((uint64_t)handle, NULL);
        return;
    }
    const char *cstr = (*env)->GetStringUTFChars(env, text, NULL);
    if (cstr == NULL) {
        return;
    }
    xenia_send_clipboard((uint64_t)handle, cstr);
    (*env)->ReleaseStringUTFChars(env, text, cstr);
}

JNIEXPORT jboolean JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendFile(JNIEnv *env, jclass clazz,
                                                        jlong handle, jstring name,
                                                        jbyteArray data) {
    (void)clazz;
    if (name == NULL || data == NULL) {
        return JNI_FALSE;
    }
    const char *nameStr = (*env)->GetStringUTFChars(env, name, NULL);
    if (nameStr == NULL) {
        return JNI_FALSE;
    }
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        (*env)->ReleaseStringUTFChars(env, name, nameStr);
        return JNI_FALSE;
    }
    int32_t status = xenia_try_send_file(
        (uint64_t)handle, nameStr, (const uint8_t *)bytes, (size_t)len
    );
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, name, nameStr);
    return status == 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_pollFileTransferEvent(JNIEnv *env, jclass clazz,
                                                                     jlong handle) {
    (void)clazz;
    XeniaFileTransferEvent event = xenia_poll_file_transfer_event((uint64_t)handle);
    /* kind 0 == XENIA_FT_EVENT_NONE (see lib.rs) -- nothing queued. */
    if (event.kind == 0) {
        xenia_file_transfer_event_free(event);
        return NULL;
    }

    size_t name_len = event.name != NULL ? strlen(event.name) : 0;
    size_t detail_len = event.detail != NULL ? strlen(event.detail) : 0;
    const size_t header_len = 32;
    jsize total_len = (jsize)(header_len + name_len + detail_len);
    jbyteArray result = (*env)->NewByteArray(env, total_len);
    if (result == NULL) {
        xenia_file_transfer_event_free(event);
        return NULL;
    }

    uint8_t header[32];
    header[0] = (uint8_t)event.kind;
    header[1] = event.outgoing ? 1 : 0;
    header[2] = event.accepted ? 1 : 0;
    header[3] = event.ok ? 1 : 0;
    memcpy(&header[4], &event.transfer_id, 8);
    memcpy(&header[12], &event.done_bytes, 8);
    memcpy(&header[20], &event.total_bytes, 8);
    uint16_t name_len16 = (uint16_t)name_len;
    uint16_t detail_len16 = (uint16_t)detail_len;
    memcpy(&header[28], &name_len16, 2);
    memcpy(&header[30], &detail_len16, 2);

    (*env)->SetByteArrayRegion(env, result, 0, (jsize)header_len, (const jbyte *)header);
    if (name_len > 0) {
        (*env)->SetByteArrayRegion(env, result, (jsize)header_len, (jsize)name_len,
                                    (const jbyte *)event.name);
    }
    if (detail_len > 0) {
        (*env)->SetByteArrayRegion(env, result, (jsize)(header_len + name_len), (jsize)detail_len,
                                    (const jbyte *)event.detail);
    }

    xenia_file_transfer_event_free(event);
    return result;
}

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_disconnect(JNIEnv *env, jclass clazz,
                                                          jlong handle) {
    (void)env; (void)clazz;
    xenia_disconnect((uint64_t)handle);
}

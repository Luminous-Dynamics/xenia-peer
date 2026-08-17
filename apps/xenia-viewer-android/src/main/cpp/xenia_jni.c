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

int32_t xenia_check_send_file(uint64_t handle, size_t data_len);
int32_t xenia_reserve_send_file(uint64_t handle, size_t data_len, uint64_t *out_token);
int32_t xenia_claim_send_file_reservation(uint64_t handle, uint64_t token, size_t data_len);
bool    xenia_cancel_send_file_reservation(uint64_t handle, uint64_t token);
int32_t xenia_commit_send_file(uint64_t handle, uint64_t token, const char *name, const uint8_t *data, size_t data_len);
int32_t xenia_try_send_file(uint64_t handle, const char *name, const uint8_t *data, size_t data_len);
int32_t xenia_begin_send_file_stream(uint64_t handle, const char *name, uint64_t expected_len, uint64_t *out_token);
int32_t xenia_append_send_file_stream(uint64_t handle, uint64_t token, const uint8_t *data, size_t data_len);
int32_t xenia_finish_send_file_stream(uint64_t handle, uint64_t token);
bool    xenia_cancel_send_file_stream(uint64_t handle, uint64_t token);

typedef struct {
    bool     valid;
    uint32_t active_reserved;
    uint32_t active_copying;
    uint32_t available_command_slots;
    uint32_t command_capacity;
} XeniaFileTransferAdmissionSnapshot;

XeniaFileTransferAdmissionSnapshot xenia_file_transfer_admission_snapshot(uint64_t handle);

typedef struct {
    bool     valid;
    uint32_t active_reserved;
    uint32_t active_copying;
    uint32_t active_streaming;
    uint64_t active_stream_bytes;
    uint32_t available_command_slots;
    uint32_t command_capacity;
} XeniaFileTransferAdmissionSnapshotV2;

XeniaFileTransferAdmissionSnapshotV2 xenia_file_transfer_admission_snapshot_v2(uint64_t handle);

enum {
    XENIA_SEND_FILE_OK = 0,
    XENIA_SEND_FILE_INVALID_ARGUMENT = 1,
    XENIA_SEND_FILE_INVALID_HANDLE = 2,
    XENIA_SEND_FILE_QUEUE_FULL = 3,
    XENIA_SEND_FILE_SESSION_CLOSED = 4,
    XENIA_SEND_FILE_TOO_LARGE = 5,
    XENIA_SEND_FILE_INVALID_RESERVATION = 6,
    XENIA_SEND_FILE_RESERVATION_SIZE_MISMATCH = 7,
    XENIA_SEND_FILE_IO_ERROR = 8,
};

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

JNIEXPORT jintArray JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_fileTransferAdmissionSnapshot(
    JNIEnv *env, jclass clazz, jlong handle
) {
    (void)clazz;
    XeniaFileTransferAdmissionSnapshot snapshot =
        xenia_file_transfer_admission_snapshot((uint64_t)handle);
    if (!snapshot.valid) {
        return NULL;
    }
    jint values[4] = {
        (jint)snapshot.active_reserved,
        (jint)snapshot.active_copying,
        (jint)snapshot.available_command_slots,
        (jint)snapshot.command_capacity,
    };
    jintArray result = (*env)->NewIntArray(env, 4);
    if (result == NULL) {
        return NULL;
    }
    (*env)->SetIntArrayRegion(env, result, 0, 4, values);
    return result;
}

JNIEXPORT jlongArray JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_fileTransferAdmissionSnapshotV2(
    JNIEnv *env, jclass clazz, jlong handle
) {
    (void)clazz;
    XeniaFileTransferAdmissionSnapshotV2 snapshot =
        xenia_file_transfer_admission_snapshot_v2((uint64_t)handle);
    if (!snapshot.valid) {
        return NULL;
    }
    jlong values[6] = {
        (jlong)snapshot.active_reserved,
        (jlong)snapshot.active_copying,
        (jlong)snapshot.active_streaming,
        (jlong)snapshot.active_stream_bytes,
        (jlong)snapshot.available_command_slots,
        (jlong)snapshot.command_capacity,
    };
    jlongArray result = (*env)->NewLongArray(env, 6);
    if (result == NULL) {
        return NULL;
    }
    (*env)->SetLongArrayRegion(env, result, 0, 6, values);
    return result;
}

static jint jni_try_send_file_status(JNIEnv *env, jlong handle, jstring name, jbyteArray data) {
    if (name == NULL || data == NULL) {
        return XENIA_SEND_FILE_INVALID_ARGUMENT;
    }
    const char *nameStr = (*env)->GetStringUTFChars(env, name, NULL);
    if (nameStr == NULL) {
        return XENIA_SEND_FILE_INVALID_ARGUMENT;
    }
    jsize len = (*env)->GetArrayLength(env, data);
    uint64_t reservation = 0;
    int32_t admission = xenia_reserve_send_file(
        (uint64_t)handle, (size_t)len, &reservation
    );
    if (admission != XENIA_SEND_FILE_OK || reservation == 0) {
        (*env)->ReleaseStringUTFChars(env, name, nameStr);
        return admission != XENIA_SEND_FILE_OK
            ? (jint)admission
            : (jint)XENIA_SEND_FILE_INVALID_RESERVATION;
    }
    int32_t claim = xenia_claim_send_file_reservation(
        (uint64_t)handle, reservation, (size_t)len
    );
    if (claim != XENIA_SEND_FILE_OK) {
        (void)xenia_cancel_send_file_reservation((uint64_t)handle, reservation);
        (*env)->ReleaseStringUTFChars(env, name, nameStr);
        return (jint)claim;
    }
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        (void)xenia_cancel_send_file_reservation((uint64_t)handle, reservation);
        (*env)->ReleaseStringUTFChars(env, name, nameStr);
        return XENIA_SEND_FILE_INVALID_ARGUMENT;
    }
    int32_t status = xenia_commit_send_file(
        (uint64_t)handle, reservation, nameStr, (const uint8_t *)bytes, (size_t)len
    );
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    (*env)->ReleaseStringUTFChars(env, name, nameStr);
    return (jint)status;
}

JNIEXPORT jlongArray JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_beginSendFileStream(
    JNIEnv *env, jclass clazz, jlong handle, jstring name, jlong expectedLen
) {
    (void)clazz;
    jlong values[2] = { XENIA_SEND_FILE_INVALID_ARGUMENT, 0 };
    if (name == NULL || expectedLen < -1) {
        goto done;
    }
    const char *nameStr = (*env)->GetStringUTFChars(env, name, NULL);
    if (nameStr == NULL) {
        goto done;
    }
    uint64_t token = 0;
    uint64_t nativeExpected = expectedLen < 0 ? UINT64_MAX : (uint64_t)expectedLen;
    int32_t status = xenia_begin_send_file_stream(
        (uint64_t)handle, nameStr, nativeExpected, &token
    );
    (*env)->ReleaseStringUTFChars(env, name, nameStr);
    values[0] = (jlong)status;
    values[1] = (jlong)token;

done:
    jlongArray result = (*env)->NewLongArray(env, 2);
    if (result == NULL) {
        return NULL;
    }
    (*env)->SetLongArrayRegion(env, result, 0, 2, values);
    return result;
}

JNIEXPORT jint JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_appendSendFileStream(
    JNIEnv *env, jclass clazz, jlong handle, jlong token, jbyteArray data, jint dataLen
) {
    (void)clazz;
    if (data == NULL || dataLen < 0) {
        return XENIA_SEND_FILE_INVALID_ARGUMENT;
    }
    jsize arrayLen = (*env)->GetArrayLength(env, data);
    if (dataLen > arrayLen) {
        return XENIA_SEND_FILE_INVALID_ARGUMENT;
    }
    jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
        return XENIA_SEND_FILE_INVALID_ARGUMENT;
    }
    int32_t status = xenia_append_send_file_stream(
        (uint64_t)handle, (uint64_t)token, (const uint8_t *)bytes, (size_t)dataLen
    );
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    return (jint)status;
}

JNIEXPORT jint JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_finishSendFileStream(
    JNIEnv *env, jclass clazz, jlong handle, jlong token
) {
    (void)env; (void)clazz;
    return (jint)xenia_finish_send_file_stream((uint64_t)handle, (uint64_t)token);
}

JNIEXPORT jboolean JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_cancelSendFileStream(
    JNIEnv *env, jclass clazz, jlong handle, jlong token
) {
    (void)env; (void)clazz;
    return xenia_cancel_send_file_stream((uint64_t)handle, (uint64_t)token)
        ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_trySendFile(JNIEnv *env, jclass clazz,
                                                           jlong handle, jstring name,
                                                           jbyteArray data) {
    (void)clazz;
    return jni_try_send_file_status(env, handle, name, data);
}

JNIEXPORT jboolean JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_sendFile(JNIEnv *env, jclass clazz,
                                                        jlong handle, jstring name,
                                                        jbyteArray data) {
    (void)clazz;
    return jni_try_send_file_status(env, handle, name, data) == XENIA_SEND_FILE_OK ? JNI_TRUE : JNI_FALSE;
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

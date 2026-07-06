/**
 * JNI C glue layer for xenia-mobile-ffi Android bindings.
 *
 * Maps Kotlin/Java calls from io.luminousdynamics.xenia.NativeBindings
 * to the Rust extern "C" FFI defined in xenia-mobile-ffi/src/lib.rs.
 * Session handles are passed as jlong (opaque u64 handle, widened).
 *
 * Frame marshalling: JNI has no way to return an arbitrary C struct
 * (XeniaFrame) directly, so `pollFrame` packs a small fixed header +
 * the RGBA payload into one jbyteArray instead of a multi-call/object
 * dance: bytes [0..4)=width (u32 LE), [4..8)=height (u32 LE),
 * [8..16)=pts_ms (u64 LE), [16..)=RGBA pixels. Native-endian packing
 * is safe here because both sides of this JNI boundary run on the
 * same device (little-endian ARM64) -- this isn't a wire format.
 * Returns null if no frame is queued yet.
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>

/* ═══════════════════════════════════════════════════════════════════════════
 * Forward declarations of Rust extern "C" functions (xenia-mobile-ffi/src/lib.rs)
 * ═══════════════════════════════════════════════════════════════════════════ */

uint64_t xenia_connect(const char *host_port, int32_t codec);
int32_t  xenia_session_state(uint64_t handle);
char    *xenia_last_error(uint64_t handle);
void     xenia_string_free(char *s);

typedef struct {
    uint32_t width;
    uint32_t height;
    uint64_t pts_ms;
    uint8_t *rgba;
    size_t   rgba_len;
} XeniaFrame;

XeniaFrame xenia_poll_frame(uint64_t handle);
void       xenia_frame_free(XeniaFrame frame);

void xenia_send_pointer(uint64_t handle, float x, float y, uint8_t button, uint8_t pressed);
void xenia_send_touch(uint64_t handle, uint8_t index, float x, float y, uint8_t phase, float pressure);
void xenia_send_key(uint64_t handle, uint32_t code, uint8_t pressed, uint8_t modifiers);
void xenia_disconnect(uint64_t handle);

/* ═══════════════════════════════════════════════════════════════════════════
 * JNI bindings
 * ═══════════════════════════════════════════════════════════════════════════ */

JNIEXPORT jlong JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_connect(JNIEnv *env, jclass clazz,
                                                       jstring hostPort, jint codec) {
    (void)clazz;
    if (hostPort == NULL) {
        return 0;
    }
    const char *cstr = (*env)->GetStringUTFChars(env, hostPort, NULL);
    if (cstr == NULL) {
        return 0;
    }
    uint64_t handle = xenia_connect(cstr, (int32_t)codec);
    (*env)->ReleaseStringUTFChars(env, hostPort, cstr);
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
    char *msg = xenia_last_error((uint64_t)handle);
    if (msg == NULL) {
        return NULL;
    }
    jstring result = (*env)->NewStringUTF(env, msg);
    xenia_string_free(msg);
    return result;
}

JNIEXPORT jbyteArray JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_pollFrame(JNIEnv *env, jclass clazz,
                                                         jlong handle) {
    (void)clazz;
    XeniaFrame frame = xenia_poll_frame((uint64_t)handle);
    if (frame.rgba == NULL || frame.rgba_len == 0) {
        return NULL;
    }

    const size_t header_len = 16;
    jsize total_len = (jsize)(header_len + frame.rgba_len);
    jbyteArray result = (*env)->NewByteArray(env, total_len);
    if (result == NULL) {
        xenia_frame_free(frame);
        return NULL;
    }

    uint8_t header[16];
    memcpy(&header[0], &frame.width, 4);
    memcpy(&header[4], &frame.height, 4);
    memcpy(&header[8], &frame.pts_ms, 8);

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

JNIEXPORT void JNICALL
Java_io_luminousdynamics_xenia_NativeBindings_disconnect(JNIEnv *env, jclass clazz,
                                                          jlong handle) {
    (void)env; (void)clazz;
    xenia_disconnect((uint64_t)handle);
}

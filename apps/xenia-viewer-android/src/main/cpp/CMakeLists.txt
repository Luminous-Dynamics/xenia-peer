cmake_minimum_required(VERSION 3.22)
project(xenia_jni C)

# JNI C glue -- thin layer between Kotlin and the Rust cdylib. Present
# for documentation/IDE tooling; the actual build path is
# build-jni.sh calling the NDK clang directly (see its header comment
# for why -- avoids AGP trying to install CMake into the read-only
# Nix store, matching the symthaea-soma precedent).
add_library(xenia_jni SHARED xenia_jni.c)

add_library(xenia_mobile_ffi SHARED IMPORTED)
set_target_properties(xenia_mobile_ffi PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libxenia_mobile_ffi.so
)

target_link_libraries(xenia_jni xenia_mobile_ffi log)

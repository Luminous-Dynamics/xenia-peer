// KNOWN ISSUE (not blocking, verified live on a real Pixel 8 Pro):
// `adb install` shows a 16KB-page-size compatibility warning for
// libxenia_mobile_ffi.so ("uncompressed library not aligned"). The
// .so's own ELF LOAD segments ARE 16KB-aligned (see build-jni.sh's
// RUSTFLAGS) -- the remaining gap is APK-level: this AGP version
// (8.2.2) doesn't automatically 16KB-align uncompressed native libs
// inside the APK zip itself. Fixing that needs AGP 8.5.1+, which
// wasn't worth pulling in during Phase 1 (real risk of an unrelated
// Gradle/Kotlin/Compose version cascade) given the app installs and
// runs correctly on this device today -- 16KB kernel pages are an
// opt-in Android 15+ thing this device isn't using. Revisit before
// any real device with 16KB pages enabled, or before Play Store
// submission.
plugins {
    id("com.android.application") version "8.2.2"
    id("org.jetbrains.kotlin.android") version "1.9.22"
}

android {
    namespace = "io.luminousdynamics.xenia"
    compileSdk = 34
    buildToolsVersion = "34.0.0" // Match Nix-provided SDK (read-only store can't install others)
    ndkVersion = "27.0.12077973"

    defaultConfig {
        applicationId = "io.luminousdynamics.xenia"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.0.1-phase1"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    // Native build is done outside Gradle (build-jni.sh compiles
    // xenia_jni.c with NDK clang and copies libxenia_jni.so +
    // libxenia_mobile_ffi.so to jniLibs/) -- avoids AGP trying to
    // install CMake into the read-only Nix store. Matches the
    // symthaea-soma precedent exactly.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.8"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.activity:activity-compose:1.8.2")
    implementation("androidx.compose.ui:ui:1.5.4")
    implementation("androidx.compose.ui:ui-graphics:1.5.4")
    implementation("androidx.compose.material3:material3:1.1.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.0")

    testImplementation("junit:junit:4.13.2")
}

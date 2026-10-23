plugins { id("com.android.application") }
val probeAbi = providers.gradleProperty("wonadAbi").getOrElse("x86_64")
require(probeAbi in setOf("x86_64", "arm64-v8a")) { "Unsupported Wonad probe ABI" }

android {
    namespace = "org.wonad.probe"
    compileSdk = 35
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    packaging { jniLibs.useLegacyPackaging = true }
    defaultConfig {
        applicationId = "org.wonad.probe"
        minSdk = 28
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-gate"
        testInstrumentationRunner = "org.wonad.probe.ProbeInstrumentation"
        ndk { abiFilters += probeAbi }
    }
    buildTypes {
        release {
            isDebuggable = false
            // Signing is supplied by the caller, never checked into this tree.
        }
    }
    sourceSets {
        getByName("main") {
            java.srcDir("../feasibility/java")
            jniLibs.srcDir("../out/android-native")
        }
    }
}

tasks.register("requireAndroidNativeProbe") {
    doLast {
        val native = rootProject.file("out/android-native/$probeAbi/libwonad_probe.so")
        check(native.isFile) {
            "Build the Android Haskell JNI library with feasibility/build-native.sh first. " +
            "A host Linux library is not an Android runtime."
        }
        val result = ProcessBuilder("python3", rootProject.file("tools/check_native.py").path,
            "--abi", probeAbi, native.path).inheritIO().start().waitFor()
        check(result == 0) { "Native library failed Android ELF validation" }
    }
}
tasks.named("preBuild") { dependsOn("requireAndroidNativeProbe") }

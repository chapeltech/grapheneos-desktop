plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
android {
    namespace = "org.wonad.desktop.prerequisites"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.wonad.desktop.prerequisites"
        minSdk = 35
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-native-prerequisite-test-only"
        ndk { abiFilters += "x86_64" }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets.getByName("main") {
        // Exact existing public-client helper includes, not the Security APK's
        // manifest/runners/services or a copy of the target policy.
        java.srcDir("../session-security/src/main/kotlin")
        java.include("org/wonad/desktop/prerequisites/**",
            "org/wonad/desktop/security/NativeSecurityClient.kt",
            "org/wonad/desktop/security/NativeProbeContinuity.kt")
        // Parent supplies a separately frozen ordinary test JNI build here.
        // This is NOT copied from SystemUI's installed privileged library.
        jniLibs.srcDir("../out/native-prerequisites-jni")
    }
    packaging { jniLibs.useLegacyPackaging = true }
}
dependencies {
    implementation(project(":desktop-sdk"))
    implementation(project(":broker-core"))
    testImplementation("junit:junit:4.13.2")
}
tasks.register("requirePrerequisiteNative") {
    doLast {
        val native = rootProject.file("out/native-prerequisites-jni/x86_64/libwonad_broker_jni.so")
        check(native.isFile) { "Parent must freeze the separately built ordinary test Rust JNI first" }
        check(ProcessBuilder("python3", rootProject.file("tools/check_native.py").path,
            "--abi", "x86_64", "--profile", "broker", native.path).inheritIO().start().waitFor() == 0)
    }
}
tasks.named("preBuild") { dependsOn("requirePrerequisiteNative") }

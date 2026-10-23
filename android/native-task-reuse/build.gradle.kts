plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
android {
    namespace = "org.wonad.desktop.taskreuse"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.wonad.desktop.taskreuse"
        minSdk = 35
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-native-task-reuse-test-only"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes.getByName("release") {
        // The ordinary test must have the real target's existing trusted
        // development certificate, without debug instrumentation privileges.
        isDebuggable = false
        signingConfig = signingConfigs.getByName("debug")
    }
    sourceSets.getByName("main") {
        // Read-only shared ordinary-client helpers, not its manifest/runners.
        java.srcDir("../session-security/src/main/kotlin")
        java.include("org/wonad/desktop/taskreuse/**",
            "org/wonad/desktop/security/NativeSecurityClient.kt",
            "org/wonad/desktop/security/NativeProbeContinuity.kt")
    }
}
dependencies {
    implementation(project(":desktop-sdk"))
    testImplementation("junit:junit:4.13.2")
}

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
android {
    namespace = "org.wonad.desktop.security"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.wonad.desktop.test"
        minSdk = 35
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-test-only"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
// A normal androidTest APK omits dependencies supplied by the target app. This
// standalone test APK also runs a service in its OWN process, so it needs both
// the SDK and Kotlin runtime packaged, not just supplied by instrumentation.
dependencies {
    implementation(project(":desktop-sdk"))
    testImplementation("junit:junit:4.13.2")
}

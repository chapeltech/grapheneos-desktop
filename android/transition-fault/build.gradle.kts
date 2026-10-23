plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies { testImplementation("junit:junit:4.13.2") }
android {
    namespace = "org.wonad.desktop.transitionfault"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.wonad.desktop.transitionfault"
        minSdk = 35
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-test-only"
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildTypes {
        getByName("debug") {
            // SystemUI's Kotlin runtime is R8-trimmed. No-restart instrumentation
            // must not accidentally link against those incomplete parent classes.
            isDebuggable = false // R8 deliberately skips repackaging debuggable builds.
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}
// This APK is never shipped or trusted by Wonad. For an isolated userdebug test,
// sign it with the selected image's development platform key so Android can
// verify the SystemUI instrumentation signature without a signature bypass.

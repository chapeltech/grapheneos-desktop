plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

android {
    namespace = "org.wonad.desktop"
    compileSdk = 35
    defaultConfig {
        // This deliberately replaces, rather than co-installs with, the product
        // client. The OS authenticates this exact package and its release signer.
        applicationId = "org.wonad.desktop"
        minSdk = 35
        targetSdk = 35
        versionCode = 1
        versionName = "3.0-phase1-conformance"
    }
    buildTypes {
        release {
            isDebuggable = false
            // No key is embedded and release never falls back to the debug key.
            // Sign this unsigned output with the frozen Wonad release identity.
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions {
        // Local JVM callback tests exercise the real generated Binder Stub's
        // process-local queues and DTOs; android.jar supplies no Binder runtime.
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    // The conformance client has no dependency on product Wonad or native code.
    implementation(project(":desktop-sdk"))
    testImplementation("junit:junit:4.13.2")
}

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
dependencies { testImplementation("junit:junit:4.13.2") }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
android {
    namespace = "org.wonad.imefixture"
    compileSdk = 35
    defaultConfig {
        applicationId = "org.wonad.imefixture"
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

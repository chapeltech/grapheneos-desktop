plugins {
    id("com.android.application") version "8.9.2"
    id("org.jetbrains.kotlin.android") version "2.1.21"
}
val catalogKey = providers.gradleProperty("catalogKey").get()
val desktopCert = providers.gradleProperty("desktopCert").get()
require(Regex("[A-Za-z0-9+/]{58}[AEIMQUYcgkosw048]=").matches(catalogKey))
require(Regex("[a-f0-9]{64}").matches(desktopCert))
android {
    namespace = "org.wonad.desktop.updates"
    compileSdk = 35
    defaultConfig {
        applicationId = namespace!!
        minSdk = 35
        targetSdk = 35
        versionCode = providers.gradleProperty("desktopVersionCode").get().toInt()
        require(versionCode in 1..2_100_000_000)
        versionName = "0.1"
        buildConfigField("String", "CATALOG_KEY", "\"$catalogKey\"")
        buildConfigField("String", "DESKTOP_CERT", "\"$desktopCert\"")
    }
    buildFeatures { buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
dependencies {
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

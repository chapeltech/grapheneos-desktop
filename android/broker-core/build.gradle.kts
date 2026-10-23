plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
android {
    namespace = "org.wonad.desktop.broker"
    compileSdk = 35
    defaultConfig {
        minSdk = 35
        testInstrumentationRunner = "org.wonad.desktop.broker.NativeBrokerInstrumentation"
    }
    sourceSets.getByName("androidTest") {
        java.srcDir("src/test/kotlin")
        java.srcDir("../input-core/src/main/kotlin")
        jniLibs.srcDir("../out/broker-native")
    }
    sourceSets.getByName("test").java.srcDir("../input-core/src/main/kotlin")
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    testOptions.unitTests.all { test ->
        test.jvmArgs("-Xcheck:jni")
        providers.gradleProperty("wonadBrokerNativeLibrary").orNull?.let { path ->
            test.systemProperty("java.library.path", file(path).parent)
        }
    }
}
dependencies {
    implementation(project(":desktop-sdk"))
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("junit:junit:4.13.2")
}

tasks.register("requireAndroidNativeBroker") {
    doLast {
        val native = rootProject.file("out/broker-native/x86_64/libwonad_broker_jni.so")
        check(native.isFile) { "Build the Android Rust library with broker-jni/build.sh android first" }
        val result = ProcessBuilder("python3", rootProject.file("tools/check_native.py").path,
            "--abi", "x86_64", "--profile", "broker", native.path).inheritIO().start().waitFor()
        check(result == 0) { "Rust JNI library failed Android ELF validation" }
        val input = rootProject.file("out/broker-native/x86_64/libwonad_input_jni.so")
        check(input.isFile) { "Build the Android input library with input-jni/build.sh android first" }
        val inputResult = ProcessBuilder("python3", rootProject.file("tools/check_native.py").path,
            "--abi", "x86_64", "--profile", "input", input.path).inheritIO().start().waitFor()
        check(inputResult == 0) { "Input JNI library failed Android ELF validation" }
    }
}
tasks.matching { it.name == "preDebugAndroidTestBuild" }.configureEach {
    dependsOn("requireAndroidNativeBroker")
}

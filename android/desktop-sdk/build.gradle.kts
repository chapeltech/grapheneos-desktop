plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    `maven-publish`
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

group = "org.wonad"
version = "3.1.0"

android {
    namespace = "org.wonad.desktop.api"
    compileSdk = 35
    defaultConfig { minSdk = 35 }
    buildFeatures { aidl = true }
    publishing {
        singleVariant("release") { withSourcesJar() }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies { testImplementation("junit:junit:4.13.2") }

// AIDL normally embeds its absolute output/input/temporary dependency paths in
// the generated Java comment.  Those comments make otherwise identical source
// JARs depend on checkout location and a random temporary filename.  Preserve
// the useful generated source while replacing only that non-semantic trace.
tasks.withType<Jar>().configureEach {
    if (name == "sourceReleaseJar") {
        // Canonical publication metadata, independent of read-only source freezes.
        filePermissions { unix("rw-r--r--") }
        eachFile {
            if (name.endsWith(".java")) {
                filter { line: String ->
                    if (line.startsWith(" * Using: ")) {
                        " * Generated from the frozen Wonad API-v3 AIDL."
                    } else {
                        line
                    }
                }
            }
        }
    }
}

val contractArchive by tasks.registering(Zip::class) {
    archiveBaseName.set("desktop-sdk")
    archiveVersion.set(project.version.toString())
    archiveClassifier.set("contract")
    destinationDirectory.set(layout.buildDirectory.dir("contract"))
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
    // Normative documents/baseline are always 0644, even when inputs are 0400.
    // The verifier CopySpec below deliberately overrides this with 0755.
    filePermissions { unix("rw-r--r--") }
    from("API-v3.md")
    from(rootProject.file("tests/fixtures/desktop-sdk-contract-v3.1.json")) {
        rename { "desktop-sdk-contract-v3.json" }
    }
    from(rootProject.file("tools/sdk_contract.py")) {
        rename { "verify-desktop-sdk-contract.py" }
        filePermissions { unix("rwxr-xr-x") }
    }
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = project.group.toString()
            artifactId = "desktop-sdk"
            version = project.version.toString()
            afterEvaluate { from(components["release"]) }
            artifact(contractArchive)
        }
    }
    repositories {
        maven {
            name = "phase1"
            url = uri(layout.buildDirectory.dir("phase1-repository"))
        }
    }
}

tasks.register<Exec>("verifyPhase1Publication") {
    group = "verification"
    description = "Fail-closed verification of the local frozen API-v3 Maven publication"
    dependsOn("publishReleasePublicationToPhase1Repository")
    workingDir(rootProject.projectDir)
    commandLine(
        "python3",
        rootProject.file("tools/verify_sdk_publication.py"),
        layout.buildDirectory.dir("phase1-repository").get().asFile,
        "--version", project.version.toString(),
    )
}

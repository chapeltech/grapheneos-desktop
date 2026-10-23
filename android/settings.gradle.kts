pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories { google(); mavenCentral() }
}
rootProject.name = "grapheneos-desktop-contract"
include(":desktop-sdk", ":broker-core", ":conformance", ":probe", ":fixture", ":ime-fixture",
    ":session-security", ":native-prerequisites", ":native-task-reuse", ":transition-fault")

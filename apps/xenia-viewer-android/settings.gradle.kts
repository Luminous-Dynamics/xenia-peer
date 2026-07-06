pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "xenia-viewer-android"

// Single flat application module (root) -- unlike symthaea-soma's
// library+demo split, this app has no embed-elsewhere-as-an-SDK use
// case, so there's no value in a separate library module.

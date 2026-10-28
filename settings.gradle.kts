pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
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
    versionCatalogs {
        create("libs") {
            library("androidx-core-ktx", "androidx.core:core-ktx:1.12.0")
            library("androidx-appcompat", "androidx.appcompat:appcompat:1.6.1")
            library("material", "com.google.android.material:material:1.11.0")
            library("junit", "junit:junit:4.13.2")
            library("androidx-junit", "androidx.test.ext:junit:1.1.5")
            library("androidx-espresso-core", "androidx.test.espresso:espresso-core:3.5.1")
            
            plugin("android-application", "com.android.application").version("8.8.2")
            plugin("kotlin-android", "org.jetbrains.kotlin.android").version("1.9.22")
            plugin("android-library", "com.android.library").version("8.8.2")
        }
    }
}

rootProject.name = "UserSU"
include(":usersu")
include(":usersu-server")

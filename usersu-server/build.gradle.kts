// import sun.jvmstat.monitor.MonitoredVmUtil.commandLine

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "dev.github.thepanoc95.usersu.server"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        aidl = true
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    ndkVersion = "26.1.10909125"
}

dependencies {
    compileOnly("androidx.annotation:annotation:1.7.1")
}

tasks.register("dexJar") {
    dependsOn("assembleRelease")
    doLast {
        val androidHome = System.getenv("ANDROID_HOME") ?: System.getenv("ANDROID_SDK_ROOT")
        if (androidHome.isNullOrEmpty()) {
            throw GradleException("ANDROID_HOME or ANDROID_SDK_ROOT environment variable not set")
        }
        val buildToolsDir = File(androidHome, "build-tools")
        val buildToolsVersionDir = buildToolsDir.listFiles()?.firstOrNull { it.isDirectory }
            ?: throw GradleException("No build-tools found in $buildToolsDir")
        
        val d8 = File(buildToolsVersionDir, "d8")
        if (!d8.exists()) {
            throw GradleException("d8 tool not found at ${d8.absolutePath}")
        }

        val classesJar = File(project.projectDir, "build/intermediates/aar_main_jar/release/syncReleaseLibJars/classes.jar")
        if (!classesJar.exists()) {
            throw GradleException("Compiled classes.jar not found at ${classesJar.absolutePath}")
        }

        val outputDir = File(project.projectDir, "build/outputs/dex_temp")
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        ProcessBuilder(
            d8.absolutePath,
            "--output",
            outputDir.absolutePath,
            classesJar.absolutePath
        ).inheritIO().start().waitFor()

        val classesDex = File(outputDir, "classes.dex")
        val finalDex = File(project.projectDir, "build/outputs/usersu-server.dex")
        if (classesDex.exists()) {
            finalDex.delete()
            classesDex.renameTo(finalDex)
            outputDir.deleteRecursively()
            println("✓ Successfully generated DEX file at: ${finalDex.absolutePath}")
        } else {
            throw GradleException("d8 failed to generate classes.dex")
        }
    }
}

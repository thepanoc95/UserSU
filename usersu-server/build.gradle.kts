plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "dev.github.thepanoc95.usersu.server"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
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
}

dependencies {
    compileOnly("androidx.annotation:annotation:1.7.1")
}

// Task to run d8 tool and generate DEX for app_process
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

        val classesJar = File(project.projectDir, "build/intermediates/aar_main_jar/release/classes.jar")
        if (!classesJar.exists()) {
            throw GradleException("Compiled classes.jar not found at ${classesJar.absolutePath}")
        }

        val outputDir = File(project.projectDir, "build/outputs/dex_temp")
        outputDir.deleteRecursively()
        outputDir.mkdirs()

        project.exec {
            commandLine(
                d8.absolutePath,
                "--output", outputDir.absolutePath,
                classesJar.absolutePath
            )
        }

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

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "dev.github.thepanoc95.usersu"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.github.thepanoc95.usersu"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
<<<<<<< HEAD
    buildFeatures {
        aidl = false
=======

    buildFeatures {
        aidl = true
>>>>>>> 8bf0fd641d74359ff87d417a0ea4facfb798eac1
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    // Add dependency on usersu-server to access generated AIDL classes
    implementation(project(":usersu-server"))
}

// Automatically copy daemon dex to assets before building
val copyServerDex = tasks.register<Copy>("copyServerDex") {
    dependsOn(":usersu-server:dexJar")
    from(project(":usersu-server").projectDir.resolve("build/outputs/usersu-server.dex"))
    into(project.projectDir.resolve("src/main/assets"))
}

tasks.named("preBuild") {
    dependsOn(copyServerDex)
}


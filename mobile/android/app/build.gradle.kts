plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.goteleport.vnet.android"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.goteleport.vnet.android"
        // 26 matches the -androidapi passed to gomobile bind.
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1-prototype"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Signed with the debug key so the prototype can be sideloaded
            // without any key management.
            signingConfig = signingConfigs.getByName("debug")
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
        viewBinding = false
    }

    splits {
        abi {
            isEnable = true
            reset()
            // arm64 for phones, x86_64 for emulators. A universal APK is also
            // produced so a single file can be sideloaded anywhere.
            include("arm64-v8a", "x86_64")
            isUniversalApk = true
        }
    }

    packaging {
        // The Go runtime is a ~96 MB shared library per ABI. Compressing it in
        // the APK takes the download from ~98 MB to ~30 MB, at the cost of
        // extracting it at install time. That is the right trade for something
        // being sideloaded; a store build would set this to false so the
        // library can be mapped straight out of the APK.
        jniLibs.useLegacyPackaging = true
    }
}

dependencies {
    // Built by `gomobile bind`; see mobile/android/README.md.
    implementation(files("libs/vnet.aar"))

    implementation("androidx.appcompat:appcompat:1.7.0")
    // Custom Tabs, so login runs in Chrome where the user's security key and
    // passkeys already work.
    implementation("androidx.browser:browser:1.8.0")
}

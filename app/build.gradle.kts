plugins {
  alias(libs.plugins.android.application)
  alias(libs.plugins.kotlin.android)
  alias(libs.plugins.kotlin.compose)
  id("org.jetbrains.kotlin.plugin.serialization") version "2.1.0"
}

android {
  namespace = "io.github.immaghzbad.aetherst"
  compileSdk = 36

  defaultConfig {
    applicationId = "io.github.immaghzbad.aetherst"
    minSdk = 26
    targetSdk = 35
    versionCode = 26
    versionName = "2.1.5"

    testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

    externalNativeBuild {
      ndkBuild {
        abiFilters("arm64-v8a")
      }
    }
  }

  externalNativeBuild {
    ndkBuild {
      path = file("src/main/cpp/Android.mk")
    }
  }

  ndkVersion = "30.0.15729638"

  signingConfigs {
    create("release") {
      val envKeystore = System.getenv("KEYSTORE_FILE")
      storeFile = when {
        envKeystore != null && file(envKeystore).exists() -> file(envKeystore)
        envKeystore != null && rootProject.file(envKeystore).exists() -> rootProject.file(envKeystore)
        file("src/main/release.jks").exists() -> file("src/main/release.jks")
        else -> rootProject.file("app/src/main/release.jks")
      }
      storePassword = System.getenv("KEYSTORE_PASSWORD") ?: "aether123456"
      keyAlias = System.getenv("KEY_ALIAS") ?: "aetherst"
      keyPassword = System.getenv("KEY_PASSWORD") ?: "aether123456"
      enableV1Signing = true
      enableV2Signing = true
      enableV3Signing = true
      enableV4Signing = false
    }
  }

  buildTypes {
    release {
      isCrunchPngs = true
      isMinifyEnabled = true
      isShrinkResources = true
      proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
      signingConfig = signingConfigs.getByName("release")
    }
    debug { }
  }

  splits {
    abi {
      isEnable = true
      reset()
      include("arm64-v8a")
      isUniversalApk = true
    }
  }

  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
  }

  kotlin {
    compilerOptions {
      jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
  }

  buildFeatures {
    compose = true
    buildConfig = true
  }
  testOptions { unitTests { isIncludeAndroidResources = true } }

  packaging {
    jniLibs {
      useLegacyPackaging = true
    }
  }
}

dependencies {
  implementation(fileTree(mapOf("dir" to "libs", "include" to listOf("*.aar", "*.jar"))))
  implementation(project(":composeApp"))
  implementation(platform(libs.androidx.compose.bom))
  implementation(libs.androidx.activity.compose)
  implementation(libs.androidx.compose.material.icons.core)
  implementation(libs.androidx.compose.material.icons.extended)
  implementation(libs.androidx.compose.material3)
  implementation(libs.androidx.compose.ui)
  implementation(libs.androidx.compose.ui.graphics)
  implementation(libs.androidx.compose.ui.tooling.preview)
  implementation(libs.androidx.core.ktx)
  implementation(libs.androidx.datastore.preferences)
  implementation(libs.androidx.lifecycle.runtime.compose)
  implementation(libs.androidx.lifecycle.runtime.ktx)
  implementation(libs.androidx.lifecycle.viewmodel.compose)
  implementation(libs.androidx.navigation.compose)
  implementation(libs.androidx.room.ktx)
  implementation(libs.androidx.room.runtime)
  implementation(libs.converter.moshi)
  implementation(libs.kotlinx.coroutines.android)
  implementation(libs.kotlinx.coroutines.core)
  implementation(libs.kotlinx.serialization.json)
  implementation(libs.logging.interceptor)
  implementation(libs.moshi.kotlin)
  implementation(libs.okhttp)
  implementation(libs.retrofit)
  testImplementation(libs.androidx.compose.ui.test.junit4)
  testImplementation(libs.androidx.core)
  testImplementation(libs.androidx.junit)
  testImplementation(libs.junit)
  testImplementation(libs.kotlinx.coroutines.test)
  testImplementation(libs.robolectric)
  androidTestImplementation(libs.androidx.espresso.core)
  androidTestImplementation(libs.androidx.runner)
  debugImplementation(libs.androidx.compose.ui.test.manifest)
  debugImplementation(libs.androidx.compose.ui.tooling)
}

tasks.register("prepareSingBox114") {
  doLast {
    val legacyBridge = file("src/main/java/io/github/immaghzbad/aetherst/core/SocksTunBridge.kt")
    if (legacyBridge.exists()) {
      legacyBridge.delete()
      println("==> Deleted legacy SocksTunBridge.kt")
    }
    val jniDir = file("src/main/jniLibs/arm64-v8a")
    jniDir.mkdirs()
    val targetSo = File(jniDir, "libsing-box.so")
    if (!targetSo.exists() || targetSo.length() < 1024 * 1024) {
      println("==> Downloading official Sing-box v1.14.4 Android arm64 binary...")
      try {
        val pb = ProcessBuilder(
          "sh", "-c",
          "curl -L -sS https://github.com/SagerNet/sing-box/releases/download/v1.14.4/sing-box-1.14.4-android-arm64.tar.gz -o sb114.tar.gz && " +
          "tar -xzf sb114.tar.gz && " +
          "cp sing-box-1.14.4-android-arm64/sing-box src/main/jniLibs/arm64-v8a/libsing-box.so && " +
          "chmod 755 src/main/jniLibs/arm64-v8a/libsing-box.so && " +
          "rm -rf sb114.tar.gz sing-box-1.14.4-android-arm64"
        )
        pb.directory(projectDir)
        pb.inheritIO()
        val code = pb.start().waitFor()
        println("==> Sing-box v1.14.4 bundle result code: $code (size=${targetSo.length()})")
      } catch (e: Exception) {
        println("==> Sing-box v1.14.4 download warning: ${e.message}")
      }
    }
  }
}

tasks.matching { it.name == "preBuild" }.configureEach {
  dependsOn("prepareSingBox114")
}

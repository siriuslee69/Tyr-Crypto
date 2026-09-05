plugins {
  id("com.android.application")
  id("org.jetbrains.kotlin.android")
}

android {
  namespace = "org.tyrcrypto.harness"
  compileSdk = 36
  buildToolsVersion = "35.0.0"

  defaultConfig {
    applicationId = "org.tyrcrypto.harness"
    minSdk = 24
    targetSdk = 36
    versionCode = 1
    versionName = "0.1"
  }

  buildTypes {
    debug {
      isDebuggable = true
    }
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

  sourceSets {
    getByName("main").jniLibs.srcDir("src/main/jniLibs")
  }

  packaging {
    jniLibs {
      useLegacyPackaging = true
    }
  }
}

dependencies {
  implementation("androidx.core:core-ktx:1.13.1")
  implementation("androidx.appcompat:appcompat:1.7.0")
}

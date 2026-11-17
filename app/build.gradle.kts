plugins {
    id("com.android.application") version "9.2.1"
}

android {
    enableKotlin = false
    namespace = "dev.localtest.xiaomicloudsync"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.localtest.xiaomicloudsync"
        minSdk = 34
        targetSdk = 36
        versionCode = 17
        versionName = "0.17.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    compileOnly("io.github.libxposed:api:102.0.0")
}

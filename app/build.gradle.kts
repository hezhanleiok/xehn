plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.xiaohe.vpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.xiaohe.vpn"
        minSdk = 24          // 与 gomobile 的 -androidapi 24 对齐
        targetSdk = 35
        // 每次改图标/名字都往上加：启动器（尤其 MIUI）会按 包名+versionCode
        // 缓存图标，版本号不变时覆盖安装会继续显示旧图标。
        // 规矩（见 docs/pitfalls.md 第 5 节）：每轮改动都要 +1，并在版本说明里写清这一版
        // 相对上一版变/没变什么。启动器按「包名 + versionCode」缓存图标，不递增会显示旧图标。
        versionCode = 4
        versionName = "0.2.2"

        // 只出 arm64 + arm。x86_64 仅在模拟器上有意义，需要额外跑一次
        // gomobile bind -target=android/amd64 并放入 libs/。
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }
    }

    buildFeatures {
        compose = true
        // 「关于 / 更新」页要显示版本号与包名，它们由 AGP 生成的 BuildConfig 提供。
        // AGP 8 起 buildConfig 默认是关的，不开就编译不过。
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources.excludes += setOf("/META-INF/{AL2.0,LGPL2.1}", "/META-INF/DEPENDENCIES")
    }

    buildTypes {
        release {
            // 引擎是 Go 编译的原生库，R8 不参与；Kotlin 侧先不混淆，等真机跑通再开。
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    // gomobile 产物。用 tools/build-engine.ps1 生成；没有它时 Kotlin 里的
    // com.xiaohe.engine.* 会编译不过 —— 这是正常的，先生成再构建。
    implementation(files("libs/engine.aar"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")

    implementation(platform("androidx.compose:compose-bom:2024.10.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")
}

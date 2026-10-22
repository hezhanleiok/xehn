// 顶层构建脚本：只声明插件版本，不在这里配置模块。
plugins {
    id("com.android.application") version "8.7.3" apply false
    id("org.jetbrains.kotlin.android") version "2.0.21" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.21" apply false
}

// 版本都可以升，但三者要匹配：AGP 8.7.x 需要 Gradle 8.9+ 与 JDK 17+。
// Kotlin 2.x 起 Compose 编译器随 Kotlin 发布，不再单独写 composeOptions。

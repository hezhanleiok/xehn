// 仓库顺序：国内镜像优先，官方源兜底。
// 这台机器连 github.com / services.gradle.org 会超时（实测），所以：
//   - Gradle 发行包走 mirrors.cloud.tencent.com（见 gradle/wrapper/gradle-wrapper.properties）
//   - 依赖走阿里云镜像（AGP / Kotlin / Compose 都在里面）
// 网络正常的环境可以把镜像删掉，只剩 google() + mavenCentral()。
pluginManagement {
    repositories {
        maven("https://maven.aliyun.com/repository/gradle-plugin")
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        maven("https://maven.aliyun.com/repository/google")
        maven("https://maven.aliyun.com/repository/public")
        google()
        mavenCentral()
    }
}

rootProject.name = "xhwarp-android"
include(":app")

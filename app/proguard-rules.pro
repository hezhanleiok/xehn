# gomobile 生成的类由 JNI 反向引用，名字不能被改。
-keep class com.xiaohe.engine.** { *; }
-keep interface com.xiaohe.engine.** { *; }
-keepclassmembers class com.xiaohe.engine.** { *; }

# Go 运行时通过 JNI 回调 LogSink 实现，保留其方法签名。
-keepclassmembers class * implements com.xiaohe.engine.LogSink {
    public void onLog(java.lang.String);
}

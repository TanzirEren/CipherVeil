# CipherVeil ProGuard rules
-keep class com.cipherveil.protector.NativeGuard { *; }
-keepclassmembers class * {
    native <methods>;
}
-dontwarn javax.annotation.**

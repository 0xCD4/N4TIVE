# Keep all JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep challenge classes
-keep class com.ctf.nativectf.challenges.** { *; }

# Keep Validator inner class (needed for ch03 TOCTOU)
-keep class com.ctf.nativectf.challenges.Ch03$Validator { *; }

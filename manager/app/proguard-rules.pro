# The protocol classes are reflected over by kotlinx.serialization.
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class me.usersu.manager.data.** {
    *** Companion;
}
-keepclasseswithmembers class me.usersu.manager.data.** {
    kotlinx.serialization.KSerializer serializer(...);
}

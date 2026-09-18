# Chaquopy accesses these public bridge methods reflectively from Python.
-keep class com.callicode.imaptools.engine.** { public *; }
-keep class com.callicode.imaptools.auth.SilentTokenProvider { public *; }

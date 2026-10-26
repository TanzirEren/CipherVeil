package com.cipherveil.protector;

/**
 * Bridge to the native (C++) hardening layer. Keeping these routines in
 * native code makes them far harder to patch/hook from Java-level tools
 * than an equivalent Java/Kotlin implementation.
 */
public class NativeGuard {

    static {
        System.loadLibrary("cipherveil");
    }

    /** Fast native FNV-1a fingerprint, used to tag/verify protected APKs. */
    public static native String fingerprint(byte[] chunk);

    /** Best-effort native anti-debugging probe (checks TracerPid on Linux/Android). */
    public static native boolean isDebuggerAttached();

    /** Lightweight native emulator heuristic (build fingerprint / hardware strings). */
    public static native boolean looksLikeEmulator(String fingerprint, String hardware);
}

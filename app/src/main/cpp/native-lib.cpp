#include <jni.h>
#include <string>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

// ---- FNV-1a 64-bit, used as a fast tamper-evident fingerprint for ----
// ---- streamed APK chunks (full file is hashed chunk-by-chunk on   ----
// ---- the Java side so a 1GB APK never has to sit fully in RAM).   ----
static uint64_t fnv1a64(const unsigned char *data, size_t len, uint64_t seed) {
    uint64_t hash = seed ? seed : 1469598103934665603ULL;
    const uint64_t prime = 1099511628211ULL;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= prime;
    }
    return hash;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_cipherveil_protector_NativeGuard_fingerprint(JNIEnv *env, jclass clazz, jbyteArray chunk) {
    jsize len = env->GetArrayLength(chunk);
    jbyte *bytes = env->GetByteArrayElements(chunk, nullptr);

    uint64_t hash = fnv1a64(reinterpret_cast<unsigned char *>(bytes), (size_t) len, 0);

    env->ReleaseByteArrayElements(chunk, bytes, JNI_ABORT);

    char buf[32];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long) hash);
    return env->NewStringUTF(buf);
}

// ---- Anti-debugging: a debugger attached via ptrace() shows a non-zero ----
// ---- TracerPid in /proc/self/status on Android/Linux.                  ----
extern "C" JNIEXPORT jboolean JNICALL
Java_com_cipherveil_protector_NativeGuard_isDebuggerAttached(JNIEnv *env, jclass clazz) {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return JNI_FALSE;

    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            std::istringstream iss(line.substr(10));
            int pid = 0;
            iss >> pid;
            return pid != 0 ? JNI_TRUE : JNI_FALSE;
        }
    }
    return JNI_FALSE;
}

// ---- Lightweight emulator heuristic based on common emulator build strings. ----
extern "C" JNIEXPORT jboolean JNICALL
Java_com_cipherveil_protector_NativeGuard_looksLikeEmulator(JNIEnv *env, jclass clazz,
                                                              jstring fingerprint, jstring hardware) {
    const char *fp = env->GetStringUTFChars(fingerprint, nullptr);
    const char *hw = env->GetStringUTFChars(hardware, nullptr);

    bool suspicious =
            (strstr(fp, "generic") != nullptr) ||
            (strstr(fp, "sdk_gphone") != nullptr) ||
            (strstr(hw, "goldfish") != nullptr) ||
            (strstr(hw, "ranchu") != nullptr);

    env->ReleaseStringUTFChars(fingerprint, fp);
    env->ReleaseStringUTFChars(hardware, hw);

    return suspicious ? JNI_TRUE : JNI_FALSE;
}

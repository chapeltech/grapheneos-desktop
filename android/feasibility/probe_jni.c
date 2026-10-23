#include <jni.h>
#include <HsFFI.h>
#include <pthread.h>
#include <stdint.h>

extern HsInt32 wonad_probe_stress(HsInt32 count);
extern HsInt32 wonad_probe_layout(HsInt32 width, HsInt32 height, HsPtr output);

static pthread_once_t runtime_once = PTHREAD_ONCE_INIT;

JNIEXPORT jstring JNICALL
Java_org_wonad_probe_NativeProbe_nativeAbi(JNIEnv *env, jclass cls) {
    (void)cls;
#if defined(__aarch64__)
    return (*env)->NewStringUTF(env, "arm64-v8a");
#elif defined(__x86_64__)
    return (*env)->NewStringUTF(env, "x86_64");
#else
#error "The Wonad runtime probe supports only Android ARM64 and x86-64"
#endif
}

static void initialize_runtime(void) {
    int argc = 1;
    char name[] = "wonad-native-probe";
    char *args[] = {name, NULL};
    char **argv = args;
    hs_init(&argc, &argv);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)vm;
    (void)reserved;
    pthread_once(&runtime_once, initialize_runtime);
    return JNI_VERSION_1_6;
}

/* The RTS lives for the process lifetime. Do not call hs_exit during Activity
 * recreation, and never retain JNI local references across native calls. */
JNIEXPORT jintArray JNICALL
Java_org_wonad_probe_NativeProbe_layout(JNIEnv *env, jclass cls, jint w, jint h) {
    (void)cls;
    HsInt32 boxes[8];
    if (wonad_probe_layout(w, h, boxes) != 8) {
        jclass exception = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
        if (exception != NULL) {
            (*env)->ThrowNew(env, exception, "Invalid desktop dimensions");
        }
        return NULL;
    }
    jint result_boxes[8];
    for (int i = 0; i < 8; ++i) result_boxes[i] = boxes[i];
    jintArray result = (*env)->NewIntArray(env, 8);
    if (result != NULL) (*env)->SetIntArrayRegion(env, result, 0, 8, result_boxes);
    return result;
}

JNIEXPORT jint JNICALL
Java_org_wonad_probe_NativeProbe_stress(JNIEnv *env, jclass cls, jint count) {
    (void)env;
    (void)cls;
    return wonad_probe_stress(count);
}

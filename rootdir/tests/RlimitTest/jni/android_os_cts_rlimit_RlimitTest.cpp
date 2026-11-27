/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <jni.h>
#include <sys/resource.h>

extern "C" JNIEXPORT jlongArray JNICALL
Java_android_os_cts_rlimit_RlimitTest_getNofileLimit(JNIEnv* env, jobject /* thiz */) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
        return nullptr;
    }
    jlongArray result = env->NewLongArray(2);
    if (result == nullptr) {
        return nullptr;
    }
    jlong limits[2];
    limits[0] = (jlong)rl.rlim_cur;
    limits[1] = (jlong)rl.rlim_max;
    env->SetLongArrayRegion(result, 0, 2, limits);
    return result;
}

extern "C" JNIEXPORT jint JNICALL Java_android_os_cts_rlimit_RlimitTest_setNofileLimit(
        JNIEnv* /* env */, jobject /* thiz */, jlong softLimit) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == -1) {
        return errno;
    }
    rl.rlim_cur = (rlim_t)softLimit;
    if (setrlimit(RLIMIT_NOFILE, &rl) == -1) {
        return errno;
    }
    return 0;
}

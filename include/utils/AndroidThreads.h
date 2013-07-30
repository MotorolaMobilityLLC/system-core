/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _LIBS_UTILS_ANDROID_THREADS_H
#define _LIBS_UTILS_ANDROID_THREADS_H

#include <stdint.h>
#include <sys/types.h>

#if defined(HAVE_PTHREADS)
# include <pthread.h>
#endif

#include <utils/ThreadDefs.h>

// ---------------------------------------------------------------------------
// C API

#ifdef __cplusplus
extern "C" {
#endif

// Create and run a new thread.
extern int androidCreateThread(android_thread_func_t, void *);

// Create thread with lots of parameters
extern int androidCreateThreadEtc(android_thread_func_t entryFunction,
                                  void *userData,
                                  const char* threadName,
                                  int32_t threadPriority,
                                  size_t threadStackSize,
                                  android_thread_id_t *threadId);

// Get some sort of unique identifier for the current thread.
extern android_thread_id_t androidGetThreadId();

// Low-level thread creation -- never creates threads that can
// interact with the Java VM.
extern int androidCreateRawThreadEtc(android_thread_func_t entryFunction,
                                     void *userData,
                                     const char* threadName,
                                     int32_t threadPriority,
                                     size_t threadStackSize,
                                     android_thread_id_t *threadId);

// Used by the Java Runtime to control how threads are created, so that
// they can be proper and lovely Java threads.
typedef int (*android_create_thread_fn)(android_thread_func_t entryFunction,
                                        void *userData,
                                        const char* threadName,
                                        int32_t threadPriority,
                                        size_t threadStackSize,
                                        android_thread_id_t *threadId);

extern void androidSetCreateThreadFunc(android_create_thread_fn func);

// ------------------------------------------------------------------
// Extra functions working with raw pids.

// Get pid for the current thread.
extern pid_t androidGetTid();

#ifdef HAVE_ANDROID_OS
// Change the scheduling group of a particular thread.  The group
// should be one of the ANDROID_TGROUP constants.  Returns BAD_VALUE if
// grp is out of range, else another non-zero value with errno set if
// the operation failed.  Thread ID zero means current thread.
extern int androidSetThreadSchedulingGroup(pid_t tid, int grp);

// Change the priority AND scheduling group of a particular thread.  The priority
// should be one of the ANDROID_PRIORITY constants.  Returns INVALID_OPERATION
// if the priority set failed, else another value if just the group set failed;
// in either case errno is set.  Thread ID zero means current thread.
extern int androidSetThreadPriority(pid_t tid, int prio);

// Get the current priority of a particular thread. Returns one of the
// ANDROID_PRIORITY constants or a negative result in case of error.
extern int androidGetThreadPriority(pid_t tid);

// Get the current scheduling group of a particular thread. Normally returns
// one of the ANDROID_TGROUP constants other than ANDROID_TGROUP_DEFAULT.
// Returns ANDROID_TGROUP_DEFAULT if no pthread support (e.g. on host) or if
// scheduling groups are disabled.  Returns INVALID_OPERATION if unexpected error.
// Thread ID zero means current thread.
extern int androidGetThreadSchedulingGroup(pid_t tid);
#endif

#ifdef __cplusplus
} // extern "C"
#endif

// ----------------------------------------------------------------------------
// C++ API
#ifdef __cplusplus
namespace android {
// ----------------------------------------------------------------------------

// Create and run a new thread.
inline bool createThread(thread_func_t f, void *a) {
    return androidCreateThread(f, a) ? true : false;
}

// Create thread with lots of parameters
inline bool createThreadEtc(thread_func_t entryFunction,
                            void *userData,
                            const char* threadName = "android:unnamed_thread",
                            int32_t threadPriority = PRIORITY_DEFAULT,
                            size_t threadStackSize = 0,
                            thread_id_t *threadId = 0)
{
    return androidCreateThreadEtc(entryFunction, userData, threadName,
        threadPriority, threadStackSize, threadId) ? true : false;
}

// Get some sort of unique identifier for the current thread.
inline thread_id_t getThreadId() {
    return androidGetThreadId();
}

// ----------------------------------------------------------------------------
}; // namespace android
#endif  // __cplusplus
// ----------------------------------------------------------------------------

#endif // _LIBS_UTILS_ANDROID_THREADS_H

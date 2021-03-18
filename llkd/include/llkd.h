/*
 * Copyright (C) 2018 The Android Open Source Project
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

#ifndef _LLKD_H_
#define _LLKD_H_

#ifndef LOG_TAG
#define LOG_TAG "livelock"
#endif

#include <stdbool.h>
#include <sys/cdefs.h>

__BEGIN_DECLS

bool llkInit(const char* threadname); /* threadname NULL, not spawned */
unsigned llkCheckMilliseconds(void);

/* clang-format off */
#define LLK_ENABLE_WRITEABLE_PROPERTY   "llk.enable"
#define LLK_ENABLE_PROPERTY             "ro." LLK_ENABLE_WRITEABLE_PROPERTY
#define LLK_ENABLE_DEFAULT              false /* "eng" and userdebug true */
#define KHT_ENABLE_WRITEABLE_PROPERTY   "khungtask.enable"
#define KHT_ENABLE_PROPERTY             "ro." KHT_ENABLE_WRITEABLE_PROPERTY
#define LLK_ENABLE_SYSRQ_T_PROPERTY     "ro.llk.sysrq_t"
#define LLK_ENABLE_SYSRQ_T_DEFAULT      true
#define LLK_MLOCKALL_PROPERTY           "ro.llk.mlockall"
#define LLK_MLOCKALL_DEFAULT            true
#define LLK_KILLTEST_PROPERTY           "ro.llk.killtest"
#define LLK_KILLTEST_DEFAULT            true
#define LLK_TIMEOUT_MS_PROPERTY         "ro.llk.timeout_ms"
#define KHT_TIMEOUT_PROPERTY            "ro.khungtask.timeout"
#define LLK_D_TIMEOUT_MS_PROPERTY       "ro.llk.D.timeout_ms"
#define LLK_Z_TIMEOUT_MS_PROPERTY       "ro.llk.Z.timeout_ms"
#define LLK_STACK_TIMEOUT_MS_PROPERTY   "ro.llk.stack.timeout_ms"
#define LLK_CHECK_MS_PROPERTY           "ro.llk.check_ms"
/* LLK_CHECK_MS_DEFAULT = actual timeout_ms / LLK_CHECKS_PER_TIMEOUT_DEFAULT */
#define LLK_CHECKS_PER_TIMEOUT_DEFAULT  5
#define LLK_CHECK_STACK_PROPERTY        "ro.llk.stack"
#define LLK_CHECK_STACK_DEFAULT         \
    "cma_alloc,__get_user_pages,bit_wait_io,wait_on_page_bit_killable"
#define LLK_IGNORELIST_PROCESS_PROPERTY "ro.llk.ignorelist.process"
#define LLK_IGNORELIST_PROCESS_DEFAULT  \
    "0,1,2,init,[kthreadd],[khungtaskd],lmkd,llkd,watchdogd,[watchdogd],[watchdogd/0]"
#define LLK_IGNORELIST_PARENT_PROPERTY  "ro.llk.ignorelist.parent"
#define LLK_IGNORELIST_PARENT_DEFAULT   "0,2,[kthreadd],adbd&[setsid]"
#define LLK_IGNORELIST_UID_PROPERTY     "ro.llk.ignorelist.uid"
#define LLK_IGNORELIST_UID_DEFAULT      ""
#define LLK_IGNORELIST_STACK_PROPERTY   "ro.llk.ignorelist.process.stack"
#define LLK_IGNORELIST_STACK_DEFAULT    "init,lmkd.llkd,llkd,keystore,ueventd,apexd"
/* clang-format on */

__END_DECLS

#ifdef __cplusplus
extern "C++" { /* In case this included wrapped with __BEGIN_DECLS */

#include <chrono>

__BEGIN_DECLS
/* C++ code allowed to not specify threadname argument for this C linkage */
bool llkInit(const char* threadname = nullptr);
__END_DECLS
std::chrono::milliseconds llkCheck(bool checkRunning = false);

/* clang-format off */
#define LLK_TIMEOUT_MS_DEFAULT  std::chrono::duration_cast<milliseconds>(std::chrono::minutes(10))
#define LLK_TIMEOUT_MS_MINIMUM  std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(10))
#define LLK_CHECK_MS_MINIMUM    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(1))
/* clang-format on */

} /* extern "C++" */
#endif /* __cplusplus */

#endif /* _LLKD_H_ */

/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include "coldboot.h"
#include "coldboot_runner.h"
#include "com_android_ueventd_flags.h"
#include "util.h"

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <selinux/android.h>
#include <selinux/selinux.h>
#include <sys/stat.h>

namespace flags = com::android::ueventd::flags;

namespace android {
namespace init {

void RestoreconRecurse(const std::string& dir) {
    android::base::Timer t;
    selinux_android_restorecon(dir.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE);

    // Mark a dir restorecon operation for 50ms,
    // Maybe you can add this dir to the ueventd.rc script to parallel processing
    if (t.duration() > 50ms) {
        LOG(INFO) << "took " << t.duration().count() << "ms restorecon '" << dir.c_str() << "'";
    }
}

void ColdBoot::RegenerateUevents() {
    uevent_listener_.RegenerateUevents([this](const Uevent& uevent) {
        uevent_queue_.emplace_back(uevent);
        return ListenerAction::kContinue;
    });
}

void ColdBoot::GenerateRestoreCon(const std::string& directory) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(directory.c_str()), &closedir);

    if (!dir) {
        PLOG(WARNING) << "opendir " << directory.c_str();
        return;
    }

    struct dirent* dent;
    while ((dent = readdir(dir.get())) != NULL) {
        if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0) continue;

        struct stat st;
        if (fstatat(dirfd(dir.get()), dent->d_name, &st, 0) == -1) continue;

        if (S_ISDIR(st.st_mode)) {
            std::string fullpath = directory + "/" + dent->d_name;
            auto parallel_restorecon = std::find(parallel_restorecon_queue_.begin(),
                                                 parallel_restorecon_queue_.end(), fullpath);
            if (parallel_restorecon == parallel_restorecon_queue_.end()) {
                restorecon_queue_.push_back(fullpath);
            }
        }
    }
}

void ColdBoot::Run() {
    android::base::Timer cold_boot_timer;

    RegenerateUevents();

    if (enable_parallel_restorecon_) {
        if (parallel_restorecon_queue_.empty()) {
            parallel_restorecon_queue_.emplace_back("/sys");
            // takes long time for /sys/devices, parallelize it
            parallel_restorecon_queue_.emplace_back("/sys/devices");
            LOG(INFO) << "Parallel processing directory is not set, set the default";
        }
        for (const auto& dir : parallel_restorecon_queue_) {
            selinux_android_restorecon(dir.c_str(), 0);
            GenerateRestoreCon(dir);
        }
    }

    std::unique_ptr<ColdbootRunner> runner;

    unsigned int parallelism = std::thread::hardware_concurrency() ?: 4;
    if constexpr (flags::enable_threadpool_coldboot()) {
        runner = std::make_unique<ColdbootRunnerThreadPool>(
                parallelism, uevent_queue_, uevent_handlers_, enable_parallel_restorecon_,
                restorecon_queue_);
    } else {
        runner = std::make_unique<ColdbootRunnerSubprocess>(
                parallelism, uevent_queue_, uevent_handlers_, enable_parallel_restorecon_,
                restorecon_queue_);
    }

    runner->StartInBackground();

    if (!enable_parallel_restorecon_) {
        selinux_android_restorecon("/sys", SELINUX_ANDROID_RESTORECON_RECURSE);
    }

    runner->Wait();

    android::base::SetProperty(kColdBootDoneProp, "true");

    // When we handle the uevents in the thread pool, the unused memory is not immediately unmapped
    // and brought back to the kernel, even after joining the threads, as opposed to handling
    // uevents in subprocesses where the memory is cleaned up upon process termination. Therefore,
    // we explicitly purge all the unused memory here when the coldboot is done in the thread pool.
    if constexpr (flags::enable_threadpool_coldboot()) {
        mallopt(M_PURGE_ALL, 0);
    }
    LOG(INFO) << "Coldboot took " << cold_boot_timer.duration().count() / 1000.0f << " seconds";
}

}  // namespace init
}  // namespace android

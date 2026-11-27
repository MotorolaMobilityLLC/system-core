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

#include <sys/stat.h>
#include <sys/syscall.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <modprobe/modprobe.h>
#include <modprobe/utils.h>

using android::modprobe::CanonicalizeModulePath;
using android::modprobe::InitModule;

bool Modprobe::Insmod(const std::string& path_name, const std::string& parameters) {
    auto canonical_name = CanonicalizeModulePath(path_name);
    android::base::Result<void> res = InitModule(path_name, module_options_, parameters);

    std::lock_guard guard(module_loaded_lock_);

    if (res.ok()) {
        module_count_++;
        module_loaded_paths_.emplace(path_name);
        module_loaded_.emplace(canonical_name);
        return true;
    }
    if (res.error().code() == EEXIST) {
        module_loaded_paths_.emplace(path_name);
        module_loaded_.emplace(canonical_name);
        return true;
    }
    return false;
}

bool Modprobe::Rmmod(const std::string& module_name) {
    auto canonical_name = CanonicalizeModulePath(module_name);
    int ret = syscall(__NR_delete_module, canonical_name.c_str(), O_NONBLOCK);
    if (ret != 0) {
        PLOG(ERROR) << "Failed to remove module '" << module_name << "'";
        return false;
    }
    std::lock_guard guard(module_loaded_lock_);
    module_loaded_.erase(canonical_name);
    return true;
}

bool Modprobe::ModuleExists(const std::string& module_name) {
    struct stat fileStat {};
    if (blocklist_enabled && module_blocklist_.count(module_name)) {
        LOG(INFO) << "module " << module_name << " is blocklisted";
        return false;
    }
    auto deps = GetDependencies(module_name);
    if (deps.empty()) {
        // missing deps can happen in the case of an alias
        return false;
    }
    if (stat(deps.front().c_str(), &fileStat)) {
        PLOG(INFO) << "module " << module_name << " can't be loaded; can't access " << deps.front();
        return false;
    }
    if (!S_ISREG(fileStat.st_mode)) {
        LOG(INFO) << "module " << module_name << " is not a regular file";
        return false;
    }
    return true;
}

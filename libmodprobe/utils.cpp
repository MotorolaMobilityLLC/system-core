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

#include <modprobe/utils.h>

#include <sys/syscall.h>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

namespace android {
namespace modprobe {

std::string CanonicalizeModulePath(const std::string& module_path) {
    auto start = module_path.find_last_of('/');
    if (start == std::string::npos) {
        start = 0;
    } else {
        start += 1;
    }
    auto end = module_path.size();
    if (android::base::EndsWith(module_path, ".ko")) {
        end -= 3;
    }
    if ((end - start) <= 1) {
        LOG(ERROR) << "malformed module name: " << module_path;
        return "";
    }
    std::string module_name = module_path.substr(start, end - start);
    // module names can have '-', but their file names will have '_'
    std::replace(module_name.begin(), module_name.end(), '-', '_');
    return module_name;
}

base::Result<void> InitModule(const std::string& path_name,
                              const std::unordered_map<std::string, std::string>& module_options,
                              const std::string& parameters) {
    std::string options = "";
    auto options_iter = module_options.find(CanonicalizeModulePath(path_name));
    if (options_iter != module_options.end()) {
        options = options_iter->second;
    }
    if (!parameters.empty()) {
        options += " " + parameters;
    }

    LOG(INFO) << "Loading module " << path_name << " with args '" << options << "'";
    android::base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(path_name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        PLOG(ERROR) << "Could not open module '" << path_name << "'";
        return android::base::ErrnoError();
    }
    int ret = syscall(__NR_finit_module, fd.get(), options.c_str(), 0);
    if (ret != 0) {
        if (errno != EEXIST) {
            PLOG(ERROR) << "Failed to insmod '" << path_name << "' with args '" << options << "'";
        }
        return android::base::ErrnoError();
    }
    LOG(INFO) << "Loaded kernel module " << path_name;
    return {};
}

}  // namespace modprobe
}  // namespace android

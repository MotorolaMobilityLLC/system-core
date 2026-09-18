/*
 *  Copyright 2025 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <sys/types.h>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <processgroup/processgroup.h>
#include <processgroup_rust_bridge/processgroup_rust_bridge.h>

#include "rust/cxx.h"

bool CgroupGetAttributePathForProcessRustBridge(rust::Str attr_name, uint32_t uid, int32_t pid,
                                                rust::String& path) {
    std::string cpp_path;
    bool ret = CgroupGetAttributePathForProcess(static_cast<std::string_view>(attr_name), uid, pid,
                                                cpp_path);

    // Copy the output into the Rust string.
    path = cpp_path.c_str();

    return ret;
}

bool SetProcessProfilesRustBridge(uint32_t uid, int32_t pid,
                                  rust::Slice<const rust::Str> profiles) {
    std::vector<std::string_view> cpp_profiles;

    for (const auto& str : profiles) {
        cpp_profiles.push_back(static_cast<std::string_view>(str));
    }

    return SetProcessProfiles(uid, pid, std::span{cpp_profiles});
}

bool SetTaskProfilesRustBridge(int32_t tid, rust::Slice<const rust::Str> profiles,
                               bool use_fd_cache) {
    std::vector<std::string> cpp_profiles;

    for (const auto& str : profiles) {
        cpp_profiles.push_back(static_cast<std::string>(str));
    }

    return SetTaskProfiles(tid, cpp_profiles, use_fd_cache);
}
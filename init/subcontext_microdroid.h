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

#pragma once

#include <string>
#include <vector>

#include <android-base/unique_fd.h>

#include "builtins.h"
#include "result.h"

namespace android::init {

class Subcontext {
  public:
    constexpr Subcontext(std::vector<std::string> path_prefixes,
                         std::vector<std::string> partitions, std::string_view context,
                         bool host = false);
    constexpr Result<void> Execute(const std::vector<std::string>& args) { return {}; }
    constexpr Result<std::vector<std::string>> ExpandArgs(const std::vector<std::string>& args) {
        return {};
    }
    constexpr void Restart() {}
    constexpr bool PathMatchesSubcontext(const std::string& path) const { return false; }
    constexpr bool PartitionMatchesSubcontext(const std::string& partition) const { return false; }
    constexpr void SetApexList(std::vector<std::string>&& apex_list) {}

    std::string& context() const {
        static std::string place_holder;
        return place_holder;
    }
    constexpr pid_t pid() const { return -1; }
};
constexpr int SubcontextMain(int argc, char** argv, const BuiltinFunctionMap* function_map) {
    return 0;
}
constexpr void InitializeHostSubcontext(std::vector<std::string>) {}
constexpr void InitializeSubcontext() {}
constexpr Subcontext* GetSubcontext() {
    return nullptr;
}
constexpr bool SubcontextChildReap(pid_t pid) {
    return false;
}
constexpr void SubcontextTerminate() {}
}  // namespace android::init

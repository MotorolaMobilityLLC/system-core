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

#pragma once

#include <modprobe/modprobe.h>
#include <modprobe/module_config.h>
#include <modprobe/module_dependency_graph.h>

#include <memory>
#include <unordered_map>

#include "thread_pool.h"
#include "uevent.h"
#include "uevent_handler.h"

namespace android {
namespace init {

class ModaliasHandler : public UeventHandler {
  public:
    ModaliasHandler(const std::vector<std::string>&);
    virtual ~ModaliasHandler() = default;

    void HandleUevent(const Uevent& uevent) override;

    // Add a uevent to the dependency graph and Enqueue dependency-free modules to the thread pool.
    void EnqueueUevent(const Uevent& uevent, ThreadPool& thread_pool) override;

  private:
    ModaliasHandler(ModuleConfig config);

    void EnqueueModule(ThreadPool& thread_pool, const std::string& module);

    std::unordered_map<std::string, std::string> module_options_;
    modprobe::ModuleDependencyGraph dependency_graph_;
    Modprobe modprobe_;
};

}  // namespace init
}  // namespace android

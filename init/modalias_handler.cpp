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

#include "modalias_handler.h"

#include <string>
#include <vector>

#include <modprobe/modprobe.h>
#include <modprobe/module_dependency_graph.h>
#include <modprobe/utils.h>

namespace android {
namespace init {

ModaliasHandler::ModaliasHandler(const std::vector<std::string>& base_paths)
    : ModaliasHandler(ModuleConfig::Parse(base_paths)) {}

ModaliasHandler::ModaliasHandler(ModuleConfig config)
    : module_options_(config.module_options),
      dependency_graph_(config),
      modprobe_(std::move(config)) {}

void ModaliasHandler::HandleUevent(const Uevent& uevent) {
    if (uevent.modalias.empty()) return;
    modprobe_.LoadWithAliases(uevent.modalias, true);
}

void ModaliasHandler::EnqueueUevent(const Uevent& uevent, ThreadPool& thread_pool) {
    if (uevent.modalias.empty()) return;
    dependency_graph_.AddModule(uevent.modalias);
    const auto& ready_modules = dependency_graph_.PopReadyModules();
    for (const std::string& module : ready_modules) {
        EnqueueModule(thread_pool, module);
    }
}

void ModaliasHandler::EnqueueModule(ThreadPool& thread_pool, const std::string& module) {
    thread_pool.Enqueue(kPriorityModalias, [this, &thread_pool, module]() {
        android::base::Result<void> res = modprobe::InitModule(module, module_options_);
        if (res.ok() || res.error().code() == EEXIST) {
            dependency_graph_.MarkModuleLoaded(module);
        } else {
            dependency_graph_.MarkModuleLoadFailed(module);
        }
        const auto& ready_modules = dependency_graph_.PopReadyModules();
        for (const std::string& ready_module : ready_modules) {
            EnqueueModule(thread_pool, ready_module);
        }
    });
}

}  // namespace init
}  // namespace android

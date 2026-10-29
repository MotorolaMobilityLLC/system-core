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

#pragma once

#include <modprobe/module_config.h>

#include <memory>
#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android-base/thread_annotations.h>

namespace android {
namespace modprobe {

// The status of a module in the dependency graph.
// If the module is blocklisted, the status is set to Blocklisted and does not change.
// If not, the status will change from NotRequested, to Pending, to Loaded or LoadFailed.
// LoadFailed can then be updated to
// - Pending when the module is requested to retry.
// - Loaded when a retry has succeeded.
enum class ModuleStatus {
    // The module is not requested to be loaded.
    NotRequested,
    // The module is requested to be loaded but not loaded.
    Pending,
    // The module has been loaded.
    Loaded,
    // The module has failed to load.
    LoadFailed,
    // The module is blocklisted.
    Blocklisted,
};

struct Module {
    std::string name;
    std::string path;

    // We use ModuleSet to describe the directed edge in the dependency graph.  We use WeakModuleSet
    // to describe the reverse directed edge. There is no memory leak here since the graph is a DAG
    // as we CHECK there is no loop.
    using WeakModuleSet = std::set<std::weak_ptr<Module>, std::owner_less<std::weak_ptr<Module>>>;
    using ModuleSet = std::set<std::shared_ptr<Module>>;

    // Set of dependencies of this module. A dependency is unmet if:
    // - it's a hard-dep and state != Loaded.
    // - it's a soft-dep and state != Loaded && state != LoadFailed. Note that failed loads are
    //   treated as "met" since soft-deps are optional.
    ModuleSet unmet_dependencies;
    // Reverse map of `unmet_dependencies`.
    WeakModuleSet rev_unmet_dependencies;
    // "soft dependencies" (softdep) are a way to specify preferred loading order or dependencies
    // that are needed for optimal functionality or to avoid issues.
    // There are two types of soft dependencies: pre-softdep and post-softdep.
    // - pre-softdep: If module A is a pre-softdep of module B, then A should be loaded before B is
    //               loaded. It is simply an implied edge in the dependency graph.
    // - post-softdep: If module A is a post-softdep of module B, then A should be loaded after B is
    //                 loaded. It is not only an edge but also implies that the loading of module A
    //                 should be initiated upon the loading of module B.
    ModuleSet pre_softdeps;
    WeakModuleSet post_softdeps;

    ModuleStatus status{ModuleStatus::NotRequested};

    bool IsReady() const;

    void MarkBlocklisted();
};

/**
 * Manages dependencies between kernel modules to facilitate parallel loading.
 *
 * This class builds a dependency graph based on ModuleConfig. It allows requesting a set of modules
 * to be loaded and then retrieving batches of modules that are ready for loading, respecting their
 * dependencies. Once a module is processed (loaded or failed), it should be marked as such to
 * unblock any modules that depend on it.
 *
 * This class is thread-safe.
 */
class ModuleDependencyGraph {
  public:
    ModuleDependencyGraph(const ModuleConfig& module_config);

    // Request a module to be loaded with its dependencies.
    void AddModule(const std::string& module_name);
    // Marks a module as loaded. This is supposed to be called after a successful init_module(2)
    void MarkModuleLoaded(const std::string& module_path);
    // Marks a module loading as failed. This is supposed to be called after a failed init_module(2)
    void MarkModuleLoadFailed(const std::string& module_path);
    // Returns module paths that are ready to be loaded. Internally, it returns ready_module_paths_
    // and clears it.
    std::unordered_set<std::string> PopReadyModules();

  private:
    std::vector<std::string> GetModuleNames(const std::string& module_name);
    std::vector<std::shared_ptr<Module>> GetModules(const std::string& module_name)
            EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);
    void AddModuleLocked(std::shared_ptr<Module>& module) EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);
    void MarkModuleLoadResult(const std::string& module_path, bool failed);

    void AddUnmetDependency(std::shared_ptr<Module> module, std::shared_ptr<Module> dep_module);
    void RemoveUnmetDependency(std::shared_ptr<Module> module, std::shared_ptr<Module> dep_module)
            EXCLUSIVE_LOCKS_REQUIRED(graph_lock_);

    const std::unordered_map<std::string, std::string> path_to_name_;
    const std::vector<std::pair<std::string, std::string>> module_aliases_;

    // A set of modules that are requested to be loaded.
    std::unordered_map<std::string, std::shared_ptr<Module>> modules_ GUARDED_BY(graph_lock_);
    // Modules that are ready to be loaded.
    std::unordered_set<std::string> ready_module_paths_ GUARDED_BY(graph_lock_);

    std::mutex graph_lock_;
};

}  // namespace modprobe
}  // namespace android

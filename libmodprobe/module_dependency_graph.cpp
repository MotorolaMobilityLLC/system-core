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

#include <modprobe/module_dependency_graph.h>
#include <modprobe/utils.h>

#include <fnmatch.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

namespace android {
namespace modprobe {

bool Module::IsReady() const {
    return unmet_dependencies.empty() && status == ModuleStatus::Pending;
}

void Module::MarkBlocklisted() {
    status = ModuleStatus::Blocklisted;
    for (const std::weak_ptr<Module>& rev_dep_weak : rev_unmet_dependencies) {
        if (std::shared_ptr<Module> rev_dep = rev_dep_weak.lock()) {
            rev_dep->MarkBlocklisted();
        }
    }
}

static std::unordered_map<std::string, std::string> BuildPathToName(
        const std::unordered_map<std::string, std::vector<std::string>>& parsed_deps) {
    std::unordered_map<std::string, std::string> path_to_name;
    for (const auto& [mod, deps] : parsed_deps) {
        CHECK(!deps.empty())
                << "The first element of a dependency list should be the module itself";
        path_to_name.emplace(deps[0], mod);
    }
    return path_to_name;
}

std::vector<std::string> ModuleDependencyGraph::GetModuleNames(const std::string& module_name) {
    std::vector<std::string> module_names = {CanonicalizeModulePath(module_name)};
    for (const auto& [alias, aliased_name] : module_aliases_) {
        if (fnmatch(alias.c_str(), module_name.c_str(), 0) == 0) {
            module_names.push_back(CanonicalizeModulePath(aliased_name));
        }
    }
    return module_names;
}

std::vector<std::shared_ptr<Module>> ModuleDependencyGraph::GetModules(
        const std::string& module_name) {
    const auto& module_names = GetModuleNames(module_name);
    std::vector<std::shared_ptr<Module>> modules;
    for (const auto& name : module_names) {
        if (modules_.contains(name)) {
            modules.push_back(modules_.at(name));
        }
    }
    if (modules.empty()) {
        LOG(ERROR) << "LMP: DependencyGraph: Unable to find a module for " << module_name
                   << " in the .dep file, tried: " << base::Join(module_names, ",");
    }
    return modules;
}

static bool HasLoop(const std::shared_ptr<Module>& mod,
                    std::unordered_set<std::shared_ptr<Module>>& visited,
                    std::unordered_set<std::shared_ptr<Module>>& recursion_stack) {
    visited.insert(mod);
    recursion_stack.insert(mod);

    for (const std::shared_ptr<Module>& dep : mod->unmet_dependencies) {
        if (recursion_stack.count(dep)) {
            return true;
        }
        if (!visited.count(dep)) {
            if (HasLoop(dep, visited, recursion_stack)) {
                return true;
            }
        }
    }

    recursion_stack.erase(mod);
    return false;
}

static bool HasLoop(const std::unordered_map<std::string, std::shared_ptr<Module>>& modules) {
    std::unordered_set<std::shared_ptr<Module>> visited;
    std::unordered_set<std::shared_ptr<Module>> recursion_stack;

    for (const auto& [_, mod] : modules) {
        if (!visited.count(mod)) {
            if (HasLoop(mod, visited, recursion_stack)) {
                return true;
            }
        }
    }

    return false;
}

ModuleDependencyGraph::ModuleDependencyGraph(const ModuleConfig& config)
    : path_to_name_(BuildPathToName(config.module_deps)), module_aliases_(config.module_aliases) {
    for (const auto& [path, name] : path_to_name_) {
        std::shared_ptr<Module> mod = std::make_shared<Module>();
        mod->name = name;
        mod->path = path;
        modules_.emplace(name, mod);
    }

    for (const auto& [_, deps] : config.module_deps) {
        CHECK(!deps.empty())
                << "The first element of a dependency list should be the module itself";
        const std::string& mod_name = path_to_name_.at(deps[0]);
        std::shared_ptr<Module> mod = modules_.at(mod_name);
        for (size_t i = 1; i < deps.size(); i++) {
            if (path_to_name_.contains(deps[i])) {
                const std::string& dep_name = path_to_name_.at(deps[i]);
                std::shared_ptr<Module> dep_module = modules_.at(dep_name);
                AddUnmetDependency(mod, dep_module);
            }
        }
    }

    for (const auto& [mod_name, softdep] : config.module_pre_softdep) {
        for (std::shared_ptr<Module> pre_softdep : GetModules(softdep)) {
            std::shared_ptr<Module> mod = modules_.at(mod_name);
            mod->pre_softdeps.insert(pre_softdep);
            AddUnmetDependency(mod, pre_softdep);
        }
    }

    for (const auto& [mod_name, softdep] : config.module_post_softdep) {
        for (std::shared_ptr<Module> post_softdep : GetModules(softdep)) {
            std::shared_ptr<Module> mod = modules_.at(mod_name);
            mod->post_softdeps.insert(post_softdep);
            AddUnmetDependency(post_softdep, mod);
        }
    }

    for (const std::string& name : config.module_blocklist) {
        for (std::shared_ptr<Module> mod : GetModules(name)) {
            mod->MarkBlocklisted();
        }
    }

    if (HasLoop(modules_)) {
        LOG(ERROR) << "Dependency graph has a loop";
    }
}

void ModuleDependencyGraph::AddUnmetDependency(std::shared_ptr<Module> mod,
                                               std::shared_ptr<Module> dep_mod) {
    mod->unmet_dependencies.insert(dep_mod);
    dep_mod->rev_unmet_dependencies.insert(mod);
}

void ModuleDependencyGraph::RemoveUnmetDependency(std::shared_ptr<Module> mod,
                                                  std::shared_ptr<Module> dep_mod) {
    mod->unmet_dependencies.erase(dep_mod);
    dep_mod->rev_unmet_dependencies.erase(mod);
    if (mod->IsReady()) {
        ready_module_paths_.insert(mod->path);
    }
}

void ModuleDependencyGraph::AddModule(const std::string& module_name) {
    std::lock_guard<std::mutex> lock(graph_lock_);

    for (std::shared_ptr<Module> mod : GetModules(module_name)) {
        AddModuleLocked(mod);
    }
}

void ModuleDependencyGraph::AddModuleLocked(std::shared_ptr<Module>& mod) {
    for (std::weak_ptr<Module> softdep_weak : mod->post_softdeps) {
        if (std::shared_ptr<Module> softdep = softdep_weak.lock()) {
            AddModuleLocked(softdep);
        }
    }

    switch (mod->status) {
        case ModuleStatus::LoadFailed:
            LOG(VERBOSE) << "LMP: DependencyGraph: Retrying previously failed module " << mod->name;
            FALLTHROUGH_INTENDED;
        case ModuleStatus::NotRequested:
            mod->status = ModuleStatus::Pending;
            if (mod->IsReady()) {
                ready_module_paths_.insert(mod->path);
            }
            for (std::shared_ptr<Module> dep : mod->unmet_dependencies) {
                AddModuleLocked(dep);
            }
            break;
        case ModuleStatus::Blocklisted:
            LOG(VERBOSE) << "LMP: DependencyGraph: Skipping blocklisted module " << mod->name;
            break;
        case ModuleStatus::Loaded:
            LOG(VERBOSE) << "LMP: DependencyGraph: Module " << mod->name << " already loaded";
            break;
        case ModuleStatus::Pending:
            break;
    }
}

void ModuleDependencyGraph::MarkModuleLoaded(const std::string& module_path) {
    MarkModuleLoadResult(module_path, false);
}

void ModuleDependencyGraph::MarkModuleLoadFailed(const std::string& module_path) {
    MarkModuleLoadResult(module_path, true);
}

void ModuleDependencyGraph::MarkModuleLoadResult(const std::string& module_path, bool failed) {
    std::lock_guard<std::mutex> lock(graph_lock_);

    const std::string& mod_name = path_to_name_.at(module_path);
    std::shared_ptr<Module> mod = modules_.at(mod_name);

    CHECK(mod->status == ModuleStatus::Pending || mod->status == ModuleStatus::LoadFailed);

    mod->status = failed ? ModuleStatus::LoadFailed : ModuleStatus::Loaded;

    Module::WeakModuleSet rev_deps = mod->rev_unmet_dependencies;
    for (const std::weak_ptr<Module>& rev_dep_weak : rev_deps) {
        if (std::shared_ptr<Module> rev_dep = rev_dep_weak.lock()) {
            // A hard-dep is satisfied only if the module is successfully loaded, but a soft-dep is
            // satisfied regardless of the loading being successful or failed.
            if (!failed || rev_dep->pre_softdeps.contains(mod)) {
                RemoveUnmetDependency(rev_dep, mod);
            }
        }
    }
}

std::unordered_set<std::string> ModuleDependencyGraph::PopReadyModules() {
    std::lock_guard<std::mutex> lock(graph_lock_);
    std::unordered_set<std::string> ready;
    ready.swap(ready_module_paths_);
    return ready;
}

}  // namespace modprobe
}  // namespace android

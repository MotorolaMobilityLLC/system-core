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

#include <modprobe/modprobe.h>
#include <modprobe/utils.h>

#include <fnmatch.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <algorithm>
#include <ctime>
#include <condition_variable>
#include <map>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

using android::modprobe::CanonicalizeModulePath;

Modprobe::Modprobe(const std::vector<std::string>& base_paths, const std::string load_file,
                   bool use_blocklist)
    : Modprobe(ModuleConfig::Parse(base_paths, load_file), use_blocklist) {}

Modprobe::Modprobe(ModuleConfig config, bool use_blocklist)
    : module_aliases_(std::move(config.module_aliases)),
      module_deps_(std::move(config.module_deps)),
      module_pre_softdep_(std::move(config.module_pre_softdep)),
      module_post_softdep_(std::move(config.module_post_softdep)),
      module_load_(std::move(config.module_load)),
      module_options_(std::move(config.module_options)),
      module_blocklist_(std::move(config.module_blocklist)),
      blocklist_enabled(use_blocklist) {}

std::vector<std::string> Modprobe::GetDependencies(const std::string& module) {
    auto it = module_deps_.find(module);
    if (it == module_deps_.end()) {
        return {};
    }
    return it->second;
}

bool Modprobe::InsmodWithDeps(const std::string& module_name, const std::string& parameters) {
    if (module_name.empty()) {
        LOG(ERROR) << "Need valid module name, given: " << module_name;
        return false;
    }

    auto dependencies = GetDependencies(module_name);
    if (dependencies.empty()) {
        LOG(ERROR) << "Module " << module_name << " not in dependency file";
        return false;
    }

    // load module dependencies in reverse order
    for (auto dep = dependencies.rbegin(); dep != dependencies.rend() - 1; ++dep) {
        LOG(VERBOSE) << "Loading hard dep for '" << module_name << "': " << *dep;
        if (!LoadWithAliases(*dep, true)) {
            return false;
        }
    }

    // try to load soft pre-dependencies
    for (const auto& [module, softdep] : module_pre_softdep_) {
        if (module_name == module) {
            LOG(VERBOSE) << "Loading soft pre-dep for '" << module << "': " << softdep;
            LoadWithAliases(softdep, false);
        }
    }

    // load target module itself with args
    if (!Insmod(dependencies[0], parameters)) {
        return false;
    }

    // try to load soft post-dependencies
    for (const auto& [module, softdep] : module_post_softdep_) {
        if (module_name == module) {
            LOG(VERBOSE) << "Loading soft post-dep for '" << module << "': " << softdep;
            LoadWithAliases(softdep, false);
        }
    }

    return true;
}

bool Modprobe::LoadWithAliases(const std::string& module_name, bool strict,
                               const std::string& parameters) {
    std::set<std::string> modules_to_load;
    bool module_loaded = false;
    {
        std::lock_guard guard(module_loaded_lock_);

        auto canonical_name = CanonicalizeModulePath(module_name);
        if (module_loaded_.count(canonical_name)) {
            return true;
        }
        modules_to_load.insert(std::move(canonical_name));
        // use aliases to expand list of modules to load (multiple modules
        // may alias themselves to the requested name)
        for (const auto& [alias, aliased_module] : module_aliases_) {
            if (fnmatch(alias.c_str(), module_name.c_str(), 0) != 0) continue;
            LOG(VERBOSE) << "Found alias for '" << module_name << "': '" << aliased_module;
            if (module_loaded_.count(CanonicalizeModulePath(aliased_module))) continue;
            modules_to_load.emplace(aliased_module);
        }
    }

    // attempt to load all modules aliased to this name
    for (const auto& module : modules_to_load) {
        if (!ModuleExists(module)) continue;
        if (InsmodWithDeps(module, parameters)) module_loaded = true;
    }

    if (strict && !module_loaded) {
        LOG(ERROR) << "LoadWithAliases was unable to load " << module_name
                   << ", tried: " << android::base::Join(modules_to_load, ", ");
        return false;
    }
    return true;
}

bool Modprobe::IsBlocklisted(const std::string& module_name) {
    if (!blocklist_enabled) return false;

    auto canonical_name = CanonicalizeModulePath(module_name);
    auto dependencies = GetDependencies(canonical_name);
    for (auto dep = dependencies.begin(); dep != dependencies.end(); ++dep) {
        if (module_blocklist_.count(CanonicalizeModulePath(*dep))) return true;
    }

    return module_blocklist_.count(canonical_name) > 0;
}

// Another option to load kernel modules. load independent modules dependencies
// in parallel and then update dependency list of other remaining modules,
// repeat these steps until all modules are loaded.
// Discard all blocklist.
// Softdeps are taken care in InsmodWithDeps().
bool Modprobe::LoadModulesParallel(int num_threads, int mode, bool test_mode) {
    std::map<std::string, std::vector<std::string>> mods_with_deps;
    std::unordered_set<std::string> mods_loading;
    std::vector<std::string> parallel_modules, sequential_modules;
    std::vector<std::thread> threads;
    std::atomic<bool> ret(true);
    std::mutex mods_to_load_lock;
    std::condition_variable cv_update_module, cv_load_module;
    int sleeping_threads = 0;

    if (test_mode)
        LOG(INFO) << "LoadParallelMode:" << mode << " test_mode: " << test_mode;

    // Get dependencies
    for (const auto& module : module_load_) {
        // Skip blocklist modules
        if (IsBlocklisted(module)) {
            LOG(VERBOSE) << "LMP: Blocklist: Module " << module << " skipping...";
            continue;
        }

        auto dependencies = GetDependencies(CanonicalizeModulePath(module));

        if (dependencies.empty()) {
            LOG(ERROR) << "LMP: Hard-dep: Module " << module
                       << " not in .dep file";
            return false;
        }

        mods_with_deps[CanonicalizeModulePath(module)] = dependencies;
    }

    // Consumers load modules in parallel or sequentially
    auto thread_function = [&] {
        while (!mods_with_deps.empty() && ret.load()) {
            std::unique_lock<std::mutex> lock(mods_to_load_lock);

            if (sequential_modules.empty() && parallel_modules.empty()) {
                sleeping_threads++;

                if (mode == LoadParallelMode::PERFORMANCE)
                    cv_update_module.notify_one();
                else if (sleeping_threads == num_threads)
                    cv_update_module.notify_one();

                cv_load_module.wait(lock, [&](){
                    return mods_with_deps.empty() ||
                           !parallel_modules.empty() ||
                           !sequential_modules.empty(); });

                sleeping_threads--;
            }

            while (!sequential_modules.empty()) {
                auto mod_to_load = std::move(sequential_modules.back());
                sequential_modules.pop_back();
                ret.store(ret.load() && LoadWithAliases(mod_to_load, true));
            }

            if (!parallel_modules.empty()) {
                auto mod_to_load = std::move(parallel_modules.back());
                parallel_modules.pop_back();

                lock.unlock();
                ret.store(ret.load() && LoadWithAliases(mod_to_load, true));
            }
        }
    };

    std::generate_n(std::back_inserter(threads), num_threads,
        [&] { return std::thread(thread_function); });

    // Producer check there's any independent module
    while (!mods_with_deps.empty()) {
        std::unique_lock<std::mutex> lock(mods_to_load_lock);
        for (const auto& [it_mod, it_dep] : mods_with_deps) {
            auto itd_last = it_dep.rbegin();
            if (itd_last == it_dep.rend())
                continue;

            auto cnd_last = CanonicalizeModulePath(*itd_last);
            // Hard-dependencies cannot be blocklisted
            if (IsBlocklisted(cnd_last)) {
                LOG(ERROR) << "LMP: Blocklist: Module-dep " << cnd_last
                           << " : failed to load module " << it_mod;
                ret.store(0);
                break;
            }

            if (mods_loading.insert(cnd_last).second) {
                if (IsLoadSequential(cnd_last))
                    sequential_modules.emplace_back(cnd_last);
                else
                    parallel_modules.emplace_back(cnd_last);
            }

            if (mode == LoadParallelMode::CONSERVATIVE &&
                parallel_modules.size() >= num_threads)
                break;
        }

        if (test_mode) {
            std::random_device rd;
            std::mt19937 rng(rd());

            std::shuffle(parallel_modules.begin(), parallel_modules.end(), rng);
        }

        cv_load_module.notify_all();
        cv_update_module.wait(lock, [&](){
            return parallel_modules.empty() &&
                   sequential_modules.empty(); });

        if (!ret.load())
            break;

        std::lock_guard guard(module_loaded_lock_);
        // Remove loaded module from mods_with_deps
        for (const auto& module_loaded : module_loaded_)
            mods_with_deps.erase(module_loaded);

        // Remove loaded module from dependency list
        for (const auto& module_loaded_path : module_loaded_paths_) {
            for (auto& [mod, deps] : mods_with_deps) {
                auto it = std::find(deps.begin(), deps.end(), module_loaded_path);
                if (it != deps.end())
                    deps.erase(it);
            }
        }
    }

    cv_load_module.notify_all();

    for (auto& thread : threads) {
        thread.join();
    }

    return ret.load();
}

bool Modprobe::LoadListedModules(bool strict) {
    auto ret = true;
    for (const auto& module : module_load_) {
        if (!LoadWithAliases(module, true)) {
            if (IsBlocklisted(module)) continue;
            ret = false;
            if (strict) break;
        }
    }
    return ret;
}

bool Modprobe::Remove(const std::string& module_name) {
    auto dependencies = GetDependencies(CanonicalizeModulePath(module_name));
    for (auto dep = dependencies.begin(); dep != dependencies.end(); ++dep) {
        Rmmod(*dep);
    }
    Rmmod(module_name);
    return true;
}

std::vector<std::string> Modprobe::ListModules(const std::string& pattern) {
    std::vector<std::string> rv;
    for (const auto& [module, deps] : module_deps_) {
        // Attempt to match both the canonical module name and the module filename.
        if (!fnmatch(pattern.c_str(), module.c_str(), 0)) {
            rv.emplace_back(module);
        } else if (!fnmatch(pattern.c_str(), android::base::Basename(deps[0]).c_str(), 0)) {
            rv.emplace_back(deps[0]);
        }
    }
    return rv;
}

bool Modprobe::IsLoadSequential(const std::string& module)
{
    std::string str = "load_sequential=1";
    auto it = module_options_[module].find(str);

    if (it != std::string::npos) {
        module_options_[module].erase(it, it + str.size());
        return true;
    }

    return false;
}

bool Modprobe::GetAllDependencies(const std::string& module,
                                  std::vector<std::string>* pre_dependencies,
                                  std::vector<std::string>* dependencies,
                                  std::vector<std::string>* post_dependencies) {
    std::string canonical_name = CanonicalizeModulePath(module);
    if (pre_dependencies) {
        pre_dependencies->clear();
        for (const auto& [it_module, it_softdep] : module_pre_softdep_) {
            if (canonical_name == it_module) {
                pre_dependencies->emplace_back(it_softdep);
            }
        }
    }
    if (dependencies) {
        dependencies->clear();
        auto hard_deps = GetDependencies(canonical_name);
        if (hard_deps.empty()) {
            return false;
        }
        for (auto dep = hard_deps.rbegin(); dep != hard_deps.rend(); dep++) {
            dependencies->emplace_back(*dep);
        }
    }
    if (post_dependencies) {
        for (const auto& [it_module, it_softdep] : module_post_softdep_) {
            if (canonical_name == it_module) {
                post_dependencies->emplace_back(it_softdep);
            }
        }
    }
    return true;
}

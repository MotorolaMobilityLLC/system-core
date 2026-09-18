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

#include <functional>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

// ModuleConfig contains the kernel module configurations parsed from files such as modules.dep.
class ModuleConfig {
  public:
    // Parses the config from the files in `base_paths` directory.
    static ModuleConfig Parse(const std::vector<std::string>& base_paths,
                              const std::string& load_file = "modules.load");
    ModuleConfig(ModuleConfig&&) = default;

    // Hard dependencies. Parsed from the modules.dep file.
    std::unordered_map<std::string, std::vector<std::string>> module_deps;
    // Module aliases. Parsed from the modules.alias file.
    std::vector<std::pair<std::string, std::string>> module_aliases;
    // Pre-softdeps. Parsed from the modules.softdep file, which contains both pre- and
    // post-softdeps.
    std::vector<std::pair<std::string, std::string>> module_pre_softdep;
    // Post-softdeps.
    std::vector<std::pair<std::string, std::string>> module_post_softdep;
    // Modules to load. Parsed from the `load_file` file specified in the last argument of
    // `Parse()`.
    std::vector<std::string> module_load;
    std::unordered_map<std::string, std::string> module_options;
    std::set<std::string> module_blocklist;

  private:
    ModuleConfig() = default;
    bool ParseDepCallback(const std::string& base_path, const std::vector<std::string>& args);
    bool ParseAliasCallback(const std::vector<std::string>& args);
    bool ParseSoftdepCallback(const std::vector<std::string>& args);
    bool ParseSoftdepParams(const std::string& module, const std::vector<std::string>& args);
    bool ParseLoadCallback(const std::vector<std::string>& args);
    bool ParseOptionsCallback(const std::vector<std::string>& args);
    bool ParseDynOptionsCallback(const std::vector<std::string>& args);
    bool ParseBlocklistCallback(const std::vector<std::string>& args);
    void ParseCfg(const std::string& cfg, std::function<bool(const std::vector<std::string>&)> f);
    void AddOption(const std::string& module_name, const std::string& option_name,
                   const std::string& value);
    void ParseKernelCmdlineOptions();
    std::string GetKernelCmdline();
};

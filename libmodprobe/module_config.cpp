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

#include <modprobe/module_config.h>
#include <modprobe/utils.h>

#include "pwd.h"

#include <utility>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include "exthandler/exthandler.h"

using android::modprobe::CanonicalizeModulePath;

ModuleConfig ModuleConfig::Parse(const std::vector<std::string>& base_paths,
                                 const std::string& load_file) {
    ModuleConfig config;
    using namespace std::placeholders;

    for (const auto& base_path : base_paths) {
        auto alias_callback = std::bind(&ModuleConfig::ParseAliasCallback, &config, _1);
        config.ParseCfg(base_path + "/modules.alias", alias_callback);

        auto dep_callback = std::bind(&ModuleConfig::ParseDepCallback, &config, base_path, _1);
        config.ParseCfg(base_path + "/modules.dep", dep_callback);

        auto softdep_callback = std::bind(&ModuleConfig::ParseSoftdepCallback, &config, _1);
        config.ParseCfg(base_path + "/modules.softdep", softdep_callback);

        auto load_callback = std::bind(&ModuleConfig::ParseLoadCallback, &config, _1);
        config.ParseCfg(base_path + "/" + load_file, load_callback);

        auto options_callback = std::bind(&ModuleConfig::ParseOptionsCallback, &config, _1);
        config.ParseCfg(base_path + "/modules.options", options_callback);

        auto blocklist_callback = std::bind(&ModuleConfig::ParseBlocklistCallback, &config, _1);
        config.ParseCfg(base_path + "/modules.blocklist", blocklist_callback);
    }

    config.ParseKernelCmdlineOptions();
    return config;
}

bool ModuleConfig::ParseDepCallback(const std::string& base_path,
                                    const std::vector<std::string>& args) {
    std::vector<std::string> deps;
    std::string prefix = "";

    // Set first item as our modules path
    std::string::size_type pos = args[0].find(':');
    if (args[0][0] != '/') {
        prefix = base_path + "/";
    }
    if (pos != std::string::npos) {
        deps.emplace_back(prefix + args[0].substr(0, pos));
    } else {
        LOG(ERROR) << "dependency lines must start with name followed by ':'";
        return false;
    }

    // Remaining items are dependencies of our module
    for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
        if ((*arg)[0] != '/') {
            prefix = base_path + "/";
        } else {
            prefix = "";
        }
        deps.push_back(prefix + *arg);
    }

    std::string canonical_name = CanonicalizeModulePath(args[0].substr(0, pos));
    if (canonical_name.empty()) {
        return false;
    }
    this->module_deps[canonical_name] = deps;

    return true;
}

bool ModuleConfig::ParseAliasCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "alias") {
        LOG(ERROR) << "non-alias line encountered in modules.alias, found " << type;
        return false;
    }

    if (args.size() != 3) {
        LOG(ERROR) << "alias lines in modules.alias must have 3 entries, not " << args.size();
        return false;
    }

    const std::string& alias = *it++;
    const std::string& module_name = *it++;
    this->module_aliases.emplace_back(alias, module_name);

    return true;
}

bool ModuleConfig::ParseSoftdepCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "softdep") {
        LOG(ERROR) << "non-softdep line encountered in modules.softdep, found " << type;
        return false;
    }

    if (args.size() < 4) {
        LOG(ERROR) << "softdep lines in modules.softdep must have at least 4 entries";
        return false;
    }

    const std::string& module = *it++;
    return ParseSoftdepParams(module, std::vector<std::string>(it, args.end()));
}

bool ModuleConfig::ParseSoftdepParams(const std::string& module,
                                      const std::vector<std::string>& args) {
    auto it = args.begin();
    std::string state = "";

    while (it != args.end()) {
        const std::string& token = *it++;
        if (token == "pre:" || token == "post:") {
            state = token;
            continue;
        }
        if (state == "") {
            LOG(ERROR) << "malformed modules.softdep at token " << token;
            return false;
        }
        if (state == "pre:") {
            this->module_pre_softdep.emplace_back(module, token);
        } else {
            this->module_post_softdep.emplace_back(module, token);
        }
    }

    return true;
}

bool ModuleConfig::ParseLoadCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& module = *it++;

    const std::string& canonical_name = CanonicalizeModulePath(module);
    if (canonical_name.empty()) {
        return false;
    }
    this->module_load.emplace_back(canonical_name);

    return true;
}

bool ModuleConfig::ParseOptionsCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type == "dyn_options") {
        return ParseDynOptionsCallback(std::vector<std::string>(it, args.end()));
    }

    if (type != "options") {
        LOG(ERROR) << "non-options line encountered in modules.options";
        return false;
    }

    if (args.size() < 2) {
        LOG(ERROR) << "lines in modules.options must have at least 2 entries, not " << args.size();
        return false;
    }

    const std::string& module = *it++;

    if (it != args.end() && *it == "softdep") {
        it++;
        return ParseSoftdepParams(module, std::vector<std::string>(it, args.end()));
    }

    std::string options = "";

    const std::string& canonical_name = CanonicalizeModulePath(module);
    if (canonical_name.empty()) {
        return false;
    }

    while (it != args.end()) {
        options += *it++;
        if (it != args.end()) {
            options += " ";
        }
    }

    auto [unused, inserted] = this->module_options.emplace(canonical_name, options);
    if (!inserted) {
        LOG(ERROR) << "multiple options lines present for module " << module;
        return false;
    }
    return true;
}

bool ModuleConfig::ParseDynOptionsCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    int arg_size = 3;

    if (args.size() < arg_size) {
        LOG(ERROR) << "dyn_options lines in modules.options must have at least" << arg_size
                   << " entries, not " << args.size();
        return false;
    }

    const std::string& module = *it++;

    const std::string& canonical_name = CanonicalizeModulePath(module);
    if (canonical_name.empty()) {
        return false;
    }

    const std::string& pwnam = *it++;
    passwd* pwd = getpwnam(pwnam.c_str());
    if (!pwd) {
        LOG(ERROR) << "invalid handler uid'" << pwnam << "'";
        return false;
    }

    std::string handler_with_args =
            android::base::Join(std::vector<std::string>(it, args.end()), ' ');
    handler_with_args.erase(std::remove(handler_with_args.begin(), handler_with_args.end(), '"'),
                            handler_with_args.end());

    LOG(DEBUG) << "Launching external module options handler: '" << handler_with_args
               << " for module: " << module;

    // There is no need to set envs for external module options handler - pass
    // empty map.
    std::unordered_map<std::string, std::string> envs_map;
    auto result = RunExternalHandler(handler_with_args, pwd->pw_uid, 0, envs_map);
    if (!result.ok()) {
        LOG(ERROR) << "External module handler failed: " << result.error();
        return false;
    }

    LOG(INFO) << "Dynamic options for module: " << module << " are '" << *result << "'";

    auto [unused, inserted] = this->module_options.emplace(canonical_name, *result);
    if (!inserted) {
        LOG(ERROR) << "multiple options lines present for module " << module;
        return false;
    }
    return true;
}

bool ModuleConfig::ParseBlocklistCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "blocklist") {
        LOG(ERROR) << "non-blocklist line encountered in modules.blocklist";
        return false;
    }

    if (args.size() != 2) {
        LOG(ERROR) << "lines in modules.blocklist must have exactly 2 entries, not " << args.size();
        return false;
    }

    const std::string& module = *it++;

    const std::string& canonical_name = CanonicalizeModulePath(module);
    if (canonical_name.empty()) {
        return false;
    }
    this->module_blocklist.emplace(canonical_name);

    return true;
}

void ModuleConfig::ParseCfg(const std::string& cfg,
                            std::function<bool(const std::vector<std::string>&)> f) {
    std::string cfg_contents;
    if (!android::base::ReadFileToString(cfg, &cfg_contents, false)) {
        return;
    }

    std::vector<std::string> lines = android::base::Split(cfg_contents, "\n");
    for (const auto& line : lines) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::vector<std::string> args = android::base::Split(line, " ");
        if (args.empty()) continue;
        f(args);
    }
    return;
}

void ModuleConfig::AddOption(const std::string& module_name, const std::string& option_name,
                             const std::string& value) {
    auto canonical_name = CanonicalizeModulePath(module_name);
    auto options_iter = module_options.find(canonical_name);
    auto option_str = option_name + "=" + value;
    if (options_iter != module_options.end()) {
        options_iter->second = options_iter->second + " " + option_str;
    } else {
        module_options.emplace(canonical_name, option_str);
    }
}

void ModuleConfig::ParseKernelCmdlineOptions(void) {
    std::string cmdline = GetKernelCmdline();
    std::string module_name = "";
    std::string option_name = "";
    std::string value = "";
    bool in_module = true;
    bool in_option = false;
    bool in_value = false;
    bool in_quotes = false;
    int start = 0;

    for (int i = 0; i < cmdline.size(); i++) {
        if (cmdline[i] == '"') {
            in_quotes = !in_quotes;
        }

        if (in_quotes) continue;

        if (cmdline[i] == ' ') {
            if (in_value) {
                value = cmdline.substr(start, i - start);
                if (!module_name.empty() && !option_name.empty()) {
                    AddOption(module_name, option_name, value);
                }
            }
            module_name = "";
            option_name = "";
            value = "";
            in_value = false;
            start = i + 1;
            in_module = true;
            continue;
        }

        if (cmdline[i] == '.') {
            if (in_module) {
                module_name = cmdline.substr(start, i - start);
                start = i + 1;
                in_module = false;
            }
            in_option = true;
            continue;
        }

        if (cmdline[i] == '=') {
            if (in_option) {
                option_name = cmdline.substr(start, i - start);
                start = i + 1;
                in_option = false;
            }
            in_value = true;
            continue;
        }
    }
    if (in_value && !in_quotes) {
        value = cmdline.substr(start, cmdline.size() - start);
        if (!module_name.empty() && !option_name.empty()) {
            AddOption(module_name, option_name, value);
        }
    }
}

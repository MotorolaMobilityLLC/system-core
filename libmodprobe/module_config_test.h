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

#include <android-base/file.h>

#include <string>

// Used by module_config_ext_test to fake a kernel commandline
extern std::string kernel_cmdline;

void WriteModuleConfigs(const TemporaryDir& dir, const std::string& module_alias,
                        const std::string& module_dep, const std::string& module_softdep,
                        const std::string& module_options, const std::string& module_load,
                        const std::string& module_blocklist);

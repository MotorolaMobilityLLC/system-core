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

#pragma once

#include <sys/types.h>
#include <cstdint>

#include <rust/cxx.h>

bool CgroupGetAttributePathForProcessRustBridge(rust::Str attr_name, uint32_t uid, int32_t pid,
                                                rust::String& path);
bool SetProcessProfilesRustBridge(uid_t uid, pid_t pid, rust::Slice<const rust::Str> profiles);
bool SetTaskProfilesRustBridge(int32_t tid, rust::Slice<const rust::Str> profiles,
                               bool use_fd_cache);
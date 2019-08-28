/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <sys/socket.h>

#include <string>

#include "epoll.h"

namespace android {
namespace init {

static constexpr const char kRestoreconProperty[] = "selinux.restorecon_recursive";

bool CanReadProperty(const std::string& source_context, const std::string& name);

extern uint32_t (*property_set)(const std::string& name, const std::string& value);

void property_init();
void property_load_boot_defaults(bool load_debug_prop);
void load_persist_props();
void StartPropertyService(int* epoll_socket);

}  // namespace init
}  // namespace android

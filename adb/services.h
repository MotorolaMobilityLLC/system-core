/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef SERVICES_H_
#define SERVICES_H_

#include "adb_unique_fd.h"

constexpr char kShellServiceArgRaw[] = "raw";
constexpr char kShellServiceArgPty[] = "pty";
constexpr char kShellServiceArgShellProtocol[] = "v2";

unique_fd create_service_thread(const char* service_name, std::function<void(unique_fd)> func);
#endif  // SERVICES_H_

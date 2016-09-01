/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <string>

// Returns true if the argument starts with a plausible socket prefix.
bool is_socket_spec(const std::string& spec);
bool is_local_socket_spec(const std::string& spec);

int socket_spec_connect(const std::string& spec, std::string* error);
int socket_spec_listen(const std::string& spec, std::string* error,
                       int* resolved_tcp_port = nullptr);

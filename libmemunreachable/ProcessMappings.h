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

#ifndef LIBMEMUNREACHABLE_PROCESS_MAPPING_H_
#define LIBMEMUNREACHABLE_PROCESS_MAPPING_H_

#include "Allocator.h"

struct Mapping {
  uintptr_t begin;
  uintptr_t end;
  bool read;
  bool write;
  bool execute;
  bool priv;
  char name[96];
};

// This function is not re-entrant since it uses a static buffer for
// the line data.
bool ProcessMappings(pid_t pid, allocator::vector<Mapping>& mappings);

#endif  // LIBMEMUNREACHABLE_PROCESS_MAPPING_H_

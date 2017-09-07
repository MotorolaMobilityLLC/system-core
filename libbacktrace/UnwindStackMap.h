/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _LIBBACKTRACE_UNWINDSTACK_MAP_H
#define _LIBBACKTRACE_UNWINDSTACK_MAP_H

#include <stdint.h>
#include <sys/types.h>

#include <memory>

#include <backtrace/BacktraceMap.h>
#include <unwindstack/Maps.h>

class UnwindStackMap : public BacktraceMap {
 public:
  explicit UnwindStackMap(pid_t pid);
  ~UnwindStackMap() = default;

  bool Build() override;

  void FillIn(uintptr_t addr, backtrace_map_t* map) override;

  unwindstack::Maps* stack_maps() { return stack_maps_.get(); }

  const std::shared_ptr<unwindstack::Memory>& process_memory() { return process_memory_; }

 protected:
  std::unique_ptr<unwindstack::Maps> stack_maps_;
  std::shared_ptr<unwindstack::Memory> process_memory_;
};

#endif  // _LIBBACKTRACE_UNWINDSTACK_MAP_H

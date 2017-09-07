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

#ifndef _LIBBACKTRACE_UNWIND_STACK_H
#define _LIBBACKTRACE_UNWIND_STACK_H

#include <stdint.h>

#include <string>

#include <backtrace/BacktraceMap.h>
#include <unwindstack/Memory.h>

#include "BacktraceCurrent.h"
#include "BacktracePtrace.h"

class UnwindStackCurrent : public BacktraceCurrent {
 public:
  UnwindStackCurrent(pid_t pid, pid_t tid, BacktraceMap* map);
  virtual ~UnwindStackCurrent() = default;

  std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) override;

  bool UnwindFromContext(size_t num_ignore_frames, ucontext_t* ucontext) override;
};

class UnwindStackPtrace : public BacktracePtrace {
 public:
  UnwindStackPtrace(pid_t pid, pid_t tid, BacktraceMap* map);
  virtual ~UnwindStackPtrace() = default;

  bool Unwind(size_t num_ignore_frames, ucontext_t* context) override;

  std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset);
};

#endif  // _LIBBACKTRACE_UNWIND_STACK_H

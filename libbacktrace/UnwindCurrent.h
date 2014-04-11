/*
 * Copyright (C) 2013 The Android Open Source Project
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

#ifndef _LIBBACKTRACE_UNWIND_CURRENT_H
#define _LIBBACKTRACE_UNWIND_CURRENT_H

#include <string>

#include "BacktraceImpl.h"
#include "BacktraceThread.h"

#define UNW_LOCAL_ONLY
#include <libunwind.h>

class UnwindCurrent : public BacktraceImpl {
public:
  UnwindCurrent();
  virtual ~UnwindCurrent();

  virtual bool Unwind(size_t num_ignore_frames);

  virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset);

  bool UnwindFromContext(size_t num_ignore_frames, bool within_handler);

  void ExtractContext(void* sigcontext);

protected:
  unw_context_t context_;
};

class UnwindThread : public UnwindCurrent, public BacktraceThreadInterface {
public:
  UnwindThread();
  virtual ~UnwindThread();

  virtual void ThreadUnwind(
      siginfo_t* siginfo, void* sigcontext, size_t num_ignore_frames);
};

#endif // _LIBBACKTRACE_UNWIND_CURRENT_H

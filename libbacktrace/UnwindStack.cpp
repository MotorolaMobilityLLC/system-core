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

#define _GNU_SOURCE 1
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <memory>
#include <set>
#include <string>

#if !defined(__ANDROID__)
#include <cutils/threads.h>
#endif

#include <backtrace/Backtrace.h>
#include <demangle.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>

#if !defined(NO_LIBDEXFILE_SUPPORT)
#include <unwindstack/DexFiles.h>
#endif
#include <unwindstack/Unwinder.h>

#include "BacktraceLog.h"
#include "UnwindStack.h"
#include "UnwindStackMap.h"

bool Backtrace::Unwind(unwindstack::Regs* regs, BacktraceMap* back_map,
                       std::vector<backtrace_frame_data_t>* frames, size_t num_ignore_frames,
                       std::vector<std::string>* skip_names, BacktraceUnwindError* error) {
  UnwindStackMap* stack_map = reinterpret_cast<UnwindStackMap*>(back_map);
  auto process_memory = stack_map->process_memory();
  unwindstack::Unwinder unwinder(MAX_BACKTRACE_FRAMES + num_ignore_frames, stack_map->stack_maps(),
                                 regs, stack_map->process_memory());
  unwinder.SetResolveNames(stack_map->ResolveNames());
  if (stack_map->GetJitDebug() != nullptr) {
    unwinder.SetJitDebug(stack_map->GetJitDebug(), regs->Arch());
  }
#if !defined(NO_LIBDEXFILE_SUPPORT)
  if (stack_map->GetDexFiles() != nullptr) {
    unwinder.SetDexFiles(stack_map->GetDexFiles(), regs->Arch());
  }
#endif
  unwinder.Unwind(skip_names, &stack_map->GetSuffixesToIgnore());
  if (error != nullptr) {
    switch (unwinder.LastErrorCode()) {
      case unwindstack::ERROR_NONE:
        error->error_code = BACKTRACE_UNWIND_NO_ERROR;
        break;

      case unwindstack::ERROR_MEMORY_INVALID:
        error->error_code = BACKTRACE_UNWIND_ERROR_ACCESS_MEM_FAILED;
        error->error_info.addr = unwinder.LastErrorAddress();
        break;

      case unwindstack::ERROR_UNWIND_INFO:
        error->error_code = BACKTRACE_UNWIND_ERROR_UNWIND_INFO;
        break;

      case unwindstack::ERROR_UNSUPPORTED:
        error->error_code = BACKTRACE_UNWIND_ERROR_UNSUPPORTED_OPERATION;
        break;

      case unwindstack::ERROR_INVALID_MAP:
        error->error_code = BACKTRACE_UNWIND_ERROR_MAP_MISSING;
        break;

      case unwindstack::ERROR_MAX_FRAMES_EXCEEDED:
        error->error_code = BACKTRACE_UNWIND_ERROR_EXCEED_MAX_FRAMES_LIMIT;
        break;

      case unwindstack::ERROR_REPEATED_FRAME:
        error->error_code = BACKTRACE_UNWIND_ERROR_REPEATED_FRAME;
        break;
    }
  }

  if (num_ignore_frames >= unwinder.NumFrames()) {
    frames->resize(0);
    return true;
  }

  auto unwinder_frames = unwinder.frames();
  frames->resize(unwinder.NumFrames() - num_ignore_frames);
  size_t cur_frame = 0;
  for (size_t i = num_ignore_frames; i < unwinder.NumFrames(); i++) {
    auto frame = &unwinder_frames[i];

    backtrace_frame_data_t* back_frame = &frames->at(cur_frame);

    back_frame->num = cur_frame++;

    back_frame->rel_pc = frame->rel_pc;
    back_frame->pc = frame->pc;
    back_frame->sp = frame->sp;

    back_frame->func_name = demangle(frame->function_name.c_str());
    back_frame->func_offset = frame->function_offset;

    back_frame->map.name = frame->map_name;
    back_frame->map.start = frame->map_start;
    back_frame->map.end = frame->map_end;
    back_frame->map.offset = frame->map_offset;
    back_frame->map.load_bias = frame->map_load_bias;
    back_frame->map.flags = frame->map_flags;
  }

  return true;
}

UnwindStackCurrent::UnwindStackCurrent(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktraceCurrent(pid, tid, map) {}

std::string UnwindStackCurrent::GetFunctionNameRaw(uint64_t pc, uint64_t* offset) {
  return GetMap()->GetFunctionName(pc, offset);
}

bool UnwindStackCurrent::UnwindFromContext(size_t num_ignore_frames, void* ucontext) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (ucontext == nullptr) {
    regs.reset(unwindstack::Regs::CreateFromLocal());
    // Fill in the registers from this function. Do it here to avoid
    // one extra function call appearing in the unwind.
    unwindstack::RegsGetLocal(regs.get());
  } else {
    regs.reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(), ucontext));
  }

  std::vector<std::string> skip_names{"libunwindstack.so", "libbacktrace.so"};
  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames, &skip_names, &error_);
}

UnwindStackPtrace::UnwindStackPtrace(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktracePtrace(pid, tid, map), memory_(pid) {}

std::string UnwindStackPtrace::GetFunctionNameRaw(uint64_t pc, uint64_t* offset) {
  return GetMap()->GetFunctionName(pc, offset);
}

bool UnwindStackPtrace::Unwind(size_t num_ignore_frames, void* context) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (context == nullptr) {
    regs.reset(unwindstack::Regs::RemoteGet(Tid()));
  } else {
    regs.reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(), context));
  }

  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames, nullptr, &error_);
}

size_t UnwindStackPtrace::Read(uint64_t addr, uint8_t* buffer, size_t bytes) {
  return memory_.Read(addr, buffer, bytes);
}

UnwindStackOffline::UnwindStackOffline(ArchEnum arch, pid_t pid, pid_t tid, BacktraceMap* map,
                                       bool map_shared)
    : Backtrace(pid, tid, map), arch_(arch) {
  map_shared_ = map_shared;
}

bool UnwindStackOffline::Unwind(size_t num_ignore_frames, void* ucontext) {
  if (ucontext == nullptr) {
    return false;
  }

  unwindstack::ArchEnum arch;
  switch (arch_) {
    case ARCH_ARM:
      arch = unwindstack::ARCH_ARM;
      break;
    case ARCH_ARM64:
      arch = unwindstack::ARCH_ARM64;
      break;
    case ARCH_X86:
      arch = unwindstack::ARCH_X86;
      break;
    case ARCH_X86_64:
      arch = unwindstack::ARCH_X86_64;
      break;
    default:
      return false;
  }

  std::unique_ptr<unwindstack::Regs> regs(unwindstack::Regs::CreateFromUcontext(arch, ucontext));

  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames, nullptr, &error_);
}

std::string UnwindStackOffline::GetFunctionNameRaw(uint64_t, uint64_t*) {
  return "";
}

size_t UnwindStackOffline::Read(uint64_t, uint8_t*, size_t) {
  return 0;
}

bool UnwindStackOffline::ReadWord(uint64_t, word_t*) {
  return false;
}

Backtrace* Backtrace::CreateOffline(ArchEnum arch, pid_t pid, pid_t tid,
                                    const std::vector<backtrace_map_t>& maps,
                                    const backtrace_stackinfo_t& stack) {
  BacktraceMap* map = BacktraceMap::CreateOffline(pid, maps, stack);
  if (map == nullptr) {
    return nullptr;
  }

  return new UnwindStackOffline(arch, pid, tid, map, false);
}

Backtrace* Backtrace::CreateOffline(ArchEnum arch, pid_t pid, pid_t tid, BacktraceMap* map) {
  if (map == nullptr) {
    return nullptr;
  }
  return new UnwindStackOffline(arch, pid, tid, map, true);
}

void Backtrace::SetGlobalElfCache(bool enable) {
  unwindstack::Elf::SetCachingEnabled(enable);
}

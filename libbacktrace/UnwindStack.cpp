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
#include <ucontext.h>

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

#include <unwindstack/Unwinder.h>

#include "BacktraceLog.h"
#ifndef NO_LIBDEXFILE
#include "UnwindDexFile.h"
#endif
#include "UnwindStack.h"
#include "UnwindStackMap.h"

static void FillInDexFrame(UnwindStackMap* stack_map, uint64_t dex_pc,
                           backtrace_frame_data_t* frame) {
  // The DEX PC points into the .dex section within an ELF file.
  // However, this is a BBS section manually mmaped to a .vdex file,
  // so we need to get the following map to find the ELF data.
  unwindstack::Maps* maps = stack_map->stack_maps();
  auto it = maps->begin();
  uint64_t rel_dex_pc;
  unwindstack::MapInfo* info;
  for (; it != maps->end(); ++it) {
    auto entry = *it;
    if (dex_pc >= entry->start && dex_pc < entry->end) {
      info = entry;
      rel_dex_pc = dex_pc - entry->start;
      frame->map.start = entry->start;
      frame->map.end = entry->end;
      frame->map.offset = entry->offset;
      frame->map.load_bias = entry->load_bias;
      frame->map.flags = entry->flags;
      frame->map.name = entry->name;
      frame->rel_pc = rel_dex_pc;
      break;
    }
  }
  if (it == maps->end() || ++it == maps->end()) {
    return;
  }

  auto entry = *it;
  auto process_memory = stack_map->process_memory();
  unwindstack::Elf* elf = entry->GetElf(process_memory, true);
  if (!elf->valid()) {
    return;
  }

  // Adjust the relative dex by the offset.
  rel_dex_pc += entry->elf_offset;

  uint64_t dex_offset;
  if (!elf->GetFunctionName(rel_dex_pc, &frame->func_name, &dex_offset)) {
    return;
  }
  frame->func_offset = dex_offset;
  if (frame->func_name != "$dexfile") {
    return;
  }

#ifndef NO_LIBDEXFILE
  UnwindDexFile* dex_file = stack_map->GetDexFile(dex_pc - dex_offset, info);
  if (dex_file != nullptr) {
    dex_file->GetMethodInformation(dex_offset, &frame->func_name, &frame->func_offset);
  }
#endif
}

bool Backtrace::Unwind(unwindstack::Regs* regs, BacktraceMap* back_map,
                       std::vector<backtrace_frame_data_t>* frames, size_t num_ignore_frames,
                       std::vector<std::string>* skip_names) {
  UnwindStackMap* stack_map = reinterpret_cast<UnwindStackMap*>(back_map);
  auto process_memory = stack_map->process_memory();
  unwindstack::Unwinder unwinder(MAX_BACKTRACE_FRAMES + num_ignore_frames, stack_map->stack_maps(),
                                 regs, stack_map->process_memory());
  if (stack_map->GetJitDebug() != nullptr) {
    unwinder.SetJitDebug(stack_map->GetJitDebug(), regs->Arch());
  }
  unwinder.Unwind(skip_names, &stack_map->GetSuffixesToIgnore());

  if (num_ignore_frames >= unwinder.NumFrames()) {
    frames->resize(0);
    return true;
  }

  auto unwinder_frames = unwinder.frames();
  // Get the real number of frames we'll need.
  size_t total_frames = 0;
  for (size_t i = num_ignore_frames; i < unwinder.NumFrames(); i++, total_frames++) {
    if (unwinder_frames[i].dex_pc != 0) {
      total_frames++;
    }
  }
  frames->resize(total_frames);
  size_t cur_frame = 0;
  for (size_t i = num_ignore_frames; i < unwinder.NumFrames(); i++) {
    auto frame = &unwinder_frames[i];

    // Inject extra 'virtual' frame that represents the dex pc data.
    // The dex pc is magic register defined in the Mterp interpreter,
    // and thus it will be restored/observed in the frame after it.
    // Adding the dex frame first here will create something like:
    //   #7 pc 006b1ba1 libartd.so  ExecuteMterpImpl+14625
    //   #8 pc 0015fa20 core.vdex   java.util.Arrays.binarySearch+8
    //   #9 pc 0039a1ef libartd.so  art::interpreter::Execute+719
    if (frame->dex_pc != 0) {
      backtrace_frame_data_t* dex_frame = &frames->at(cur_frame++);
      dex_frame->num = cur_frame;
      dex_frame->pc = frame->dex_pc;
      dex_frame->rel_pc = frame->dex_pc;
      dex_frame->sp = frame->sp;
      dex_frame->stack_size = 0;
      dex_frame->func_offset = 0;
      FillInDexFrame(stack_map, frame->dex_pc, dex_frame);
    }

    backtrace_frame_data_t* back_frame = &frames->at(cur_frame++);

    back_frame->num = cur_frame;

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

bool UnwindStackCurrent::UnwindFromContext(size_t num_ignore_frames, ucontext_t* ucontext) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (ucontext == nullptr) {
    regs.reset(unwindstack::Regs::CreateFromLocal());
    // Fill in the registers from this function. Do it here to avoid
    // one extra function call appearing in the unwind.
    unwindstack::RegsGetLocal(regs.get());
  } else {
    regs.reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(), ucontext));
  }

  error_.error_code = BACKTRACE_UNWIND_NO_ERROR;
  std::vector<std::string> skip_names{"libunwindstack.so", "libbacktrace.so"};
  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames, &skip_names);
}

UnwindStackPtrace::UnwindStackPtrace(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktracePtrace(pid, tid, map), memory_(pid) {}

std::string UnwindStackPtrace::GetFunctionNameRaw(uint64_t pc, uint64_t* offset) {
  return GetMap()->GetFunctionName(pc, offset);
}

bool UnwindStackPtrace::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (context == nullptr) {
    regs.reset(unwindstack::Regs::RemoteGet(Tid()));
  } else {
    regs.reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(), context));
  }

  error_.error_code = BACKTRACE_UNWIND_NO_ERROR;
  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames, nullptr);
}

size_t UnwindStackPtrace::Read(uint64_t addr, uint8_t* buffer, size_t bytes) {
  return memory_.Read(addr, buffer, bytes);
}

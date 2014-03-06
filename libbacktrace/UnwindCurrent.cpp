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

#define LOG_TAG "libbacktrace"

#include <sys/types.h>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "UnwindCurrent.h"
#include "UnwindMap.h"

#include <ucontext.h>

//-------------------------------------------------------------------------
// UnwindCurrent functions.
//-------------------------------------------------------------------------
UnwindCurrent::UnwindCurrent() {
}

UnwindCurrent::~UnwindCurrent() {
}

bool UnwindCurrent::Unwind(size_t num_ignore_frames) {
  int ret = unw_getcontext(&context_);
  if (ret < 0) {
    BACK_LOGW("unw_getcontext failed %d", ret);
    return false;
  }
  return UnwindFromContext(num_ignore_frames, true);
}

std::string UnwindCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  *offset = 0;
  char buf[512];
  unw_word_t value;
  if (unw_get_proc_name_by_ip(unw_local_addr_space, pc, buf, sizeof(buf),
                              &value, &context_) >= 0 && buf[0] != '\0') {
    *offset = static_cast<uintptr_t>(value);
    return buf;
  }
  return "";
}

bool UnwindCurrent::UnwindFromContext(size_t num_ignore_frames, bool resolve) {
  // The cursor structure is pretty large, do not put it on the stack.
  unw_cursor_t* cursor = new unw_cursor_t;
  int ret = unw_init_local(cursor, &context_);
  if (ret < 0) {
    BACK_LOGW("unw_init_local failed %d", ret);
    delete cursor;
    return false;
  }

  std::vector<backtrace_frame_data_t>* frames = GetFrames();
  frames->reserve(MAX_BACKTRACE_FRAMES);
  size_t num_frames = 0;
  do {
    unw_word_t pc;
    ret = unw_get_reg(cursor, UNW_REG_IP, &pc);
    if (ret < 0) {
      BACK_LOGW("Failed to read IP %d", ret);
      break;
    }
    unw_word_t sp;
    ret = unw_get_reg(cursor, UNW_REG_SP, &sp);
    if (ret < 0) {
      BACK_LOGW("Failed to read SP %d", ret);
      break;
    }

    if (num_ignore_frames == 0) {
      frames->resize(num_frames+1);
      backtrace_frame_data_t* frame = &frames->at(num_frames);
      frame->num = num_frames;
      frame->pc = static_cast<uintptr_t>(pc);
      frame->sp = static_cast<uintptr_t>(sp);
      frame->stack_size = 0;

      if (num_frames > 0) {
        // Set the stack size for the previous frame.
        backtrace_frame_data_t* prev = &frames->at(num_frames-1);
        prev->stack_size = frame->sp - prev->sp;
      }

      if (resolve) {
        frame->func_name = GetFunctionName(frame->pc, &frame->func_offset);
        frame->map = FindMap(frame->pc);
      } else {
        frame->map = NULL;
        frame->func_offset = 0;
      }
      num_frames++;
    } else {
      num_ignore_frames--;
    }
    ret = unw_step (cursor);
  } while (ret > 0 && num_frames < MAX_BACKTRACE_FRAMES);

  delete cursor;
  return true;
}

void UnwindCurrent::ExtractContext(void* sigcontext) {
  unw_tdep_context_t* context = reinterpret_cast<unw_tdep_context_t*>(&context_);
  const ucontext_t* uc = reinterpret_cast<const ucontext_t*>(sigcontext);

#if defined(__arm__)
  context->regs[0] = uc->uc_mcontext.arm_r0;
  context->regs[1] = uc->uc_mcontext.arm_r1;
  context->regs[2] = uc->uc_mcontext.arm_r2;
  context->regs[3] = uc->uc_mcontext.arm_r3;
  context->regs[4] = uc->uc_mcontext.arm_r4;
  context->regs[5] = uc->uc_mcontext.arm_r5;
  context->regs[6] = uc->uc_mcontext.arm_r6;
  context->regs[7] = uc->uc_mcontext.arm_r7;
  context->regs[8] = uc->uc_mcontext.arm_r8;
  context->regs[9] = uc->uc_mcontext.arm_r9;
  context->regs[10] = uc->uc_mcontext.arm_r10;
  context->regs[11] = uc->uc_mcontext.arm_fp;
  context->regs[12] = uc->uc_mcontext.arm_ip;
  context->regs[13] = uc->uc_mcontext.arm_sp;
  context->regs[14] = uc->uc_mcontext.arm_lr;
  context->regs[15] = uc->uc_mcontext.arm_pc;
#else
  context->uc_mcontext = uc->uc_mcontext;
#endif
}

//-------------------------------------------------------------------------
// UnwindThread functions.
//-------------------------------------------------------------------------
UnwindThread::UnwindThread() {
}

UnwindThread::~UnwindThread() {
}

void UnwindThread::ThreadUnwind(
    siginfo_t* /*siginfo*/, void* sigcontext, size_t num_ignore_frames) {
  ExtractContext(sigcontext);
  UnwindFromContext(num_ignore_frames, false);
}

//-------------------------------------------------------------------------
// C++ object creation function.
//-------------------------------------------------------------------------
Backtrace* CreateCurrentObj(BacktraceMap* map) {
  return new BacktraceCurrent(new UnwindCurrent(), map);
}

Backtrace* CreateThreadObj(pid_t tid, BacktraceMap* map) {
  UnwindThread* thread_obj = new UnwindThread();
  return new BacktraceThread(thread_obj, thread_obj, tid, map);
}

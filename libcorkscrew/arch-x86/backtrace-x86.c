/*
 * Copyright (C) 2011 The Android Open Source Project
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

/*
 * Backtracing functions for x86.
 */

#define LOG_TAG "Corkscrew"
//#define LOG_NDEBUG 0

#include "../backtrace-arch.h"
#include "../backtrace-helper.h"
#include <corkscrew/ptrace.h>

#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/exec_elf.h>
#include <cutils/log.h>

/* Machine context at the time a signal was raised. */
typedef struct ucontext {
    uint32_t uc_flags;
    struct ucontext* uc_link;
    stack_t uc_stack;
    struct sigcontext {
        uint32_t gs;
        uint32_t fs;
        uint32_t es;
        uint32_t ds;
        uint32_t edi;
        uint32_t esi;
        uint32_t ebp;
        uint32_t esp;
        uint32_t ebx;
        uint32_t edx;
        uint32_t ecx;
        uint32_t eax;
        uint32_t trapno;
        uint32_t err;
        uint32_t eip;
        uint32_t cs;
        uint32_t efl;
        uint32_t uesp;
        uint32_t ss;
        void* fpregs;
        uint32_t oldmask;
        uint32_t cr2;
    } uc_mcontext;
    uint32_t uc_sigmask;
} ucontext_t;

/* Unwind state. */
typedef struct {
    uint32_t ebp;
    uint32_t eip;
    uint32_t esp;
} unwind_state_t;

static ssize_t unwind_backtrace_common(pid_t tid, const ptrace_context_t* context,
        unwind_state_t* state, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth) {
    size_t ignored_frames = 0;
    size_t returned_frames = 0;

    while (state->ebp && returned_frames < max_depth) {
        backtrace_frame_t* frame = add_backtrace_entry(state->eip,
                backtrace, ignore_depth, max_depth,
                &ignored_frames, &returned_frames);
        uint32_t next_esp = state->ebp + 8;
        if (frame) {
            frame->stack_top = state->esp;
            if (state->esp < next_esp) {
                frame->stack_size = next_esp - state->esp;
            }
        }
        state->esp = next_esp;
        if (!try_get_word(tid, state->ebp + 4, &state->eip)
                || !try_get_word(tid, state->ebp, &state->ebp)
                || !state->eip) {
            break;
        }
    }

    return returned_frames;
}

ssize_t unwind_backtrace_signal_arch(siginfo_t* siginfo, void* sigcontext,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    const ucontext_t* uc = (const ucontext_t*)sigcontext;

    unwind_state_t state;
    state.ebp = uc->uc_mcontext.ebp;
    state.eip = uc->uc_mcontext.eip;
    state.esp = uc->uc_mcontext.esp;

    return unwind_backtrace_common(-1, NULL, &state, backtrace, ignore_depth, max_depth);
}

ssize_t unwind_backtrace_ptrace_arch(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    pt_regs_x86_t regs;
    if (ptrace(PTRACE_GETREGS, tid, 0, &regs)) {
        return -1;
    }

    unwind_state_t state;
    state.ebp = regs.ebp;
    state.eip = regs.eip;
    state.esp = regs.esp;

    return unwind_backtrace_common(tid, context, &state, backtrace, ignore_depth, max_depth);
}

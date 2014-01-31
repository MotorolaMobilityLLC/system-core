/*
** Copyright 2013, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "../utility.h"
#include "../machine.h"

void dump_memory_and_code(log_t* log, pid_t tid, int scope_flags) {
}

void dump_registers(log_t* log, pid_t tid, int scope_flags) {
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, tid, 0, &r) == -1) {
        _LOG(log, scope_flags, "cannot get registers: %s\n", strerror(errno));
        return;
    }
    _LOG(log, scope_flags, "    rax %016lx  rbx %016lx  rcx %016lx  rdx %016lx\n",
         r.rax, r.rbx, r.rcx, r.rdx);
    _LOG(log, scope_flags, "    rsi %016lx  rdi %016lx\n",
         r.rsi, r.rdi);
    _LOG(log, scope_flags, "    r8  %016lx  r9  %016lx  r10 %016lx  r11 %016lx\n",
         r.r8, r.r9, r.r10, r.r11);
    _LOG(log, scope_flags, "    r12 %016lx  r13 %016lx  r14 %016lx  r15 %016lx\n",
         r.r12, r.r13, r.r14, r.r15);
    _LOG(log, scope_flags, "    cs  %016lx  ss  %016lx\n",
         r.cs, r.ss);
    _LOG(log, scope_flags, "    rip %016lx  rbp %016lx  rsp %016lx  eflags %016lx\n",
         r.rip, r.rbp, r.rsp, r.eflags);
}

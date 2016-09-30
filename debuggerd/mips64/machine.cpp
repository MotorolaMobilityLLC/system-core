/*
 * Copyright 2014, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "DEBUG"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>

#include <android/log.h>
#include <backtrace/Backtrace.h>

#include "machine.h"
#include "utility.h"

#define R(x) (static_cast<uintptr_t>(x))

// If configured to do so, dump memory around *all* registers
// for the crashing thread.
void dump_memory_and_code(log_t* log, Backtrace* backtrace) {
  pt_regs r;
  if (ptrace(PTRACE_GETREGS, backtrace->Tid(), 0, &r)) {
    ALOGE("cannot get registers: %s\n", strerror(errno));
    return;
  }

  static const char reg_names[] = "$0atv0v1a0a1a2a3a4a5a6a7t0t1t2t3s0s1s2s3s4s5s6s7t8t9k0k1gpsps8ra";

  for (int reg = 0; reg < 32; reg++) {
    // skip uninteresting registers
    if (reg == 0 // $0
        || reg == 26 // $k0
        || reg == 27 // $k1
        || reg == 31 // $ra (done below)
       )
      continue;

    dump_memory(log, backtrace, R(r.regs[reg]), "memory near %.2s:", &reg_names[reg * 2]);
  }

  uintptr_t pc = R(r.cp0_epc);
  uintptr_t ra = R(r.regs[31]);
  dump_memory(log, backtrace, pc, "code around pc:");
  if (pc != ra) {
    dump_memory(log, backtrace, ra, "code around ra:");
  }
}

void dump_registers(log_t* log, pid_t tid) {
  pt_regs r;
  if(ptrace(PTRACE_GETREGS, tid, 0, &r)) {
    ALOGE("cannot get registers: %s\n", strerror(errno));
    return;
  }

  _LOG(log, logtype::REGISTERS, " zr %016" PRIxPTR "  at %016" PRIxPTR
       "  v0 %016" PRIxPTR "  v1 %016" PRIxPTR "\n",
       R(r.regs[0]), R(r.regs[1]), R(r.regs[2]), R(r.regs[3]));
  _LOG(log, logtype::REGISTERS, " a0 %016" PRIxPTR "  a1 %016" PRIxPTR
       "  a2 %016" PRIxPTR "  a3 %016" PRIxPTR "\n",
       R(r.regs[4]), R(r.regs[5]), R(r.regs[6]), R(r.regs[7]));
  _LOG(log, logtype::REGISTERS, " a4 %016" PRIxPTR "  a5 %016" PRIxPTR
       "  a6 %016" PRIxPTR "  a7 %016" PRIxPTR "\n",
       R(r.regs[8]), R(r.regs[9]), R(r.regs[10]), R(r.regs[11]));
  _LOG(log, logtype::REGISTERS, " t0 %016" PRIxPTR "  t1 %016" PRIxPTR
       "  t2 %016" PRIxPTR "  t3 %016" PRIxPTR "\n",
       R(r.regs[12]), R(r.regs[13]), R(r.regs[14]), R(r.regs[15]));
  _LOG(log, logtype::REGISTERS, " s0 %016" PRIxPTR "  s1 %016" PRIxPTR
       "  s2 %016" PRIxPTR "  s3 %016" PRIxPTR "\n",
       R(r.regs[16]), R(r.regs[17]), R(r.regs[18]), R(r.regs[19]));
  _LOG(log, logtype::REGISTERS, " s4 %016" PRIxPTR "  s5 %016" PRIxPTR
       "  s6 %016" PRIxPTR "  s7 %016" PRIxPTR "\n",
       R(r.regs[20]), R(r.regs[21]), R(r.regs[22]), R(r.regs[23]));
  _LOG(log, logtype::REGISTERS, " t8 %016" PRIxPTR "  t9 %016" PRIxPTR
       "  k0 %016" PRIxPTR "  k1 %016" PRIxPTR "\n",
       R(r.regs[24]), R(r.regs[25]), R(r.regs[26]), R(r.regs[27]));
  _LOG(log, logtype::REGISTERS, " gp %016" PRIxPTR "  sp %016" PRIxPTR
       "  s8 %016" PRIxPTR "  ra %016" PRIxPTR "\n",
       R(r.regs[28]), R(r.regs[29]), R(r.regs[30]), R(r.regs[31]));
  _LOG(log, logtype::REGISTERS, " hi %016" PRIxPTR "  lo %016" PRIxPTR
       " bva %016" PRIxPTR " epc %016" PRIxPTR "\n",
       R(r.hi), R(r.lo), R(r.cp0_badvaddr), R(r.cp0_epc));
}

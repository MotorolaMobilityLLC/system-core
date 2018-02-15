/*
 * Copyright 2008, The Android Open Source Project
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

#include "libdebuggerd/utility.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <backtrace/Backtrace.h>
#include <debuggerd/handler.h>
#include <log/log.h>
#include <unwindstack/Memory.h>

using android::base::unique_fd;

// Whitelist output desired in the logcat output.
bool is_allowed_in_logcat(enum logtype ltype) {
  if ((ltype == HEADER)
   || (ltype == REGISTERS)
   || (ltype == BACKTRACE)) {
    return true;
  }
  return false;
}

static bool should_write_to_kmsg() {
  // Write to kmsg if tombstoned isn't up, and we're able to do so.
  if (!android::base::GetBoolProperty("ro.debuggable", false)) {
    return false;
  }

  if (android::base::GetProperty("init.svc.tombstoned", "") == "running") {
    return false;
  }

  return true;
}

__attribute__((__weak__, visibility("default")))
void _LOG(log_t* log, enum logtype ltype, const char* fmt, ...) {
  bool write_to_tombstone = (log->tfd != -1);
  bool write_to_logcat = is_allowed_in_logcat(ltype)
                      && log->crashed_tid != -1
                      && log->current_tid != -1
                      && (log->crashed_tid == log->current_tid);
  static bool write_to_kmsg = should_write_to_kmsg();

  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  size_t len = strlen(buf);
  if (len <= 0) {
    return;
  }

  if (write_to_tombstone) {
    TEMP_FAILURE_RETRY(write(log->tfd, buf, len));
  }

  if (write_to_logcat) {
    __android_log_buf_write(LOG_ID_CRASH, ANDROID_LOG_FATAL, LOG_TAG, buf);
    if (log->amfd_data != nullptr) {
      *log->amfd_data += buf;
    }

    if (write_to_kmsg) {
      unique_fd kmsg_fd(open("/dev/kmsg_debug", O_WRONLY | O_APPEND | O_CLOEXEC));
      if (kmsg_fd.get() >= 0) {
        // Our output might contain newlines which would otherwise be handled by the android logger.
        // Split the lines up ourselves before sending to the kernel logger.
        if (buf[len - 1] == '\n') {
          buf[len - 1] = '\0';
        }

        std::vector<std::string> fragments = android::base::Split(buf, "\n");
        for (const std::string& fragment : fragments) {
          static constexpr char prefix[] = "<3>DEBUG: ";
          struct iovec iov[3];
          iov[0].iov_base = const_cast<char*>(prefix);
          iov[0].iov_len = strlen(prefix);
          iov[1].iov_base = const_cast<char*>(fragment.c_str());
          iov[1].iov_len = fragment.length();
          iov[2].iov_base = const_cast<char*>("\n");
          iov[2].iov_len = 1;
          TEMP_FAILURE_RETRY(writev(kmsg_fd.get(), iov, 3));
        }
      }
    }
  }
}

#define MEMORY_BYTES_TO_DUMP 256
#define MEMORY_BYTES_PER_LINE 16

void dump_memory(log_t* log, unwindstack::Memory* memory, uint64_t addr, const std::string& label) {
  // Align the address to sizeof(long) and start 32 bytes before the address.
  addr &= ~(sizeof(long) - 1);
  if (addr >= 4128) {
    addr -= 32;
  }

  // Don't bother if the address looks too low, or looks too high.
  if (addr < 4096 ||
#if defined(__LP64__)
      addr > 0x4000000000000000UL - MEMORY_BYTES_TO_DUMP) {
#else
      addr > 0xffff0000 - MEMORY_BYTES_TO_DUMP) {
#endif
    return;
  }

  _LOG(log, logtype::MEMORY, "\n%s:\n", label.c_str());

  // Dump 256 bytes
  uintptr_t data[MEMORY_BYTES_TO_DUMP/sizeof(uintptr_t)];
  memset(data, 0, MEMORY_BYTES_TO_DUMP);
  size_t bytes = memory->Read(addr, reinterpret_cast<uint8_t*>(data), sizeof(data));
  if (bytes % sizeof(uintptr_t) != 0) {
    // This should never happen, but just in case.
    ALOGE("Bytes read %zu, is not a multiple of %zu", bytes, sizeof(uintptr_t));
    bytes &= ~(sizeof(uintptr_t) - 1);
  }

  uint64_t start = 0;
  bool skip_2nd_read = false;
  if (bytes == 0) {
    // In this case, we might want to try another read at the beginning of
    // the next page only if it's within the amount of memory we would have
    // read.
    size_t page_size = sysconf(_SC_PAGE_SIZE);
    start = ((addr + (page_size - 1)) & ~(page_size - 1)) - addr;
    if (start == 0 || start >= MEMORY_BYTES_TO_DUMP) {
      skip_2nd_read = true;
    }
  }

  if (bytes < MEMORY_BYTES_TO_DUMP && !skip_2nd_read) {
    // Try to do one more read. This could happen if a read crosses a map,
    // but the maps do not have any break between them. Or it could happen
    // if reading from an unreadable map, but the read would cross back
    // into a readable map. Only requires one extra read because a map has
    // to contain at least one page, and the total number of bytes to dump
    // is smaller than a page.
    size_t bytes2 = memory->Read(addr + start + bytes, reinterpret_cast<uint8_t*>(data) + bytes,
                                 sizeof(data) - bytes - start);
    bytes += bytes2;
    if (bytes2 > 0 && bytes % sizeof(uintptr_t) != 0) {
      // This should never happen, but we'll try and continue any way.
      ALOGE("Bytes after second read %zu, is not a multiple of %zu", bytes, sizeof(uintptr_t));
      bytes &= ~(sizeof(uintptr_t) - 1);
    }
  }

  // Dump the code around memory as:
  //  addr             contents                           ascii
  //  0000000000008d34 ef000000e8bd0090 e1b00000512fff1e  ............../Q
  //  0000000000008d44 ea00b1f9e92d0090 e3a070fcef000000  ......-..p......
  // On 32-bit machines, there are still 16 bytes per line but addresses and
  // words are of course presented differently.
  uintptr_t* data_ptr = data;
  size_t current = 0;
  size_t total_bytes = start + bytes;
  for (size_t line = 0; line < MEMORY_BYTES_TO_DUMP / MEMORY_BYTES_PER_LINE; line++) {
    std::string logline;
    android::base::StringAppendF(&logline, "    %" PRIPTR, addr);

    addr += MEMORY_BYTES_PER_LINE;
    std::string ascii;
    for (size_t i = 0; i < MEMORY_BYTES_PER_LINE / sizeof(uintptr_t); i++) {
      if (current >= start && current + sizeof(uintptr_t) <= total_bytes) {
        android::base::StringAppendF(&logline, " %" PRIPTR, static_cast<uint64_t>(*data_ptr));

        // Fill out the ascii string from the data.
        uint8_t* ptr = reinterpret_cast<uint8_t*>(data_ptr);
        for (size_t val = 0; val < sizeof(uintptr_t); val++, ptr++) {
          if (*ptr >= 0x20 && *ptr < 0x7f) {
            ascii += *ptr;
          } else {
            ascii += '.';
          }
        }
        data_ptr++;
      } else {
        logline += ' ' + std::string(sizeof(uintptr_t) * 2, '-');
        ascii += std::string(sizeof(uintptr_t), '.');
      }
      current += sizeof(uintptr_t);
    }
    _LOG(log, logtype::MEMORY, "%s  %s\n", logline.c_str(), ascii.c_str());
  }
}

void read_with_default(const char* path, char* buf, size_t len, const char* default_value) {
  unique_fd fd(open(path, O_RDONLY | O_CLOEXEC));
  if (fd != -1) {
    int rc = TEMP_FAILURE_RETRY(read(fd.get(), buf, len - 1));
    if (rc != -1) {
      buf[rc] = '\0';

      // Trim trailing newlines.
      if (rc > 0 && buf[rc - 1] == '\n') {
        buf[rc - 1] = '\0';
      }
      return;
    }
  }
  strcpy(buf, default_value);
}

void drop_capabilities() {
  __user_cap_header_struct capheader;
  memset(&capheader, 0, sizeof(capheader));
  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;

  __user_cap_data_struct capdata[2];
  memset(&capdata, 0, sizeof(capdata));

  if (capset(&capheader, &capdata[0]) == -1) {
    PLOG(FATAL) << "failed to drop capabilities";
  }

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    PLOG(FATAL) << "failed to set PR_SET_NO_NEW_PRIVS";
  }
}

bool signal_has_si_addr(int si_signo, int si_code) {
  // Manually sent signals won't have si_addr.
  if (si_code == SI_USER || si_code == SI_QUEUE || si_code == SI_TKILL) {
    return false;
  }

  switch (si_signo) {
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
    case SIGSEGV:
    case SIGTRAP:
      return true;
    default:
      return false;
  }
}

const char* get_signame(int sig) {
  switch (sig) {
    case SIGABRT: return "SIGABRT";
    case SIGBUS: return "SIGBUS";
    case SIGFPE: return "SIGFPE";
    case SIGILL: return "SIGILL";
    case SIGSEGV: return "SIGSEGV";
#if defined(SIGSTKFLT)
    case SIGSTKFLT: return "SIGSTKFLT";
#endif
    case SIGSTOP: return "SIGSTOP";
    case SIGSYS: return "SIGSYS";
    case SIGTRAP: return "SIGTRAP";
    case DEBUGGER_SIGNAL: return "<debuggerd signal>";
    default: return "?";
  }
}

const char* get_sigcode(int signo, int code) {
  // Try the signal-specific codes...
  switch (signo) {
    case SIGILL:
      switch (code) {
        case ILL_ILLOPC: return "ILL_ILLOPC";
        case ILL_ILLOPN: return "ILL_ILLOPN";
        case ILL_ILLADR: return "ILL_ILLADR";
        case ILL_ILLTRP: return "ILL_ILLTRP";
        case ILL_PRVOPC: return "ILL_PRVOPC";
        case ILL_PRVREG: return "ILL_PRVREG";
        case ILL_COPROC: return "ILL_COPROC";
        case ILL_BADSTK: return "ILL_BADSTK";
      }
      static_assert(NSIGILL == ILL_BADSTK, "missing ILL_* si_code");
      break;
    case SIGBUS:
      switch (code) {
        case BUS_ADRALN: return "BUS_ADRALN";
        case BUS_ADRERR: return "BUS_ADRERR";
        case BUS_OBJERR: return "BUS_OBJERR";
        case BUS_MCEERR_AR: return "BUS_MCEERR_AR";
        case BUS_MCEERR_AO: return "BUS_MCEERR_AO";
      }
      static_assert(NSIGBUS == BUS_MCEERR_AO, "missing BUS_* si_code");
      break;
    case SIGFPE:
      switch (code) {
        case FPE_INTDIV: return "FPE_INTDIV";
        case FPE_INTOVF: return "FPE_INTOVF";
        case FPE_FLTDIV: return "FPE_FLTDIV";
        case FPE_FLTOVF: return "FPE_FLTOVF";
        case FPE_FLTUND: return "FPE_FLTUND";
        case FPE_FLTRES: return "FPE_FLTRES";
        case FPE_FLTINV: return "FPE_FLTINV";
        case FPE_FLTSUB: return "FPE_FLTSUB";
      }
      static_assert(NSIGFPE == FPE_FLTSUB, "missing FPE_* si_code");
      break;
    case SIGSEGV:
      switch (code) {
        case SEGV_MAPERR: return "SEGV_MAPERR";
        case SEGV_ACCERR: return "SEGV_ACCERR";
#if defined(SEGV_BNDERR)
        case SEGV_BNDERR: return "SEGV_BNDERR";
#endif
#if defined(SEGV_PKUERR)
        case SEGV_PKUERR: return "SEGV_PKUERR";
#endif
      }
#if defined(SEGV_PKUERR)
      static_assert(NSIGSEGV == SEGV_PKUERR, "missing SEGV_* si_code");
#elif defined(SEGV_BNDERR)
      static_assert(NSIGSEGV == SEGV_BNDERR, "missing SEGV_* si_code");
#else
      static_assert(NSIGSEGV == SEGV_ACCERR, "missing SEGV_* si_code");
#endif
      break;
#if defined(SYS_SECCOMP) // Our glibc is too old, and we build this for the host too.
    case SIGSYS:
      switch (code) {
        case SYS_SECCOMP: return "SYS_SECCOMP";
      }
      static_assert(NSIGSYS == SYS_SECCOMP, "missing SYS_* si_code");
      break;
#endif
    case SIGTRAP:
      switch (code) {
        case TRAP_BRKPT: return "TRAP_BRKPT";
        case TRAP_TRACE: return "TRAP_TRACE";
        case TRAP_BRANCH: return "TRAP_BRANCH";
        case TRAP_HWBKPT: return "TRAP_HWBKPT";
      }
      if ((code & 0xff) == SIGTRAP) {
        switch ((code >> 8) & 0xff) {
          case PTRACE_EVENT_FORK:
            return "PTRACE_EVENT_FORK";
          case PTRACE_EVENT_VFORK:
            return "PTRACE_EVENT_VFORK";
          case PTRACE_EVENT_CLONE:
            return "PTRACE_EVENT_CLONE";
          case PTRACE_EVENT_EXEC:
            return "PTRACE_EVENT_EXEC";
          case PTRACE_EVENT_VFORK_DONE:
            return "PTRACE_EVENT_VFORK_DONE";
          case PTRACE_EVENT_EXIT:
            return "PTRACE_EVENT_EXIT";
          case PTRACE_EVENT_SECCOMP:
            return "PTRACE_EVENT_SECCOMP";
          case PTRACE_EVENT_STOP:
            return "PTRACE_EVENT_STOP";
        }
      }
      static_assert(NSIGTRAP == TRAP_HWBKPT, "missing TRAP_* si_code");
      break;
  }
  // Then the other codes...
  switch (code) {
    case SI_USER: return "SI_USER";
    case SI_KERNEL: return "SI_KERNEL";
    case SI_QUEUE: return "SI_QUEUE";
    case SI_TIMER: return "SI_TIMER";
    case SI_MESGQ: return "SI_MESGQ";
    case SI_ASYNCIO: return "SI_ASYNCIO";
    case SI_SIGIO: return "SI_SIGIO";
    case SI_TKILL: return "SI_TKILL";
    case SI_DETHREAD: return "SI_DETHREAD";
  }
  // Then give up...
  return "?";
}

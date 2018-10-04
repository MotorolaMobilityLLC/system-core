/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#define LOG_TAG "DEBUG"

#include "libdebuggerd/tombstone.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <time.h>

#include <memory>
#include <string>
#include <elf.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <android/log.h>
#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>
#include <log/log.h>
#include <log/logprint.h>
#include <private/android_filesystem_config.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

// Needed to get DEBUGGER_SIGNAL.
#include "debuggerd/handler.h"

#include "libdebuggerd/backtrace.h"
#include "libdebuggerd/elf_utils.h"
#include "libdebuggerd/open_files_list.h"
#include "libdebuggerd/utility.h"

using android::base::GetBoolProperty;
using android::base::GetProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

using unwindstack::Memory;
using unwindstack::Regs;

using namespace std::literals::string_literals;

#define STACK_WORDS 16

static void dump_header_info(log_t* log) {
  auto fingerprint = GetProperty("ro.build.fingerprint", "unknown");
  auto revision = GetProperty("ro.revision", "unknown");

  _LOG(log, logtype::HEADER, "Build fingerprint: '%s'\n", fingerprint.c_str());
  _LOG(log, logtype::HEADER, "Revision: '%s'\n", revision.c_str());
  _LOG(log, logtype::HEADER, "ABI: '%s'\n", ABI_STRING);
}

static void dump_probable_cause(log_t* log, const siginfo_t* si) {
  std::string cause;
  if (si->si_signo == SIGSEGV && si->si_code == SEGV_MAPERR) {
    if (si->si_addr < reinterpret_cast<void*>(4096)) {
      cause = StringPrintf("null pointer dereference");
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0ffc)) {
      cause = "call to kuser_helper_version";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0fe0)) {
      cause = "call to kuser_get_tls";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0fc0)) {
      cause = "call to kuser_cmpxchg";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0fa0)) {
      cause = "call to kuser_memory_barrier";
    } else if (si->si_addr == reinterpret_cast<void*>(0xffff0f60)) {
      cause = "call to kuser_cmpxchg64";
    }
  } else if (si->si_signo == SIGSYS && si->si_code == SYS_SECCOMP) {
    cause = StringPrintf("seccomp prevented call to disallowed %s system call %d", ABI_STRING,
                         si->si_syscall);
  }

  if (!cause.empty()) _LOG(log, logtype::HEADER, "Cause: %s\n", cause.c_str());
}

static void dump_signal_info(log_t* log, const siginfo_t* si) {
  char addr_desc[32]; // ", fault addr 0x1234"
  if (signal_has_si_addr(si->si_signo, si->si_code)) {
    snprintf(addr_desc, sizeof(addr_desc), "%p", si->si_addr);
  } else {
    snprintf(addr_desc, sizeof(addr_desc), "--------");
  }

  _LOG(log, logtype::HEADER, "signal %d (%s), code %d (%s), fault addr %s\n", si->si_signo,
       get_signame(si->si_signo), si->si_code, get_sigcode(si->si_signo, si->si_code), addr_desc);

  dump_probable_cause(log, si);
}

static void dump_thread_info(log_t* log, const ThreadInfo& thread_info) {
  // Blacklist logd, logd.reader, logd.writer, logd.auditd, logd.control ...
  // TODO: Why is this controlled by thread name?
  if (thread_info.thread_name == "logd" ||
      android::base::StartsWith(thread_info.thread_name, "logd.")) {
    log->should_retrieve_logcat = false;
  }

  _LOG(log, logtype::HEADER, "pid: %d, tid: %d, name: %s  >>> %s <<<\n", thread_info.pid,
       thread_info.tid, thread_info.thread_name.c_str(), thread_info.process_name.c_str());
}

static void dump_stack_segment(log_t* log, BacktraceMap* backtrace_map, Memory* process_memory,
                               uint64_t* sp, size_t words, int label) {
  // Read the data all at once.
  word_t stack_data[words];

  // TODO: Do we need to word align this for crashes caused by a misaligned sp?
  //       The process_vm_readv implementation of Memory should handle this appropriately?
  size_t bytes_read = process_memory->Read(*sp, stack_data, sizeof(word_t) * words);
  words = bytes_read / sizeof(word_t);
  std::string line;
  for (size_t i = 0; i < words; i++) {
    line = "    ";
    if (i == 0 && label >= 0) {
      // Print the label once.
      line += StringPrintf("#%02d  ", label);
    } else {
      line += "     ";
    }
    line += StringPrintf("%" PRIPTR "  %" PRIPTR, *sp, static_cast<uint64_t>(stack_data[i]));

    backtrace_map_t map;
    backtrace_map->FillIn(stack_data[i], &map);
    std::string map_name{map.Name()};
    if (BacktraceMap::IsValid(map) && !map_name.empty()) {
      line += "  " + map_name;
      uint64_t offset = 0;
      std::string func_name = backtrace_map->GetFunctionName(stack_data[i], &offset);
      if (!func_name.empty()) {
        line += " (" + func_name;
        if (offset) {
          line += StringPrintf("+%" PRIu64, offset);
        }
        line += ')';
      }
    }
    _LOG(log, logtype::STACK, "%s\n", line.c_str());

    *sp += sizeof(word_t);
  }
}

static void dump_stack(log_t* log, BacktraceMap* backtrace_map, Memory* process_memory,
                       std::vector<backtrace_frame_data_t>& frames) {
  size_t first = 0, last;
  for (size_t i = 0; i < frames.size(); i++) {
    const backtrace_frame_data_t& frame = frames[i];
    if (frame.sp) {
      if (!first) {
        first = i+1;
      }
      last = i;
    }
  }

  if (!first) {
    return;
  }
  first--;

  // Dump a few words before the first frame.
  uint64_t sp = frames[first].sp - STACK_WORDS * sizeof(word_t);
  dump_stack_segment(log, backtrace_map, process_memory, &sp, STACK_WORDS, -1);

  // Dump a few words from all successive frames.
  // Only log the first 3 frames, put the rest in the tombstone.
  for (size_t i = first; i <= last; i++) {
    const backtrace_frame_data_t* frame = &frames[i];
    if (sp != frame->sp) {
      _LOG(log, logtype::STACK, "         ........  ........\n");
      sp = frame->sp;
    }
    if (i == last) {
      dump_stack_segment(log, backtrace_map, process_memory, &sp, STACK_WORDS, i);
      if (sp < frame->sp + frame->stack_size) {
        _LOG(log, logtype::STACK, "         ........  ........\n");
      }
    } else {
      size_t words = frame->stack_size / sizeof(word_t);
      if (words == 0) {
        words = 1;
      } else if (words > STACK_WORDS) {
        words = STACK_WORDS;
      }
      dump_stack_segment(log, backtrace_map, process_memory, &sp, words, i);
    }
  }
}

static std::string get_addr_string(uint64_t addr) {
  std::string addr_str;
#if defined(__LP64__)
  addr_str = StringPrintf("%08x'%08x",
                          static_cast<uint32_t>(addr >> 32),
                          static_cast<uint32_t>(addr & 0xffffffff));
#else
  addr_str = StringPrintf("%08x", static_cast<uint32_t>(addr));
#endif
  return addr_str;
}

static void dump_abort_message(log_t* log, Memory* process_memory, uint64_t address) {
  if (address == 0) {
    return;
  }

  size_t length;
  if (!process_memory->ReadFully(address, &length, sizeof(length))) {
    _LOG(log, logtype::HEADER, "Failed to read abort message header: %s\n", strerror(errno));
    return;
  }

  char msg[512];
  if (length >= sizeof(msg)) {
    _LOG(log, logtype::HEADER, "Abort message too long: claimed length = %zd\n", length);
    return;
  }

  if (!process_memory->ReadFully(address + sizeof(length), msg, length)) {
    _LOG(log, logtype::HEADER, "Failed to read abort message: %s\n", strerror(errno));
    return;
  }

  msg[length] = '\0';
  _LOG(log, logtype::HEADER, "Abort message: '%s'\n", msg);
}

static void dump_all_maps(log_t* log, BacktraceMap* map, Memory* process_memory, uint64_t addr) {
  bool print_fault_address_marker = addr;

  ScopedBacktraceMapIteratorLock lock(map);
  _LOG(log, logtype::MAPS,
       "\n"
       "memory map (%zu entr%s):",
       map->size(), map->size() == 1 ? "y" : "ies");
  if (print_fault_address_marker) {
    if (map->begin() != map->end() && addr < (*map->begin())->start) {
      _LOG(log, logtype::MAPS, "\n--->Fault address falls at %s before any mapped regions\n",
           get_addr_string(addr).c_str());
      print_fault_address_marker = false;
    } else {
      _LOG(log, logtype::MAPS, " (fault address prefixed with --->)\n");
    }
  } else {
    _LOG(log, logtype::MAPS, "\n");
  }

  std::string line;
  for (auto it = map->begin(); it != map->end(); ++it) {
    const backtrace_map_t* entry = *it;
    line = "    ";
    if (print_fault_address_marker) {
      if (addr < entry->start) {
        _LOG(log, logtype::MAPS, "--->Fault address falls at %s between mapped regions\n",
             get_addr_string(addr).c_str());
        print_fault_address_marker = false;
      } else if (addr >= entry->start && addr < entry->end) {
        line = "--->";
        print_fault_address_marker = false;
      }
    }
    line += get_addr_string(entry->start) + '-' + get_addr_string(entry->end - 1) + ' ';
    if (entry->flags & PROT_READ) {
      line += 'r';
    } else {
      line += '-';
    }
    if (entry->flags & PROT_WRITE) {
      line += 'w';
    } else {
      line += '-';
    }
    if (entry->flags & PROT_EXEC) {
      line += 'x';
    } else {
      line += '-';
    }
    line += StringPrintf("  %8" PRIx64 "  %8" PRIx64, entry->offset, entry->end - entry->start);
    bool space_needed = true;
    if (entry->name.length() > 0) {
      space_needed = false;
      line += "  " + entry->name;
      std::string build_id;
      if ((entry->flags & PROT_READ) && elf_get_build_id(process_memory, entry->start, &build_id)) {
        line += " (BuildId: " + build_id + ")";
      }
    }
    if (entry->load_bias != 0) {
      if (space_needed) {
        line += ' ';
      }
      line += StringPrintf(" (load bias 0x%" PRIx64 ")", entry->load_bias);
    }
    _LOG(log, logtype::MAPS, "%s\n", line.c_str());
  }
  if (print_fault_address_marker) {
    _LOG(log, logtype::MAPS, "--->Fault address falls at %s after any mapped regions\n",
         get_addr_string(addr).c_str());
  }
}

void dump_backtrace(log_t* log, std::vector<backtrace_frame_data_t>& frames, const char* prefix) {
  for (auto& frame : frames) {
    _LOG(log, logtype::BACKTRACE, "%s%s\n", prefix, Backtrace::FormatFrameData(&frame).c_str());
  }
}

static void print_register_row(log_t* log,
                               const std::vector<std::pair<std::string, uint64_t>>& registers) {
  std::string output;
  for (auto& [name, value] : registers) {
    output += android::base::StringPrintf("  %-3s %0*" PRIx64, name.c_str(),
                                          static_cast<int>(2 * sizeof(void*)),
                                          static_cast<uint64_t>(value));
  }

  _LOG(log, logtype::REGISTERS, "  %s\n", output.c_str());
}

void dump_registers(log_t* log, Regs* regs) {
  // Split lr/sp/pc into their own special row.
  static constexpr size_t column_count = 4;
  std::vector<std::pair<std::string, uint64_t>> current_row;
  std::vector<std::pair<std::string, uint64_t>> special_row;

#if defined(__arm__) || defined(__aarch64__)
  static constexpr const char* special_registers[] = {"ip", "lr", "sp", "pc"};
#elif defined(__i386__)
  static constexpr const char* special_registers[] = {"ebp", "esp", "eip"};
#elif defined(__x86_64__)
  static constexpr const char* special_registers[] = {"rbp", "rsp", "rip"};
#else
  static constexpr const char* special_registers[] = {};
#endif

  regs->IterateRegisters([log, &current_row, &special_row](const char* name, uint64_t value) {
    auto row = &current_row;
    for (const char* special_name : special_registers) {
      if (strcmp(special_name, name) == 0) {
        row = &special_row;
        break;
      }
    }

    row->emplace_back(name, value);
    if (current_row.size() == column_count) {
      print_register_row(log, current_row);
      current_row.clear();
    }
  });

  if (!current_row.empty()) {
    print_register_row(log, current_row);
  }

  print_register_row(log, special_row);
}

void dump_memory_and_code(log_t* log, BacktraceMap* map, Memory* memory, Regs* regs) {
  regs->IterateRegisters([log, map, memory](const char* reg_name, uint64_t reg_value) {
    std::string label{"memory near "s + reg_name};
    if (map) {
      backtrace_map_t map_info;
      map->FillIn(reg_value, &map_info);
      std::string map_name{map_info.Name()};
      if (!map_name.empty()) label += " (" + map_info.Name() + ")";
    }
    dump_memory(log, memory, reg_value, label);
  });
}

static bool dump_thread(log_t* log, BacktraceMap* map, Memory* process_memory,
                        const ThreadInfo& thread_info, uint64_t abort_msg_address,
                        bool primary_thread) {
  UNUSED(process_memory);
  log->current_tid = thread_info.tid;
  if (!primary_thread) {
    _LOG(log, logtype::THREAD, "--- --- --- --- --- --- --- --- --- --- --- --- --- --- --- ---\n");
  }
  dump_thread_info(log, thread_info);

  if (thread_info.siginfo) {
    dump_signal_info(log, thread_info.siginfo);
  }

  if (primary_thread) {
    dump_abort_message(log, process_memory, abort_msg_address);
  }

  dump_registers(log, thread_info.registers.get());

  // Unwind will mutate the registers, so make a copy first.
  std::unique_ptr<Regs> regs_copy(thread_info.registers->Clone());
  std::vector<backtrace_frame_data_t> frames;
  if (!Backtrace::Unwind(regs_copy.get(), map, &frames, 0, nullptr)) {
    _LOG(log, logtype::THREAD, "Failed to unwind");
    return false;
  }

  if (!frames.empty()) {
    _LOG(log, logtype::BACKTRACE, "\nbacktrace:\n");
    dump_backtrace(log, frames, "    ");

    _LOG(log, logtype::STACK, "\nstack:\n");
    dump_stack(log, map, process_memory, frames);
  }

  if (primary_thread) {
    dump_memory_and_code(log, map, process_memory, thread_info.registers.get());
    if (map) {
      uint64_t addr = 0;
      siginfo_t* si = thread_info.siginfo;
      if (signal_has_si_addr(si->si_signo, si->si_code)) {
        addr = reinterpret_cast<uint64_t>(si->si_addr);
      }
      dump_all_maps(log, map, process_memory, addr);
    }
  }

  log->current_tid = log->crashed_tid;
  return true;
}

// Reads the contents of the specified log device, filters out the entries
// that don't match the specified pid, and writes them to the tombstone file.
//
// If "tail" is non-zero, log the last "tail" number of lines.
static EventTagMap* g_eventTagMap = NULL;

static void dump_log_file(log_t* log, pid_t pid, const char* filename, unsigned int tail) {
  bool first = true;
  struct logger_list* logger_list;

  if (!log->should_retrieve_logcat) {
    return;
  }

  logger_list = android_logger_list_open(
      android_name_to_log_id(filename), ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, tail, pid);

  if (!logger_list) {
    ALOGE("Unable to open %s: %s\n", filename, strerror(errno));
    return;
  }

  struct log_msg log_entry;

  while (true) {
    ssize_t actual = android_logger_list_read(logger_list, &log_entry);
    struct logger_entry* entry;

    if (actual < 0) {
      if (actual == -EINTR) {
        // interrupted by signal, retry
        continue;
      } else if (actual == -EAGAIN) {
        // non-blocking EOF; we're done
        break;
      } else {
        ALOGE("Error while reading log: %s\n", strerror(-actual));
        break;
      }
    } else if (actual == 0) {
      ALOGE("Got zero bytes while reading log: %s\n", strerror(errno));
      break;
    }

    // NOTE: if you ALOGV something here, this will spin forever,
    // because you will be writing as fast as you're reading.  Any
    // high-frequency debug diagnostics should just be written to
    // the tombstone file.

    entry = &log_entry.entry_v1;

    if (first) {
      _LOG(log, logtype::LOGS, "--------- %slog %s\n",
        tail ? "tail end of " : "", filename);
      first = false;
    }

    // Msg format is: <priority:1><tag:N>\0<message:N>\0
    //
    // We want to display it in the same format as "logcat -v threadtime"
    // (although in this case the pid is redundant).
    static const char* kPrioChars = "!.VDIWEFS";
    unsigned hdr_size = log_entry.entry.hdr_size;
    if (!hdr_size) {
      hdr_size = sizeof(log_entry.entry_v1);
    }
    if ((hdr_size < sizeof(log_entry.entry_v1)) ||
        (hdr_size > sizeof(log_entry.entry))) {
      continue;
    }
    char* msg = reinterpret_cast<char*>(log_entry.buf) + hdr_size;

    char timeBuf[32];
    time_t sec = static_cast<time_t>(entry->sec);
    struct tm tmBuf;
    struct tm* ptm;
    ptm = localtime_r(&sec, &tmBuf);
    strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

    if (log_entry.id() == LOG_ID_EVENTS) {
      if (!g_eventTagMap) {
        g_eventTagMap = android_openEventTagMap(NULL);
      }
      AndroidLogEntry e;
      char buf[512];
      android_log_processBinaryLogBuffer(entry, &e, g_eventTagMap, buf, sizeof(buf));
      _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8.*s: %s\n",
         timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
         'I', (int)e.tagLen, e.tag, e.message);
      continue;
    }

    unsigned char prio = msg[0];
    char* tag = msg + 1;
    msg = tag + strlen(tag) + 1;

    // consume any trailing newlines
    char* nl = msg + strlen(msg) - 1;
    while (nl >= msg && *nl == '\n') {
      *nl-- = '\0';
    }

    char prioChar = (prio < strlen(kPrioChars) ? kPrioChars[prio] : '?');

    // Look for line breaks ('\n') and display each text line
    // on a separate line, prefixed with the header, like logcat does.
    do {
      nl = strchr(msg, '\n');
      if (nl) {
        *nl = '\0';
        ++nl;
      }

      _LOG(log, logtype::LOGS, "%s.%03d %5d %5d %c %-8s: %s\n",
         timeBuf, entry->nsec / 1000000, entry->pid, entry->tid,
         prioChar, tag, msg);
    } while ((msg = nl));
  }

  android_logger_list_free(logger_list);
}

// Dumps the logs generated by the specified pid to the tombstone, from both
// "system" and "main" log devices.  Ideally we'd interleave the output.
static void dump_logs(log_t* log, pid_t pid, unsigned int tail) {
  if (pid == getpid()) {
    // Cowardly refuse to dump logs while we're running in-process.
    return;
  }

  dump_log_file(log, pid, "system", tail);
  dump_log_file(log, pid, "main", tail);
}

void engrave_tombstone_ucontext(int tombstone_fd, uint64_t abort_msg_address, siginfo_t* siginfo,
                                ucontext_t* ucontext) {
  pid_t pid = getpid();
  pid_t tid = gettid();

  log_t log;
  log.current_tid = tid;
  log.crashed_tid = tid;
  log.tfd = tombstone_fd;
  log.amfd_data = nullptr;

  char thread_name[16];
  char process_name[128];

  read_with_default("/proc/self/comm", thread_name, sizeof(thread_name), "<unknown>");
  read_with_default("/proc/self/cmdline", process_name, sizeof(process_name), "<unknown>");

  std::unique_ptr<Regs> regs(Regs::CreateFromUcontext(Regs::CurrentArch(), ucontext));

  std::map<pid_t, ThreadInfo> threads;
  threads[gettid()] = ThreadInfo{
      .registers = std::move(regs),
      .tid = tid,
      .thread_name = thread_name,
      .pid = pid,
      .process_name = process_name,
      .siginfo = siginfo,
  };

  std::unique_ptr<BacktraceMap> backtrace_map(BacktraceMap::Create(getpid(), false));
  if (!backtrace_map) {
    ALOGE("failed to create backtrace map");
    _exit(1);
  }

  std::shared_ptr<Memory> process_memory = backtrace_map->GetProcessMemory();
  engrave_tombstone(unique_fd(dup(tombstone_fd)), backtrace_map.get(), process_memory.get(),
                    threads, tid, abort_msg_address, nullptr, nullptr);
}

int crash_dump_fd_write(int fd, char *buffer, size_t size)
{
  int written_bytes=0;

  while (size) {
    written_bytes = write(fd, buffer, size);
    if (written_bytes < 0)
    {
      return written_bytes;
    }
    buffer = (char *)(buffer + written_bytes);
    size = size - written_bytes;
  }
  return 0;
}


#define CRASH_DUMP_MAX_REGION_COUNT 200
#define CRASH_DUMP_SCRATCH_SIZE 0x10000
#define CRASH_DUMP_MAX_MAPS 50
void capture_crash_dump(unique_fd crash_dump_fd, BacktraceMap* map, Memory* process_memory, pid_t target_thread, const std::map<pid_t, ThreadInfo>& threads)
{
  uint32_t offset=0, index=0;
  uint64_t addr=0,first_sp=0, last_sp=0;;
  char *buffer, *pmem;
  size_t size, tmp_size, iter_size;
  int read_bytes;
  Elf64_Ehdr ehdr;
  Elf64_Phdr phdr[CRASH_DUMP_MAX_REGION_COUNT];
  uint32_t region_count=0;
  uint32_t map_index=0;
  char *scratch=new char[CRASH_DUMP_SCRATCH_SIZE];
  int fd = crash_dump_fd.get();
  std::string interested_maps[CRASH_DUMP_MAX_MAPS];
  UNUSED(target_thread);

  if (fd < 0) {
    ALOGE("Crash dump fd open failed\n");
    delete [] scratch;
    return;
  }

  if (!scratch) {
    ALOGE("Crash dump scratch space could not be allocated for size %x \n", (uint32_t)CRASH_DUMP_SCRATCH_SIZE);
    close(fd);
    return;
  }

  memset((void *)&ehdr, 0, sizeof(Elf64_Ehdr));
  memset((void *)&phdr, 0, (sizeof(Elf64_Phdr)*CRASH_DUMP_MAX_REGION_COUNT));
  memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_ident[EI_VERSION] = EV_CURRENT;
  ehdr.e_ident[EI_OSABI] = ELFOSABI_SYSV;
  ehdr.e_type = ET_CORE;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_phoff = sizeof(ehdr);
  ehdr.e_ehsize = sizeof(ehdr);
  ehdr.e_phentsize = sizeof(Elf64_Phdr);

  for (auto& [tid, thread_info] : threads) {
    if (region_count>=CRASH_DUMP_MAX_REGION_COUNT) {
      break;
    }
    std::vector<backtrace_frame_data_t> frames;
    BacktraceUnwindError error;
    //ALOGE("Triggering Unwind %p\n", (void *)&thread_info);
    Backtrace::Unwind(thread_info.registers.get(), map, &frames, 0, nullptr, &error);
    if (error.error_code!=BACKTRACE_UNWIND_NO_ERROR)
    {
      ALOGE("Unwind error %x\n", (uint32_t)error.error_code);
      continue;
    }
    if (!frames.empty()) {
      first_sp=0;
      last_sp=0;
      //ALOGE("Frame size %x\n", (uint32_t)frames.size());
      for (size_t frame_index = 0; frame_index < frames.size(); frame_index++) {
        const backtrace_frame_data_t& frame = frames[frame_index];
        /*Get the maps from callstacks of all the threads in process*/
        if (BacktraceMap::IsValid(frame.map) && (map_index < CRASH_DUMP_MAX_MAPS) && (frame.map.name.length()>0)) {
          for (index = 0; index < map_index; index++) {
            if (strcmp((const char *)interested_maps[index].c_str(), frame.map.name.c_str()) == 0) {
              //ALOGE("Interested MAP parsed %s\n", frame.map.name.c_str());
              break;
            }
          }
          if (index==map_index) {
            interested_maps[map_index].assign(frame.map.name);
            //ALOGE("Interested MAP saved %s\n", interested_maps[map_index].c_str());
            map_index++;
          }
        }
        if (frame.sp) {
          if (!first_sp) {
            first_sp = (uint64_t)frame.sp;
          }
          last_sp = (uint64_t)frame.sp;
        }
      }
      //ALOGE("Frame Stack first sp %p last sp %p\n", (void *)first_sp, (void *)last_sp);
      if (first_sp && last_sp && (last_sp>first_sp)) {
        phdr[region_count].p_type = PT_LOAD;
        phdr[region_count].p_vaddr = first_sp;
        phdr[region_count].p_paddr = first_sp;
        phdr[region_count].p_filesz = phdr[region_count].p_memsz = (size_t)(last_sp-first_sp);
        phdr[region_count].p_flags = PF_R | PF_W;
        region_count++;
      }
    }
  }

  /*Parse the maps to identify regions to be dumped*/
  for (auto it = map->begin(); (it != map->end())&&(region_count < CRASH_DUMP_MAX_REGION_COUNT); ++it) {
    const backtrace_map_t* entry = *it;
    size = entry->end - entry->start;
    if (!((entry->flags & PROT_WRITE)&&(entry->name.length()>0)&&(size>0))) {
      continue;
    }

    for (index = 0; index < map_index; index++) {
      if (strstr((const char *)entry->name.c_str(), interested_maps[index].c_str())) {
        //ALOGE("Interested MAP found %s\n", entry->name.c_str());
        break;
      }
    }

    if ((index<map_index) ||
         strstr((const char *)entry->name.c_str(), "libc_malloc") ||
         strstr((const char *)entry->name.c_str(), "anon:.bss") ||
         strstr((const char *)entry->name.c_str(), "libc.so")) {
      //ALOGE("MAP found %p size %x\n", (void *)entry->start, (uint32_t)size);
      phdr[region_count].p_type = PT_LOAD;
      phdr[region_count].p_vaddr = entry->start;
      phdr[region_count].p_paddr = entry->start;
      phdr[region_count].p_filesz = phdr[region_count].p_memsz = size;
      phdr[region_count].p_flags = PF_R | PF_W;
      region_count++;
    }
  }


  ALOGE("Crash dump elf region count %d\n", region_count);
  offset = sizeof(Elf64_Ehdr)+(sizeof(Elf64_Phdr)*region_count/*number of headers*/);
  ehdr.e_phnum = region_count;

  for (index=0; index < region_count; index++) {
    phdr[index].p_offset = offset;
    offset += phdr[index].p_filesz;
  }

  /*Write ELF header*/
  if (crash_dump_fd_write(fd, (char *)&ehdr, sizeof(Elf64_Ehdr)))
  {
    delete [] scratch;
    close(fd);
    return;
  }

  /*Write Program headers*/
  if (crash_dump_fd_write(fd, (char *)&phdr, (sizeof(Elf64_Phdr)*region_count)))
  {
    delete [] scratch;
    close(fd);
    return;
  }

  /*Read actual data and append to the BT dump file*/
  for (index=0; index< region_count ; index++) {
    addr=phdr[index].p_vaddr;
    size=phdr[index].p_memsz;

    while (size) {
      pmem = scratch;
      if (size > CRASH_DUMP_SCRATCH_SIZE)
      {
        size-=CRASH_DUMP_SCRATCH_SIZE;
        tmp_size = CRASH_DUMP_SCRATCH_SIZE;
      } else {
        tmp_size = size;
        size=0;
      }

      /*Read from PID memory using Backtrace*/
      read_bytes=0;
      iter_size = tmp_size;
      buffer = pmem;
      while (iter_size) {
        read_bytes = process_memory->Read(static_cast<uintptr_t>(addr) , reinterpret_cast<uint8_t*>(buffer), iter_size);
        //ALOGE("Process memory %p read bytes %x\n", (void *)addr, read_bytes);
        if (read_bytes < 0)
        {
          delete [] scratch;
          close(fd);
          return;
        }
        buffer = (char *)(buffer + read_bytes);
        iter_size = iter_size - read_bytes;
        addr = addr + read_bytes;
      }

      /*Write onto BT DUMP file*/
      if (crash_dump_fd_write(fd, pmem, tmp_size))
      {
        delete [] scratch;
        close(fd);
        return;
      }
    }
  }
  delete [] scratch;
  close(fd);
  return;
}

void engrave_tombstone(unique_fd output_fd, BacktraceMap* map, Memory* process_memory,
                       const std::map<pid_t, ThreadInfo>& threads, pid_t target_thread,
                       uint64_t abort_msg_address, OpenFilesList* open_files,
                       std::string* amfd_data) {
  // don't copy log messages to tombstone unless this is a dev device
  bool want_logs = android::base::GetBoolProperty("ro.debuggable", false);

  log_t log;
  log.current_tid = target_thread;
  log.crashed_tid = target_thread;
  log.tfd = output_fd.get();
  log.amfd_data = amfd_data;

  _LOG(&log, logtype::HEADER, "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n");
  dump_header_info(&log);

  auto it = threads.find(target_thread);
  if (it == threads.end()) {
    LOG(FATAL) << "failed to find target thread";
  }
  dump_thread(&log, map, process_memory, it->second, abort_msg_address, true);

  if (want_logs) {
    dump_logs(&log, it->second.pid, 50);
  }

  for (auto& [tid, thread_info] : threads) {
    if (tid == target_thread) {
      continue;
    }

    dump_thread(&log, map, process_memory, thread_info, 0, false);
  }

  if (open_files) {
    _LOG(&log, logtype::OPEN_FILES, "\nopen files:\n");
    dump_open_files_list(&log, *open_files, "    ");
  }

  if (want_logs) {
    dump_logs(&log, it->second.pid, 0);
  }
}

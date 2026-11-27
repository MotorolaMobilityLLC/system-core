/*
 * Copyright 2016, The Android Open Source Project
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

#include "util.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <functional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "protocol.h"

constexpr const char kUnknown[] = "<unknown>";

std::vector<std::string> get_command_line(pid_t pid) {
  std::vector<std::string> result;

  std::string cmdline;
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/cmdline", pid), &cmdline);

  auto it = cmdline.cbegin();
  while (it != cmdline.cend()) {
    // string::iterator is a wrapped type, not a raw char*.
    auto terminator = std::find(it, cmdline.cend(), '\0');
    result.emplace_back(it, terminator);
    it = std::find_if(terminator, cmdline.cend(), [](char c) { return c != '\0'; });
  }
  if (result.empty()) {
    return {kUnknown};
  }

  return result;
}

std::string get_process_name(pid_t pid) {
  std::string result(kUnknown);
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/cmdline", pid), &result);
  // We only want the name, not the whole command line, so truncate at the first NUL.
  return result.c_str();
}

std::string get_thread_name(pid_t tid) {
  std::string result(kUnknown);
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/comm", tid), &result);
  return android::base::Trim(result);
}

std::string get_executable_name(pid_t pid) {
  std::string result;
  if (!android::base::Readlink(android::base::StringPrintf("/proc/%d/exe", pid), &result)) {
    return kUnknown;
  }
  return result;
}

std::string get_timestamp() {
  timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  tm tm;
  localtime_r(&ts.tv_sec, &tm);

  char buf[strlen("1970-01-01 00:00:00.123456789+0830") + 1];
  char* s = buf;
  size_t sz = sizeof(buf), n;
  n = strftime(s, sz, "%F %H:%M", &tm), s += n, sz -= n;
  n = snprintf(s, sz, ":%02d.%09ld", tm.tm_sec, ts.tv_nsec), s += n, sz -= n;
  n = strftime(s, sz, "%z", &tm), s += n, sz -= n;
  return buf;
}

bool iterate_tids(pid_t pid, std::function<void(pid_t)> callback) {
  char buf[BUFSIZ];
  snprintf(buf, sizeof(buf), "/proc/%d/task", pid);
  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(buf), closedir);
  if (dir == nullptr) {
    return false;
  }

  struct dirent* entry;
  while ((entry = readdir(dir.get())) != nullptr) {
    pid_t tid = atoi(entry->d_name);
    if (tid == 0) {
      continue;
    }
    callback(tid);
  }
  return true;
}

bool is_microdroid() {
  return android::base::GetProperty("ro.hardware", "") == "microdroid";
}

void get_vmflags(pid_t pid, std::unordered_map<uint64_t, std::string>& vmflags) {
  // See if any maps have other flags enabled. The only way to get this
  // information is to read the smaps file and check the VmFlags field.
  std::string smaps_str(android::base::StringPrintf("/proc/%d/smaps", pid));
  FILE* smaps_file = fopen(smaps_str.c_str(), "re");
  if (smaps_file == nullptr) {
    return;
  }
  // Choose a size that should be big enough for all lines and avoid ever
  // doing a realloc.
  constexpr size_t kLineSize = 200;
  char* buffer = reinterpret_cast<char*>(malloc(kLineSize));
  size_t allocated_length = kLineSize;
  uint64_t map_start = 0;
  while (true) {
    ssize_t buffer_len = getline(&buffer, &allocated_length, smaps_file);
    if (buffer_len <= 0) {
      break;
    }
    char* end = nullptr;
    uint64_t tmp_start = strtoul(buffer, &end, 16);
    if (end != nullptr && *end == '-') {
      map_start = tmp_start;
      continue;
    }
    constexpr char kVmFlagsStr[] = "VmFlags:";
    constexpr size_t kVmFlagsStrLen = std::char_traits<char>::length(kVmFlagsStr);
    if (strncmp(buffer, kVmFlagsStr, kVmFlagsStrLen) == 0) {
      // Skip spaces in front of string.
      size_t flag_start = kVmFlagsStrLen + 1;
      while (isspace(buffer[flag_start])) {
        ++flag_start;
      }
      // Remove spaces at end of string.
      while (isspace(buffer[--buffer_len])) {
        buffer[buffer_len] = '\0';
      }
      vmflags[map_start] = std::string(&buffer[flag_start]);
      map_start = 0;
    }
  }
  free(buffer);
  fclose(smaps_file);
}

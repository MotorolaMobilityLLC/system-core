/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "bootchart.h"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <fstream>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

using android::base::StringPrintf;
using android::base::boot_clock;
using android::base::GetBoolProperty;
using android::base::ReadFileToString;
using namespace std::chrono_literals;

namespace android {
namespace init {

static std::optional<std::thread> g_bootcharting_thread;

[[clang::no_destroy]] static std::mutex g_bootcharting_finished_mutex;
[[clang::no_destroy]] static std::condition_variable g_bootcharting_finished_cv;
static bool g_bootcharting_finished;

static std::string get_bootchart_path(std::string_view file) {
    static const bool early = GetBoolProperty("ro.boot.bootchart.enabled", false);
    return std::string(early ? "/dev/bootchart/" : "/data/bootchart/") + std::string(file);
}

static bool is_bootchart_enabled() {
    // Support bootchart start on early-init
    if (GetBoolProperty("ro.boot.bootchart.enabled", false)) {
        return true;
    }
    // Otherwise, fallback to start on post-fs-data
    // We don't care about the content, but we do care that /data/bootchart/enabled exists.
    std::string start;
    return ReadFileToString("/data/bootchart/enabled", &start);
}

static long long get_uptime_jiffies() {
    constexpr int64_t kNanosecondsPerJiffy = 10000000;
    boot_clock::time_point uptime = boot_clock::now();
    return uptime.time_since_epoch().count() / kNanosecondsPerJiffy;
}

static std::unique_ptr<FILE, decltype(&fclose)> fopen_unique(const char* filename,
                                                             const char* mode) {
  std::unique_ptr<FILE, decltype(&fclose)> result(fopen(filename, mode), fclose);
  if (!result) PLOG(ERROR) << "bootchart: failed to open " << filename;
  return result;
}

static std::string get_cpu_model() {
#if defined(__i386__) || defined(__x86_64__)
    static const char* kModelKey = "model name";
#elif defined(__arm__) || defined(__aarch64__)
    static const char* kModelKey = "Processor";
#else
    static const char* kModelKey = nullptr;
#endif

    if (kModelKey) {
        if (std::ifstream infile("/proc/cpuinfo"); infile.is_open()) {
            std::string line;
            while (std::getline(infile, line)) {
                if (android::base::StartsWith(line, kModelKey)) {
                    std::vector<std::string> parts = android::base::Split(line, ":");
                    if (parts.size() > 1) return android::base::Trim(parts[1]);
                }
            }
        }
    }

    utsname uts;
    if (uname(&uts) != -1) return uts.machine;
    return "unknown";
}

static void log_header() {
  char date[32];
  time_t now_t = time(NULL);
  struct tm now = *localtime(&now_t);
  strftime(date, sizeof(date), "%F %T", &now);

  utsname uts;
  if (uname(&uts) == -1) return;

  std::string fingerprint = android::base::GetProperty("ro.build.fingerprint", "");
  if (fingerprint.empty()) return;

  std::string kernel_cmdline;
  ReadFileToString("/proc/cmdline", &kernel_cmdline);

  auto fp = fopen_unique(get_bootchart_path("header").c_str(), "we");
  if (!fp) return;
  fprintf(&*fp, "version = Android init 0.8\n");
  fprintf(&*fp, "title = Boot chart for Android (%s)\n", date);
  fprintf(&*fp, "system.uname = %s %s %s %s\n", uts.sysname, uts.release, uts.version, uts.machine);
  fprintf(&*fp, "system.release = %s\n", fingerprint.c_str());
  fprintf(&*fp, "system.cpu = %s\n", get_cpu_model().c_str());
  fprintf(&*fp, "system.kernel.options = %s\n", kernel_cmdline.c_str());
}

static void log_uptime(FILE* log) {
  fprintf(log, "%lld\n", get_uptime_jiffies());
}

static void log_file(FILE* log, const char* procfile) {
  log_uptime(log);

  std::string content;
  if (ReadFileToString(procfile, &content)) {
    fprintf(log, "%s\n", content.c_str());
  }
}

static void log_processes(FILE* log) {
  log_uptime(log);

  std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir("/proc"), closedir);
  struct dirent* entry;
  while ((entry = readdir(dir.get())) != NULL) {
    // Only match numeric values.
    int pid = atoi(entry->d_name);
    if (pid == 0) continue;

    // /proc/<pid>/stat only has truncated task names, so get the full
    // name from /proc/<pid>/cmdline.
    std::string cmdline_path = StringPrintf("/proc/%d/cmdline", pid);
    std::string process_cmdline;
    if (ReadFileToString(cmdline_path, &process_cmdline)) {
      // Remove trailing null chars
      while (!process_cmdline.empty() && process_cmdline.back() == '\0') {
        process_cmdline.pop_back();
      }
      // Replace remaining null chars with spaces
      std::replace(process_cmdline.begin(), process_cmdline.end(), '\0', ' ');
      process_cmdline = android::base::Trim(process_cmdline);

      // Trim the executable path, should keep only the basename
      if (!process_cmdline.empty()) {
        size_t first_space = process_cmdline.find(' ');
        std::string executable;
        std::string args;

        if (first_space != std::string::npos) {
          executable = process_cmdline.substr(0, first_space);
          args = process_cmdline.substr(first_space);
        } else {
          executable = process_cmdline;
        }
        size_t last_slash = executable.find_last_of('/');
        if (last_slash != std::string::npos && last_slash < executable.size() - 1) {
          executable = executable.substr(last_slash + 1);
        }
        process_cmdline = executable + args;
      }
    } else {
      process_cmdline = "unknown process";
    }

    // Read process stat line.
    std::string stat;
    if (ReadFileToString(StringPrintf("/proc/%d/stat", pid), &stat)) {
      if (!process_cmdline.empty()) {
        // Substitute the process name with its real name.
        size_t open = stat.find('(');
        size_t close = stat.find_last_of(')');
        if (open != std::string::npos && close != std::string::npos) {
          stat.replace(open + 1, close - open - 1, process_cmdline);
        }
      }
      fputs(stat.c_str(), log);
    }
  }

  fputc('\n', log);
}

static void bootchart_thread_main() {
  LOG(INFO) << "Bootcharting started";

  // Unshare the mount namespace of this thread so that the init process itself can switch
  // the mount namespace later while this thread is still running.
  // Otherwise, setns() call invoked as part of `enter_default_mount_ns` fails with EINVAL.
  //
  // Note that after unshare()'ing the mount namespace from the main thread, this thread won't
  // receive mount/unmount events from the other mount namespace unless the events are happening
  // from under a sharable mount.
  //
  // The bootchart thread is safe to unshare the mount namespace because it only reads from /proc
  // and write to /data which are not private mounts.
  if (unshare(CLONE_NEWNS) == -1) {
      PLOG(ERROR) << "Cannot create mount namespace";
      return;
  }
  // Open log files.
  auto stat_log = fopen_unique(get_bootchart_path("proc_stat.log").c_str(), "we");
  if (!stat_log) return;
  auto proc_log = fopen_unique(get_bootchart_path("proc_ps.log").c_str(), "we");
  if (!proc_log) return;
  auto disk_log = fopen_unique(get_bootchart_path("proc_diskstats.log").c_str(), "we");
  if (!disk_log) return;

  log_header();

  while (true) {
    {
      std::unique_lock<std::mutex> lock(g_bootcharting_finished_mutex);
      g_bootcharting_finished_cv.wait_for(lock, 200ms);
      if (g_bootcharting_finished) break;
    }

    log_file(&*stat_log, "/proc/stat");
    log_file(&*disk_log, "/proc/diskstats");
    log_processes(&*proc_log);
  }

  LOG(INFO) << "Bootcharting finished";
}

static Result<void> do_bootchart_start() {
    if (!is_bootchart_enabled()) {
        LOG(VERBOSE) << "Not bootcharting";
        return {};
    }
    if (!g_bootcharting_thread)
        g_bootcharting_thread.emplace(bootchart_thread_main);
    return {};
}

static Result<void> do_bootchart_stop() {
    if (!g_bootcharting_thread) return {};

    // Tell the worker thread it's time to quit.
    {
        std::lock_guard<std::mutex> lock(g_bootcharting_finished_mutex);
        g_bootcharting_finished = true;
        g_bootcharting_finished_cv.notify_one();
    }

    g_bootcharting_thread->join();
    g_bootcharting_thread.reset();
    return {};
}

Result<void> do_bootchart(const BuiltinArguments& args) {
    if (args[1] == "start") return do_bootchart_start();
    return do_bootchart_stop();
}

}  // namespace init
}  // namespace android

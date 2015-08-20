/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <fcntl.h>  // for open

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/flag_helper.h>
#include <chromeos/syslog_logging.h>
#include <metrics/metrics_library.h>

#include "kernel_collector.h"
#include "kernel_warning_collector.h"
#include "udev_collector.h"
#include "unclean_shutdown_collector.h"
#include "user_collector.h"

static const char kCrashCounterHistogram[] = "Logging.CrashCounter";
static const char kUserCrashSignal[] =
    "org.chromium.CrashReporter.UserCrash";
static const char kKernelCrashDetected[] = "/var/run/kernel-crash-detected";
static const char kUncleanShutdownDetected[] =
    "/var/run/unclean-shutdown-detected";

// Enumeration of kinds of crashes to be used in the CrashCounter histogram.
enum CrashKinds {
  kCrashKindUncleanShutdown = 1,
  kCrashKindUser = 2,
  kCrashKindKernel = 3,
  kCrashKindUdev = 4,
  kCrashKindKernelWarning = 5,
  kCrashKindMax
};

static MetricsLibrary s_metrics_lib;

using base::FilePath;
using base::StringPrintf;

static bool IsFeedbackAllowed() {
  return s_metrics_lib.AreMetricsEnabled();
}

static bool TouchFile(const FilePath &file_path) {
  return base::WriteFile(file_path, "", 0) == 0;
}

static void SendCrashMetrics(CrashKinds type, const char* name) {
  // TODO(kmixter): We can remove this histogram as part of
  // crosbug.com/11163.
  s_metrics_lib.SendEnumToUMA(kCrashCounterHistogram, type, kCrashKindMax);
  s_metrics_lib.SendCrashToUMA(name);
}

static void CountKernelCrash() {
  SendCrashMetrics(kCrashKindKernel, "kernel");
}

static void CountUdevCrash() {
  SendCrashMetrics(kCrashKindUdev, "udevcrash");
}

static void CountUncleanShutdown() {
  SendCrashMetrics(kCrashKindUncleanShutdown, "uncleanshutdown");
}

static void CountUserCrash() {
  SendCrashMetrics(kCrashKindUser, "user");
  std::string command = StringPrintf(
      "/usr/bin/dbus-send --type=signal --system / \"%s\" &",
      kUserCrashSignal);
  // Announce through D-Bus whenever a user crash happens. This is
  // used by the metrics daemon to log active use time between
  // crashes.
  //
  // This could be done more efficiently by explicit fork/exec or
  // using a dbus library directly. However, this should run
  // relatively rarely and longer term we may need to implement a
  // better way to do this that doesn't rely on D-Bus.
  //
  // We run in the background in case dbus daemon itself is crashed
  // and not responding.  This allows us to not block and potentially
  // deadlock on a dbus-daemon crash.  If dbus-daemon crashes without
  // restarting, each crash will fork off a lot of dbus-send
  // processes.  Such a system is in a unusable state and will need
  // to be restarted anyway.

  int status = system(command.c_str());
  LOG_IF(WARNING, status != 0) << "dbus-send running failed";
}


static int Initialize(KernelCollector *kernel_collector,
                      UserCollector *user_collector,
                      UncleanShutdownCollector *unclean_shutdown_collector,
                      const bool unclean_check,
                      const bool clean_shutdown) {
  CHECK(!clean_shutdown) << "Incompatible options";

  bool was_kernel_crash = false;
  bool was_unclean_shutdown = false;
  kernel_collector->Enable();
  if (kernel_collector->is_enabled()) {
    was_kernel_crash = kernel_collector->Collect();
  }

  if (unclean_check) {
    was_unclean_shutdown = unclean_shutdown_collector->Collect();
  }

  // Touch a file to notify the metrics daemon that a kernel
  // crash has been detected so that it can log the time since
  // the last kernel crash.
  if (IsFeedbackAllowed()) {
    if (was_kernel_crash) {
      TouchFile(FilePath(kKernelCrashDetected));
    } else if (was_unclean_shutdown) {
      // We only count an unclean shutdown if it did not come with
      // an associated kernel crash.
      TouchFile(FilePath(kUncleanShutdownDetected));
    }
  }

  // Must enable the unclean shutdown collector *after* collecting.
  unclean_shutdown_collector->Enable();
  user_collector->Enable();

  return 0;
}

static int HandleUserCrash(UserCollector *user_collector,
                           const std::string& user, const bool crash_test) {
  // Handle a specific user space crash.
  CHECK(!user.empty()) << "--user= must be set";

  // Make it possible to test what happens when we crash while
  // handling a crash.
  if (crash_test) {
    *(volatile char *)0 = 0;
    return 0;
  }

  // Accumulate logs to help in diagnosing failures during user collection.
  chromeos::LogToString(true);
  // Handle the crash, get the name of the process from procfs.
  bool handled = user_collector->HandleCrash(user, nullptr);
  chromeos::LogToString(false);
  if (!handled)
    return 1;
  return 0;
}

static int HandleUdevCrash(UdevCollector *udev_collector,
                           const std::string& udev_event) {
  // Handle a crash indicated by a udev event.
  CHECK(!udev_event.empty()) << "--udev= must be set";

  // Accumulate logs to help in diagnosing failures during user collection.
  chromeos::LogToString(true);
  bool handled = udev_collector->HandleCrash(udev_event);
  chromeos::LogToString(false);
  if (!handled)
    return 1;
  return 0;
}

static int HandleKernelWarning(KernelWarningCollector
                               *kernel_warning_collector) {
  // Accumulate logs to help in diagnosing failures during collection.
  chromeos::LogToString(true);
  bool handled = kernel_warning_collector->Collect();
  chromeos::LogToString(false);
  if (!handled)
    return 1;
  return 0;
}

// Interactive/diagnostics mode for generating kernel crash signatures.
static int GenerateKernelSignature(KernelCollector *kernel_collector,
                                   const std::string& kernel_signature_file) {
  std::string kcrash_contents;
  std::string signature;
  if (!base::ReadFileToString(FilePath(kernel_signature_file),
                              &kcrash_contents)) {
    fprintf(stderr, "Could not read file.\n");
    return 1;
  }
  if (!kernel_collector->ComputeKernelStackSignature(
          kcrash_contents,
          &signature,
          true)) {
    fprintf(stderr, "Signature could not be generated.\n");
    return 1;
  }
  printf("Kernel crash signature is \"%s\".\n", signature.c_str());
  return 0;
}

// Ensure stdout, stdin, and stderr are open file descriptors.  If
// they are not, any code which writes to stderr/stdout may write out
// to files opened during execution.  In particular, when
// crash_reporter is run by the kernel coredump pipe handler (via
// kthread_create/kernel_execve), it will not have file table entries
// 1 and 2 (stdout and stderr) populated.  We populate them here.
static void OpenStandardFileDescriptors() {
  int new_fd = -1;
  // We open /dev/null to fill in any of the standard [0, 2] file
  // descriptors.  We leave these open for the duration of the
  // process.  This works because open returns the lowest numbered
  // invalid fd.
  do {
    new_fd = open("/dev/null", 0);
    CHECK_GE(new_fd, 0) << "Unable to open /dev/null";
  } while (new_fd >= 0 && new_fd <= 2);
  close(new_fd);
}

int main(int argc, char *argv[]) {
  DEFINE_bool(init, false, "Initialize crash logging");
  DEFINE_bool(clean_shutdown, false, "Signal clean shutdown");
  DEFINE_string(generate_kernel_signature, "",
                "Generate signature from given kcrash file");
  DEFINE_bool(crash_test, false, "Crash test");
  DEFINE_string(user, "", "User crash info (pid:signal:exec_name)");
  DEFINE_bool(unclean_check, true, "Check for unclean shutdown");
  DEFINE_string(udev, "", "Udev event description (type:device:subsystem)");
  DEFINE_bool(kernel_warning, false, "Report collected kernel warning");
  DEFINE_string(pid, "", "PID of crashing process");
  DEFINE_string(uid, "", "UID of crashing process");
  DEFINE_string(exe, "", "Executable name of crashing process");
  DEFINE_bool(core2md_failure, false, "Core2md failure test");
  DEFINE_bool(directory_failure, false, "Spool directory failure test");
  DEFINE_string(filter_in, "",
                "Ignore all crashes but this for testing");

  OpenStandardFileDescriptors();
  FilePath my_path = base::MakeAbsoluteFilePath(FilePath(argv[0]));
  s_metrics_lib.Init();
  chromeos::FlagHelper::Init(argc, argv, "Chromium OS Crash Reporter");
  chromeos::OpenLog(my_path.BaseName().value().c_str(), true);
  chromeos::InitLog(chromeos::kLogToSyslog);

  KernelCollector kernel_collector;
  kernel_collector.Initialize(CountKernelCrash, IsFeedbackAllowed);
  UserCollector user_collector;
  user_collector.Initialize(CountUserCrash,
                            my_path.value(),
                            IsFeedbackAllowed,
                            true,  // generate_diagnostics
                            FLAGS_core2md_failure,
                            FLAGS_directory_failure,
                            FLAGS_filter_in);
  UncleanShutdownCollector unclean_shutdown_collector;
  unclean_shutdown_collector.Initialize(CountUncleanShutdown,
                                        IsFeedbackAllowed);
  UdevCollector udev_collector;
  udev_collector.Initialize(CountUdevCrash, IsFeedbackAllowed);

  KernelWarningCollector kernel_warning_collector;
  kernel_warning_collector.Initialize(CountUdevCrash, IsFeedbackAllowed);

  if (FLAGS_init) {
    return Initialize(&kernel_collector,
                      &user_collector,
                      &unclean_shutdown_collector,
                      FLAGS_unclean_check,
                      FLAGS_clean_shutdown);
  }

  if (FLAGS_clean_shutdown) {
    unclean_shutdown_collector.Disable();
    user_collector.Disable();
    return 0;
  }

  if (!FLAGS_generate_kernel_signature.empty()) {
    return GenerateKernelSignature(&kernel_collector,
                                   FLAGS_generate_kernel_signature);
  }

  if (!FLAGS_udev.empty()) {
    return HandleUdevCrash(&udev_collector, FLAGS_udev);
  }

  if (FLAGS_kernel_warning) {
    return HandleKernelWarning(&kernel_warning_collector);
  }

  return HandleUserCrash(&user_collector, FLAGS_user, FLAGS_crash_test);
}

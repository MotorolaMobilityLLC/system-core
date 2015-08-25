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

#include "user_collector.h"

#include <elf.h>
#include <fcntl.h>
#include <grp.h>  // For struct group.
#include <pcrecpp.h>
#include <pwd.h>  // For struct passwd.
#include <stdint.h>
#include <sys/cdefs.h>  // For __WORDSIZE
#include <sys/types.h>  // For getpwuid_r, getgrnam_r, WEXITSTATUS.
#include <unistd.h>  // For setgroups

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/process.h>
#include <chromeos/syslog_logging.h>
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>

static const char kCollectionErrorSignature[] =
    "crash_reporter-user-collection";
static const char kCorePatternProperty[] = "crash_reporter.coredump.enabled";
static const char kCoreToMinidumpConverterPath[] = "/system/bin/core2md";

static const char kStatePrefix[] = "State:\t";

static const char kCoreTempFolder[] = "/data/misc/crash_reporter/tmp";

// Define an otherwise invalid value that represents an unknown UID.
static const uid_t kUnknownUid = -1;

const char *UserCollector::kUserId = "Uid:\t";
const char *UserCollector::kGroupId = "Gid:\t";

using base::FilePath;
using base::StringPrintf;

UserCollector::UserCollector()
    : generate_diagnostics_(false),
      initialized_(false) {
}

void UserCollector::Initialize(
    UserCollector::CountCrashFunction count_crash_function,
    const std::string &our_path,
    UserCollector::IsFeedbackAllowedFunction is_feedback_allowed_function,
    bool generate_diagnostics,
    bool core2md_failure,
    bool directory_failure,
    const std::string &filter_in) {
  CrashCollector::Initialize(count_crash_function,
                             is_feedback_allowed_function);
  our_path_ = our_path;
  initialized_ = true;
  generate_diagnostics_ = generate_diagnostics;
  core2md_failure_ = core2md_failure;
  directory_failure_ = directory_failure;
  filter_in_ = filter_in;

  gid_t groups[] = { AID_SYSTEM, AID_DBUS };
  if (setgroups(arraysize(groups), groups) != 0) {
    PLOG(FATAL) << "Unable to set groups to system and dbus";
  }
}

UserCollector::~UserCollector() {
}

std::string UserCollector::GetErrorTypeSignature(ErrorType error_type) const {
  switch (error_type) {
    case kErrorSystemIssue:
      return "system-issue";
    case kErrorReadCoreData:
      return "read-core-data";
    case kErrorUnusableProcFiles:
      return "unusable-proc-files";
    case kErrorInvalidCoreFile:
      return "invalid-core-file";
    case kErrorUnsupported32BitCoreFile:
      return "unsupported-32bit-core-file";
    case kErrorCore2MinidumpConversion:
      return "core2md-conversion";
    default:
      return "";
  }
}

// Return the string that should be used for the kernel's core_pattern file.
// Note that if you change the format of the enabled pattern, you'll probably
// also need to change the ParseCrashAttributes() function below, the
// user_collector_test.cc unittest, and the logging_UserCrash.py autotest.
std::string UserCollector::GetPattern(bool enabled) const {
  if (enabled) {
    // Combine the four crash attributes into one parameter to try to reduce
    // the size of the invocation line for crash_reporter, since the kernel
    // has a fixed-sized (128B) buffer for it (before parameter expansion).
    // Note that the kernel does not support quoted arguments in core_pattern.
    return StringPrintf("|%s --user=%%P:%%s:%%u:%%e", our_path_.c_str());
  } else {
    return "core";
  }
}

bool UserCollector::SetUpInternal(bool enabled) {
  CHECK(initialized_);
  LOG(INFO) << (enabled ? "Enabling" : "Disabling") << " user crash handling";

  property_set(kCorePatternProperty, enabled ? "1" : "0");

  return true;
}

bool UserCollector::GetFirstLineWithPrefix(
    const std::vector<std::string> &lines,
    const char *prefix, std::string *line) {
  std::vector<std::string>::const_iterator line_iterator;
  for (line_iterator = lines.begin(); line_iterator != lines.end();
       ++line_iterator) {
    if (line_iterator->find(prefix) == 0) {
      *line = *line_iterator;
      return true;
    }
  }
  return false;
}

bool UserCollector::GetIdFromStatus(
    const char *prefix, IdKind kind,
    const std::vector<std::string> &status_lines, int *id) {
  // From fs/proc/array.c:task_state(), this file contains:
  // \nUid:\t<uid>\t<euid>\t<suid>\t<fsuid>\n
  std::string id_line;
  if (!GetFirstLineWithPrefix(status_lines, prefix, &id_line)) {
    return false;
  }
  std::string id_substring = id_line.substr(strlen(prefix), std::string::npos);
  std::vector<std::string> ids;
  base::SplitString(id_substring, '\t', &ids);
  if (ids.size() != kIdMax || kind < 0 || kind >= kIdMax) {
    return false;
  }
  const char *number = ids[kind].c_str();
  char *end_number = nullptr;
  *id = strtol(number, &end_number, 10);
  if (*end_number != '\0') {
    return false;
  }
  return true;
}

bool UserCollector::GetStateFromStatus(
    const std::vector<std::string> &status_lines, std::string *state) {
  std::string state_line;
  if (!GetFirstLineWithPrefix(status_lines, kStatePrefix, &state_line)) {
    return false;
  }
  *state = state_line.substr(strlen(kStatePrefix), std::string::npos);
  return true;
}

void UserCollector::EnqueueCollectionErrorLog(pid_t pid,
                                              ErrorType error_type,
                                              const std::string &exec) {
  FilePath crash_path;
  LOG(INFO) << "Writing conversion problems as separate crash report.";
  if (!GetCreatedCrashDirectoryByEuid(0, &crash_path, nullptr)) {
    LOG(ERROR) << "Could not even get log directory; out of space?";
    return;
  }
  AddCrashMetaData("sig", kCollectionErrorSignature);
  AddCrashMetaData("error_type", GetErrorTypeSignature(error_type));
  std::string dump_basename = FormatDumpBasename(exec, time(nullptr), pid);
  std::string error_log = chromeos::GetLog();
  FilePath diag_log_path = GetCrashPath(crash_path, dump_basename, "diaglog");
  if (GetLogContents(FilePath(log_config_path_), kCollectionErrorSignature,
                     diag_log_path)) {
    // We load the contents of diag_log into memory and append it to
    // the error log.  We cannot just append to files because we need
    // to always create new files to prevent attack.
    std::string diag_log_contents;
    base::ReadFileToString(diag_log_path, &diag_log_contents);
    error_log.append(diag_log_contents);
    base::DeleteFile(diag_log_path, false);
  }
  FilePath log_path = GetCrashPath(crash_path, dump_basename, "log");
  FilePath meta_path = GetCrashPath(crash_path, dump_basename, "meta");
  // We must use WriteNewFile instead of base::WriteFile as we do
  // not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(log_path, error_log.data(), error_log.length()) < 0) {
    LOG(ERROR) << "Error writing new file " << log_path.value();
    return;
  }
  WriteCrashMetaData(meta_path, exec, log_path.value());
}

bool UserCollector::CopyOffProcFiles(pid_t pid,
                                     const FilePath &container_dir) {
  if (!base::CreateDirectory(container_dir)) {
    PLOG(ERROR) << "Could not create " << container_dir.value().c_str();
    return false;
  }
  FilePath process_path = GetProcessPath(pid);
  if (!base::PathExists(process_path)) {
    LOG(ERROR) << "Path " << process_path.value() << " does not exist";
    return false;
  }
  static const char *proc_files[] = {
    "auxv",
    "cmdline",
    "environ",
    "maps",
    "status"
  };
  for (unsigned i = 0; i < arraysize(proc_files); ++i) {
    if (!base::CopyFile(process_path.Append(proc_files[i]),
                        container_dir.Append(proc_files[i]))) {
      LOG(ERROR) << "Could not copy " << proc_files[i] << " file";
      return false;
    }
  }
  return true;
}

bool UserCollector::ValidateProcFiles(const FilePath &container_dir) const {
  // Check if the maps file is empty, which could be due to the crashed
  // process being reaped by the kernel before finishing a core dump.
  int64_t file_size = 0;
  if (!base::GetFileSize(container_dir.Append("maps"), &file_size)) {
    LOG(ERROR) << "Could not get the size of maps file";
    return false;
  }
  if (file_size == 0) {
    LOG(ERROR) << "maps file is empty";
    return false;
  }
  return true;
}

UserCollector::ErrorType UserCollector::ValidateCoreFile(
    const FilePath &core_path) const {
  int fd = HANDLE_EINTR(open(core_path.value().c_str(), O_RDONLY));
  if (fd < 0) {
    PLOG(ERROR) << "Could not open core file " << core_path.value();
    return kErrorInvalidCoreFile;
  }

  char e_ident[EI_NIDENT];
  bool read_ok = base::ReadFromFD(fd, e_ident, sizeof(e_ident));
  IGNORE_EINTR(close(fd));
  if (!read_ok) {
    LOG(ERROR) << "Could not read header of core file";
    return kErrorInvalidCoreFile;
  }

  if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 ||
      e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3) {
    LOG(ERROR) << "Invalid core file";
    return kErrorInvalidCoreFile;
  }

#if __WORDSIZE == 64
  // TODO(benchan, mkrebs): Remove this check once core2md can
  // handles both 32-bit and 64-bit ELF on a 64-bit platform.
  if (e_ident[EI_CLASS] == ELFCLASS32) {
    LOG(ERROR) << "Conversion of 32-bit core file on 64-bit platform is "
               << "currently not supported";
    return kErrorUnsupported32BitCoreFile;
  }
#endif

  return kErrorNone;
}

bool UserCollector::GetCreatedCrashDirectory(pid_t pid, uid_t supplied_ruid,
                                             FilePath *crash_file_path,
                                             bool *out_of_capacity) {
  FilePath process_path = GetProcessPath(pid);
  std::string status;
  if (directory_failure_) {
    LOG(ERROR) << "Purposefully failing to create spool directory";
    return false;
  }

  uid_t uid;
  if (base::ReadFileToString(process_path.Append("status"), &status)) {
    std::vector<std::string> status_lines;
    base::SplitString(status, '\n', &status_lines);

    std::string process_state;
    if (!GetStateFromStatus(status_lines, &process_state)) {
      LOG(ERROR) << "Could not find process state in status file";
      return false;
    }
    LOG(INFO) << "State of crashed process [" << pid << "]: " << process_state;

    // Get effective UID of crashing process.
    int id;
    if (!GetIdFromStatus(kUserId, kIdEffective, status_lines, &id)) {
      LOG(ERROR) << "Could not find euid in status file";
      return false;
    }
    uid = id;
  } else if (supplied_ruid != kUnknownUid) {
    LOG(INFO) << "Using supplied UID " << supplied_ruid
              << " for crashed process [" << pid
              << "] due to error reading status file";
    uid = supplied_ruid;
  } else {
    LOG(ERROR) << "Could not read status file and kernel did not supply UID";
    LOG(INFO) << "Path " << process_path.value() << " DirectoryExists: "
              << base::DirectoryExists(process_path);
    return false;
  }

  if (!GetCreatedCrashDirectoryByEuid(uid, crash_file_path, out_of_capacity)) {
    LOG(ERROR) << "Could not create crash directory";
    return false;
  }
  return true;
}

bool UserCollector::CopyStdinToCoreFile(const FilePath &core_path) {
  // Copy off all stdin to a core file.
  FilePath stdin_path("/proc/self/fd/0");
  if (base::CopyFile(stdin_path, core_path)) {
    return true;
  }

  PLOG(ERROR) << "Could not write core file";
  // If the file system was full, make sure we remove any remnants.
  base::DeleteFile(core_path, false);
  return false;
}

bool UserCollector::RunCoreToMinidump(const FilePath &core_path,
                                      const FilePath &procfs_directory,
                                      const FilePath &minidump_path,
                                      const FilePath &temp_directory) {
  FilePath output_path = temp_directory.Append("output");
  chromeos::ProcessImpl core2md;
  core2md.RedirectOutput(output_path.value());
  core2md.AddArg(kCoreToMinidumpConverterPath);
  core2md.AddArg(core_path.value());
  core2md.AddArg(procfs_directory.value());

  if (!core2md_failure_) {
    core2md.AddArg(minidump_path.value());
  } else {
    // To test how core2md errors are propagaged, cause an error
    // by forgetting a required argument.
  }

  int errorlevel = core2md.Run();

  std::string output;
  base::ReadFileToString(output_path, &output);
  if (errorlevel != 0) {
    LOG(ERROR) << "Problem during " << kCoreToMinidumpConverterPath
               << " [result=" << errorlevel << "]: " << output;
    return false;
  }

  if (!base::PathExists(minidump_path)) {
    LOG(ERROR) << "Minidump file " << minidump_path.value()
               << " was not created";
    return false;
  }
  return true;
}

UserCollector::ErrorType UserCollector::ConvertCoreToMinidump(
    pid_t pid,
    const FilePath &container_dir,
    const FilePath &core_path,
    const FilePath &minidump_path) {
  // If proc files are unuable, we continue to read the core file from stdin,
  // but only skip the core-to-minidump conversion, so that we may still use
  // the core file for debugging.
  bool proc_files_usable =
      CopyOffProcFiles(pid, container_dir) && ValidateProcFiles(container_dir);

  if (!CopyStdinToCoreFile(core_path)) {
    return kErrorReadCoreData;
  }

  if (!proc_files_usable) {
    LOG(INFO) << "Skipped converting core file to minidump due to "
              << "unusable proc files";
    return kErrorUnusableProcFiles;
  }

  ErrorType error = ValidateCoreFile(core_path);
  if (error != kErrorNone) {
    return error;
  }

  if (!RunCoreToMinidump(core_path,
                         container_dir,  // procfs directory
                         minidump_path,
                         container_dir)) {  // temporary directory
    return kErrorCore2MinidumpConversion;
  }

  LOG(INFO) << "Stored minidump to " << minidump_path.value();
  return kErrorNone;
}

UserCollector::ErrorType UserCollector::ConvertAndEnqueueCrash(
    pid_t pid, const std::string &exec, uid_t supplied_ruid,
    bool *out_of_capacity) {
  FilePath crash_path;
  if (!GetCreatedCrashDirectory(pid, supplied_ruid, &crash_path,
      out_of_capacity)) {
    LOG(ERROR) << "Unable to find/create process-specific crash path";
    return kErrorSystemIssue;
  }

  // Directory like /tmp/crash_reporter/1234 which contains the
  // procfs entries and other temporary files used during conversion.
  FilePath container_dir(StringPrintf("%s/%d", kCoreTempFolder, pid));
  // Delete a pre-existing directory from crash reporter that may have
  // been left around for diagnostics from a failed conversion attempt.
  // If we don't, existing files can cause forking to fail.
  base::DeleteFile(container_dir, true);
  std::string dump_basename = FormatDumpBasename(exec, time(nullptr), pid);
  FilePath core_path = GetCrashPath(crash_path, dump_basename, "core");
  FilePath meta_path = GetCrashPath(crash_path, dump_basename, "meta");
  FilePath minidump_path = GetCrashPath(crash_path, dump_basename, "dmp");
  FilePath log_path = GetCrashPath(crash_path, dump_basename, "log");

  if (GetLogContents(FilePath(log_config_path_), exec, log_path))
    AddCrashMetaData("log", log_path.value());

  ErrorType error_type =
      ConvertCoreToMinidump(pid, container_dir, core_path, minidump_path);
  if (error_type != kErrorNone) {
    LOG(INFO) << "Leaving core file at " << core_path.value()
              << " due to conversion error";
    return error_type;
  }

  // Here we commit to sending this file.  We must not return false
  // after this point or we will generate a log report as well as a
  // crash report.
  WriteCrashMetaData(meta_path,
                     exec,
                     minidump_path.value());

  if (!IsDeveloperImage()) {
    base::DeleteFile(core_path, false);
  } else {
    LOG(INFO) << "Leaving core file at " << core_path.value()
              << " due to developer image";
  }

  base::DeleteFile(container_dir, true);
  return kErrorNone;
}

bool UserCollector::ParseCrashAttributes(const std::string &crash_attributes,
                                         pid_t *pid, int *signal, uid_t *uid,
                                         std::string *kernel_supplied_name) {
  pcrecpp::RE re("(\\d+):(\\d+):(\\d+):(.*)");
  if (re.FullMatch(crash_attributes, pid, signal, uid, kernel_supplied_name))
    return true;

  LOG(INFO) << "Falling back to parsing crash attributes '"
            << crash_attributes << "' without UID";
  pcrecpp::RE re_without_uid("(\\d+):(\\d+):(.*)");
  *uid = kUnknownUid;
  return re_without_uid.FullMatch(crash_attributes, pid, signal,
      kernel_supplied_name);
}

bool UserCollector::ShouldDump(bool has_owner_consent,
                               bool is_developer,
                               std::string *reason) {
  reason->clear();

  // For developer builds, we always want to keep the crash reports unless
  // we're testing the crash facilities themselves.  This overrides
  // feedback.  Crash sending still obeys consent.
  if (is_developer) {
    *reason = "developer build - not testing - always dumping";
    return true;
  }

  if (!has_owner_consent) {
    *reason = "ignoring - no consent";
    return false;
  }

  *reason = "handling";
  return true;
}

bool UserCollector::HandleCrash(const std::string &crash_attributes,
                                const char *force_exec) {
  CHECK(initialized_);
  pid_t pid = 0;
  int signal = 0;
  uid_t supplied_ruid = kUnknownUid;
  std::string kernel_supplied_name;

  if (!ParseCrashAttributes(crash_attributes, &pid, &signal, &supplied_ruid,
                            &kernel_supplied_name)) {
    LOG(ERROR) << "Invalid parameter: --user=" <<  crash_attributes;
    return false;
  }

  std::string exec;
  if (force_exec) {
    exec.assign(force_exec);
  } else if (!GetExecutableBaseNameFromPid(pid, &exec)) {
    // If we cannot find the exec name, use the kernel supplied name.
    // We don't always use the kernel's since it truncates the name to
    // 16 characters.
    exec = StringPrintf("supplied_%s", kernel_supplied_name.c_str());
  }

  // Allow us to test the crash reporting mechanism successfully even if
  // other parts of the system crash.
  if (!filter_in_.empty() &&
      (filter_in_ == "none" ||
       filter_in_ != exec)) {
    // We use a different format message to make it more obvious in tests
    // which crashes are test generated and which are real.
    LOG(WARNING) << "Ignoring crash from " << exec << "[" << pid << "] while "
                 << "filter_in=" << filter_in_ << ".";
    return true;
  }

  std::string reason;
  bool dump = ShouldDump(is_feedback_allowed_function_(),
                         IsDeveloperImage(),
                         &reason);

  LOG(WARNING) << "Received crash notification for " << exec << "[" << pid
               << "] sig " << signal << ", user " << supplied_ruid
               << " (" << reason << ")";

  if (dump) {
    count_crash_function_();

    if (generate_diagnostics_) {
      bool out_of_capacity = false;
      ErrorType error_type =
          ConvertAndEnqueueCrash(pid, exec, supplied_ruid, &out_of_capacity);
      if (error_type != kErrorNone) {
        if (!out_of_capacity)
          EnqueueCollectionErrorLog(pid, error_type, exec);
        return false;
      }
    }
  }

  return true;
}

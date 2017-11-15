/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "service.h"

#include <fcntl.h>
#include <inttypes.h>
#include <linux/securebits.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/system_properties.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <hidl-util/FQName.h>
#include <processgroup/processgroup.h>
#include <selinux/selinux.h>
#include <system/thread_defs.h>

#include "init.h"
#include "property_service.h"
#include "rlimit_parser.h"
#include "util.h"

using android::base::boot_clock;
using android::base::GetProperty;
using android::base::Join;
using android::base::make_scope_guard;
using android::base::ParseInt;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::WriteStringToFile;

namespace android {
namespace init {

static Result<std::string> ComputeContextFromExecutable(std::string& service_name,
                                                        const std::string& service_path) {
    std::string computed_context;

    char* raw_con = nullptr;
    char* raw_filecon = nullptr;

    if (getcon(&raw_con) == -1) {
        return Error() << "Could not get security context";
    }
    std::unique_ptr<char> mycon(raw_con);

    if (getfilecon(service_path.c_str(), &raw_filecon) == -1) {
        return Error() << "Could not get file context";
    }
    std::unique_ptr<char> filecon(raw_filecon);

    char* new_con = nullptr;
    int rc = security_compute_create(mycon.get(), filecon.get(),
                                     string_to_security_class("process"), &new_con);
    if (rc == 0) {
        computed_context = new_con;
        free(new_con);
    }
    if (rc == 0 && computed_context == mycon.get()) {
        return Error() << "File " << service_path << "(labeled \"" << filecon.get()
                       << "\") has incorrect label or no domain transition from " << mycon.get()
                       << " to another SELinux domain defined. Have you configured your "
                          "service correctly? https://source.android.com/security/selinux/"
                          "device-policy#label_new_services_and_address_denials";
    }
    if (rc < 0) {
        return Error() << "Could not get process context";
    }
    return computed_context;
}

static void SetUpPidNamespace(const std::string& service_name) {
    constexpr unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;

    // It's OK to LOG(FATAL) in this function since it's running in the first
    // child process.

    // Recursively remount / as slave like zygote does so unmounting and mounting /proc
    // doesn't interfere with the parent namespace's /proc mount. This will also
    // prevent any other mounts/unmounts initiated by the service from interfering
    // with the parent namespace but will still allow mount events from the parent
    // namespace to propagate to the child.
    if (mount("rootfs", "/", nullptr, (MS_SLAVE | MS_REC), nullptr) == -1) {
        PLOG(FATAL) << "couldn't remount(/) recursively as slave for " << service_name;
    }
    // umount() then mount() /proc.
    // Note that it is not sufficient to mount with MS_REMOUNT.
    if (umount("/proc") == -1) {
        PLOG(FATAL) << "couldn't umount(/proc) for " << service_name;
    }
    if (mount("", "/proc", "proc", kSafeFlags, "") == -1) {
        PLOG(FATAL) << "couldn't mount(/proc) for " << service_name;
    }

    if (prctl(PR_SET_NAME, service_name.c_str()) == -1) {
        PLOG(FATAL) << "couldn't set name for " << service_name;
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        PLOG(FATAL) << "couldn't fork init inside the PID namespace for " << service_name;
    }

    if (child_pid > 0) {
        // So that we exit with the right status.
        static int init_exitstatus = 0;
        signal(SIGTERM, [](int) { _exit(init_exitstatus); });

        pid_t waited_pid;
        int status;
        while ((waited_pid = wait(&status)) > 0) {
             // This loop will end when there are no processes left inside the
             // PID namespace or when the init process inside the PID namespace
             // gets a signal.
            if (waited_pid == child_pid) {
                init_exitstatus = status;
            }
        }
        if (!WIFEXITED(init_exitstatus)) {
            _exit(EXIT_FAILURE);
        }
        _exit(WEXITSTATUS(init_exitstatus));
    }
}

static bool ExpandArgsAndExecv(const std::vector<std::string>& args) {
    std::vector<std::string> expanded_args;
    std::vector<char*> c_strings;

    expanded_args.resize(args.size());
    c_strings.push_back(const_cast<char*>(args[0].data()));
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (!expand_props(args[i], &expanded_args[i])) {
            LOG(FATAL) << args[0] << ": cannot expand '" << args[i] << "'";
        }
        c_strings.push_back(expanded_args[i].data());
    }
    c_strings.push_back(nullptr);

    return execv(c_strings[0], c_strings.data()) == 0;
}

unsigned long Service::next_start_order_ = 1;
bool Service::is_exec_service_running_ = false;

Service::Service(const std::string& name, Subcontext* subcontext_for_restart_commands,
                 const std::vector<std::string>& args)
    : Service(name, 0, 0, 0, {}, 0, 0, "", subcontext_for_restart_commands, args) {}

Service::Service(const std::string& name, unsigned flags, uid_t uid, gid_t gid,
                 const std::vector<gid_t>& supp_gids, const CapSet& capabilities,
                 unsigned namespace_flags, const std::string& seclabel,
                 Subcontext* subcontext_for_restart_commands, const std::vector<std::string>& args)
    : name_(name),
      classnames_({"default"}),
      flags_(flags),
      pid_(0),
      crash_count_(0),
      uid_(uid),
      gid_(gid),
      supp_gids_(supp_gids),
      capabilities_(capabilities),
      namespace_flags_(namespace_flags),
      seclabel_(seclabel),
      onrestart_(false, subcontext_for_restart_commands, "<Service '" + name + "' onrestart>", 0),
      keychord_id_(0),
      ioprio_class_(IoSchedClass_NONE),
      ioprio_pri_(0),
      priority_(0),
      oom_score_adjust_(-1000),
      swappiness_(-1),
      soft_limit_in_bytes_(-1),
      limit_in_bytes_(-1),
      start_order_(0),
      args_(args) {
    onrestart_.InitSingleTrigger("onrestart");
}

void Service::NotifyStateChange(const std::string& new_state) const {
    if ((flags_ & SVC_TEMPORARY) != 0) {
        // Services created by 'exec' are temporary and don't have properties tracking their state.
        return;
    }

    std::string prop_name = "init.svc." + name_;
    property_set(prop_name, new_state);

    if (new_state == "running") {
        uint64_t start_ns = time_started_.time_since_epoch().count();
        std::string boottime_property = "ro.boottime." + name_;
        if (GetProperty(boottime_property, "").empty()) {
            property_set(boottime_property, std::to_string(start_ns));
        }
    }
}

void Service::KillProcessGroup(int signal) {
    // If we've already seen a successful result from killProcessGroup*(), then we have removed
    // the cgroup already and calling these functions a second time will simply result in an error.
    // This is true regardless of which signal was sent.
    // These functions handle their own logging, so no additional logging is needed.
    if (!process_cgroup_empty_) {
        LOG(INFO) << "Sending signal " << signal << " to service '" << name_ << "' (pid " << pid_
                  << ") process group...";
        int r;
        if (signal == SIGTERM) {
            r = killProcessGroupOnce(uid_, pid_, signal);
        } else {
            r = killProcessGroup(uid_, pid_, signal);
        }

        if (r == 0) process_cgroup_empty_ = true;
    }
}

void Service::SetProcessAttributes() {
    for (const auto& rlimit : rlimits_) {
        if (setrlimit(rlimit.first, &rlimit.second) == -1) {
            LOG(FATAL) << StringPrintf("setrlimit(%d, {rlim_cur=%ld, rlim_max=%ld}) failed",
                                       rlimit.first, rlimit.second.rlim_cur, rlimit.second.rlim_max);
        }
    }
    // Keep capabilites on uid change.
    if (capabilities_.any() && uid_) {
        // If Android is running in a container, some securebits might already
        // be locked, so don't change those.
        unsigned long securebits = prctl(PR_GET_SECUREBITS);
        if (securebits == -1UL) {
            PLOG(FATAL) << "prctl(PR_GET_SECUREBITS) failed for " << name_;
        }
        securebits |= SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED;
        if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
            PLOG(FATAL) << "prctl(PR_SET_SECUREBITS) failed for " << name_;
        }
    }

    // TODO: work out why this fails for `console` then upgrade to FATAL.
    if (setpgid(0, getpid()) == -1) PLOG(ERROR) << "setpgid failed for " << name_;

    if (gid_) {
        if (setgid(gid_) != 0) {
            PLOG(FATAL) << "setgid failed for " << name_;
        }
    }
    if (setgroups(supp_gids_.size(), &supp_gids_[0]) != 0) {
        PLOG(FATAL) << "setgroups failed for " << name_;
    }
    if (uid_) {
        if (setuid(uid_) != 0) {
            PLOG(FATAL) << "setuid failed for " << name_;
        }
    }
    if (!seclabel_.empty()) {
        if (setexeccon(seclabel_.c_str()) < 0) {
            PLOG(FATAL) << "cannot setexeccon('" << seclabel_ << "') for " << name_;
        }
    }
    if (priority_ != 0) {
        if (setpriority(PRIO_PROCESS, 0, priority_) != 0) {
            PLOG(FATAL) << "setpriority failed for " << name_;
        }
    }
    if (capabilities_.any()) {
        if (!SetCapsForExec(capabilities_)) {
            LOG(FATAL) << "cannot set capabilities for " << name_;
        }
    }
}

void Service::Reap() {
    if (!(flags_ & SVC_ONESHOT) || (flags_ & SVC_RESTART)) {
        KillProcessGroup(SIGKILL);
    }

    // Remove any descriptor resources we may have created.
    std::for_each(descriptors_.begin(), descriptors_.end(),
                  std::bind(&DescriptorInfo::Clean, std::placeholders::_1));

    if (flags_ & SVC_EXEC) UnSetExec();

    if (flags_ & SVC_TEMPORARY) return;

    pid_ = 0;
    flags_ &= (~SVC_RUNNING);
    start_order_ = 0;

    // Oneshot processes go into the disabled state on exit,
    // except when manually restarted.
    if ((flags_ & SVC_ONESHOT) && !(flags_ & SVC_RESTART)) {
        flags_ |= SVC_DISABLED;
    }

    // Disabled and reset processes do not get restarted automatically.
    if (flags_ & (SVC_DISABLED | SVC_RESET))  {
        NotifyStateChange("stopped");
        return;
    }

    // If we crash > 4 times in 4 minutes, reboot into recovery.
    boot_clock::time_point now = boot_clock::now();
    if ((flags_ & SVC_CRITICAL) && !(flags_ & SVC_RESTART)) {
        if (now < time_crashed_ + 4min) {
            if (++crash_count_ > 4) {
                LOG(FATAL) << "critical process '" << name_ << "' exited 4 times in 4 minutes";
            }
        } else {
            time_crashed_ = now;
            crash_count_ = 1;
        }
    }

    flags_ &= (~SVC_RESTART);
    flags_ |= SVC_RESTARTING;

    // Execute all onrestart commands for this service.
    onrestart_.ExecuteAllCommands();

    NotifyStateChange("restarting");
    return;
}

void Service::DumpState() const {
    LOG(INFO) << "service " << name_;
    LOG(INFO) << "  class '" << Join(classnames_, " ") << "'";
    LOG(INFO) << "  exec " << Join(args_, " ");
    std::for_each(descriptors_.begin(), descriptors_.end(),
                  [] (const auto& info) { LOG(INFO) << *info; });
}

Result<Success> Service::ParseCapabilities(const std::vector<std::string>& args) {
    capabilities_ = 0;

    if (!CapAmbientSupported()) {
        return Error()
               << "capabilities requested but the kernel does not support ambient capabilities";
    }

    unsigned int last_valid_cap = GetLastValidCap();
    if (last_valid_cap >= capabilities_.size()) {
        LOG(WARNING) << "last valid run-time capability is larger than CAP_LAST_CAP";
    }

    for (size_t i = 1; i < args.size(); i++) {
        const std::string& arg = args[i];
        int res = LookupCap(arg);
        if (res < 0) {
            return Error() << StringPrintf("invalid capability '%s'", arg.c_str());
        }
        unsigned int cap = static_cast<unsigned int>(res);  // |res| is >= 0.
        if (cap > last_valid_cap) {
            return Error() << StringPrintf("capability '%s' not supported by the kernel",
                                           arg.c_str());
        }
        capabilities_[cap] = true;
    }
    return Success();
}

Result<Success> Service::ParseClass(const std::vector<std::string>& args) {
    classnames_ = std::set<std::string>(args.begin() + 1, args.end());
    return Success();
}

Result<Success> Service::ParseConsole(const std::vector<std::string>& args) {
    flags_ |= SVC_CONSOLE;
    console_ = args.size() > 1 ? "/dev/" + args[1] : "";
    return Success();
}

Result<Success> Service::ParseCritical(const std::vector<std::string>& args) {
    flags_ |= SVC_CRITICAL;
    return Success();
}

Result<Success> Service::ParseDisabled(const std::vector<std::string>& args) {
    flags_ |= SVC_DISABLED;
    flags_ |= SVC_RC_DISABLED;
    return Success();
}

Result<Success> Service::ParseGroup(const std::vector<std::string>& args) {
    auto gid = DecodeUid(args[1]);
    if (!gid) {
        return Error() << "Unable to decode GID for '" << args[1] << "': " << gid.error();
    }
    gid_ = *gid;

    for (std::size_t n = 2; n < args.size(); n++) {
        gid = DecodeUid(args[n]);
        if (!gid) {
            return Error() << "Unable to decode GID for '" << args[n] << "': " << gid.error();
        }
        supp_gids_.emplace_back(*gid);
    }
    return Success();
}

Result<Success> Service::ParsePriority(const std::vector<std::string>& args) {
    priority_ = 0;
    if (!ParseInt(args[1], &priority_,
                  static_cast<int>(ANDROID_PRIORITY_HIGHEST), // highest is negative
                  static_cast<int>(ANDROID_PRIORITY_LOWEST))) {
        return Error() << StringPrintf("process priority value must be range %d - %d",
                                       ANDROID_PRIORITY_HIGHEST, ANDROID_PRIORITY_LOWEST);
    }
    return Success();
}

Result<Success> Service::ParseInterface(const std::vector<std::string>& args) {
    const std::string& interface_name = args[1];
    const std::string& instance_name = args[2];

    const FQName fq_name = FQName(interface_name);
    if (!fq_name.isValid()) {
        return Error() << "Invalid fully-qualified name for interface '" << interface_name << "'";
    }

    if (!fq_name.isFullyQualified()) {
        return Error() << "Interface name not fully-qualified '" << interface_name << "'";
    }

    if (fq_name.isValidValueName()) {
        return Error() << "Interface name must not be a value name '" << interface_name << "'";
    }

    const std::string fullname = interface_name + "/" + instance_name;

    for (const auto& svc : ServiceList::GetInstance()) {
        if (svc->interfaces().count(fullname) > 0) {
            return Error() << "Interface '" << fullname << "' redefined in " << name()
                           << " but is already defined by " << svc->name();
        }
    }

    interfaces_.insert(fullname);

    return Success();
}

Result<Success> Service::ParseIoprio(const std::vector<std::string>& args) {
    if (!ParseInt(args[2], &ioprio_pri_, 0, 7)) {
        return Error() << "priority value must be range 0 - 7";
    }

    if (args[1] == "rt") {
        ioprio_class_ = IoSchedClass_RT;
    } else if (args[1] == "be") {
        ioprio_class_ = IoSchedClass_BE;
    } else if (args[1] == "idle") {
        ioprio_class_ = IoSchedClass_IDLE;
    } else {
        return Error() << "ioprio option usage: ioprio <rt|be|idle> <0-7>";
    }

    return Success();
}

Result<Success> Service::ParseKeycodes(const std::vector<std::string>& args) {
    for (std::size_t i = 1; i < args.size(); i++) {
        int code;
        if (ParseInt(args[i], &code)) {
            keycodes_.emplace_back(code);
        } else {
            LOG(WARNING) << "ignoring invalid keycode: " << args[i];
        }
    }
    return Success();
}

Result<Success> Service::ParseOneshot(const std::vector<std::string>& args) {
    flags_ |= SVC_ONESHOT;
    return Success();
}

Result<Success> Service::ParseOnrestart(const std::vector<std::string>& args) {
    std::vector<std::string> str_args(args.begin() + 1, args.end());
    int line = onrestart_.NumCommands() + 1;
    if (auto result = onrestart_.AddCommand(str_args, line); !result) {
        return Error() << "cannot add Onrestart command: " << result.error();
    }
    return Success();
}

Result<Success> Service::ParseNamespace(const std::vector<std::string>& args) {
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "pid") {
            namespace_flags_ |= CLONE_NEWPID;
            // PID namespaces require mount namespaces.
            namespace_flags_ |= CLONE_NEWNS;
        } else if (args[i] == "mnt") {
            namespace_flags_ |= CLONE_NEWNS;
        } else {
            return Error() << "namespace must be 'pid' or 'mnt'";
        }
    }
    return Success();
}

Result<Success> Service::ParseOomScoreAdjust(const std::vector<std::string>& args) {
    if (!ParseInt(args[1], &oom_score_adjust_, -1000, 1000)) {
        return Error() << "oom_score_adjust value must be in range -1000 - +1000";
    }
    return Success();
}

Result<Success> Service::ParseMemcgSwappiness(const std::vector<std::string>& args) {
    if (!ParseInt(args[1], &swappiness_, 0)) {
        return Error() << "swappiness value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseMemcgLimitInBytes(const std::vector<std::string>& args) {
    if (!ParseInt(args[1], &limit_in_bytes_, 0)) {
        return Error() << "limit_in_bytes value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseMemcgSoftLimitInBytes(const std::vector<std::string>& args) {
    if (!ParseInt(args[1], &soft_limit_in_bytes_, 0)) {
        return Error() << "soft_limit_in_bytes value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseProcessRlimit(const std::vector<std::string>& args) {
    auto rlimit = ParseRlimit(args);
    if (!rlimit) return rlimit.error();

    rlimits_.emplace_back(*rlimit);
    return Success();
}

Result<Success> Service::ParseSeclabel(const std::vector<std::string>& args) {
    seclabel_ = args[1];
    return Success();
}

Result<Success> Service::ParseSetenv(const std::vector<std::string>& args) {
    environment_vars_.emplace_back(args[1], args[2]);
    return Success();
}

Result<Success> Service::ParseShutdown(const std::vector<std::string>& args) {
    if (args[1] == "critical") {
        flags_ |= SVC_SHUTDOWN_CRITICAL;
        return Success();
    }
    return Error() << "Invalid shutdown option";
}

template <typename T>
Result<Success> Service::AddDescriptor(const std::vector<std::string>& args) {
    int perm = args.size() > 3 ? std::strtoul(args[3].c_str(), 0, 8) : -1;
    Result<uid_t> uid = 0;
    Result<gid_t> gid = 0;
    std::string context = args.size() > 6 ? args[6] : "";

    if (args.size() > 4) {
        uid = DecodeUid(args[4]);
        if (!uid) {
            return Error() << "Unable to find UID for '" << args[4] << "': " << uid.error();
        }
    }

    if (args.size() > 5) {
        gid = DecodeUid(args[5]);
        if (!gid) {
            return Error() << "Unable to find GID for '" << args[5] << "': " << gid.error();
        }
    }

    auto descriptor = std::make_unique<T>(args[1], args[2], *uid, *gid, perm, context);

    auto old =
        std::find_if(descriptors_.begin(), descriptors_.end(),
                     [&descriptor] (const auto& other) { return descriptor.get() == other.get(); });

    if (old != descriptors_.end()) {
        return Error() << "duplicate descriptor " << args[1] << " " << args[2];
    }

    descriptors_.emplace_back(std::move(descriptor));
    return Success();
}

// name type perm [ uid gid context ]
Result<Success> Service::ParseSocket(const std::vector<std::string>& args) {
    if (!StartsWith(args[2], "dgram") && !StartsWith(args[2], "stream") &&
        !StartsWith(args[2], "seqpacket")) {
        return Error() << "socket type must be 'dgram', 'stream' or 'seqpacket'";
    }
    return AddDescriptor<SocketInfo>(args);
}

// name type perm [ uid gid context ]
Result<Success> Service::ParseFile(const std::vector<std::string>& args) {
    if (args[2] != "r" && args[2] != "w" && args[2] != "rw") {
        return Error() << "file type must be 'r', 'w' or 'rw'";
    }
    if ((args[1][0] != '/') || (args[1].find("../") != std::string::npos)) {
        return Error() << "file name must not be relative";
    }
    return AddDescriptor<FileInfo>(args);
}

Result<Success> Service::ParseUser(const std::vector<std::string>& args) {
    auto uid = DecodeUid(args[1]);
    if (!uid) {
        return Error() << "Unable to find UID for '" << args[1] << "': " << uid.error();
    }
    uid_ = *uid;
    return Success();
}

Result<Success> Service::ParseWritepid(const std::vector<std::string>& args) {
    writepid_files_.assign(args.begin() + 1, args.end());
    return Success();
}

class Service::OptionParserMap : public KeywordMap<OptionParser> {
  public:
    OptionParserMap() {}

  private:
    const Map& map() const override;
};

const Service::OptionParserMap::Map& Service::OptionParserMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    // clang-format off
    static const Map option_parsers = {
        {"capabilities",
                        {1,     kMax, &Service::ParseCapabilities}},
        {"class",       {1,     kMax, &Service::ParseClass}},
        {"console",     {0,     1,    &Service::ParseConsole}},
        {"critical",    {0,     0,    &Service::ParseCritical}},
        {"disabled",    {0,     0,    &Service::ParseDisabled}},
        {"group",       {1,     NR_SVC_SUPP_GIDS + 1, &Service::ParseGroup}},
        {"interface",   {2,     2,    &Service::ParseInterface}},
        {"ioprio",      {2,     2,    &Service::ParseIoprio}},
        {"priority",    {1,     1,    &Service::ParsePriority}},
        {"keycodes",    {1,     kMax, &Service::ParseKeycodes}},
        {"oneshot",     {0,     0,    &Service::ParseOneshot}},
        {"onrestart",   {1,     kMax, &Service::ParseOnrestart}},
        {"oom_score_adjust",
                        {1,     1,    &Service::ParseOomScoreAdjust}},
        {"memcg.swappiness",
                        {1,     1,    &Service::ParseMemcgSwappiness}},
        {"memcg.soft_limit_in_bytes",
                        {1,     1,    &Service::ParseMemcgSoftLimitInBytes}},
        {"memcg.limit_in_bytes",
                        {1,     1,    &Service::ParseMemcgLimitInBytes}},
        {"namespace",   {1,     2,    &Service::ParseNamespace}},
        {"rlimit",      {3,     3,    &Service::ParseProcessRlimit}},
        {"seclabel",    {1,     1,    &Service::ParseSeclabel}},
        {"setenv",      {2,     2,    &Service::ParseSetenv}},
        {"shutdown",    {1,     1,    &Service::ParseShutdown}},
        {"socket",      {3,     6,    &Service::ParseSocket}},
        {"file",        {2,     2,    &Service::ParseFile}},
        {"user",        {1,     1,    &Service::ParseUser}},
        {"writepid",    {1,     kMax, &Service::ParseWritepid}},
    };
    // clang-format on
    return option_parsers;
}

Result<Success> Service::ParseLine(const std::vector<std::string>& args) {
    static const OptionParserMap parser_map;
    auto parser = parser_map.FindFunction(args);

    if (!parser) return parser.error();

    return std::invoke(*parser, this, args);
}

Result<Success> Service::ExecStart() {
    flags_ |= SVC_ONESHOT;

    if (auto result = Start(); !result) {
        return result;
    }

    flags_ |= SVC_EXEC;
    is_exec_service_running_ = true;

    LOG(INFO) << "SVC_EXEC pid " << pid_ << " (uid " << uid_ << " gid " << gid_ << "+"
              << supp_gids_.size() << " context " << (!seclabel_.empty() ? seclabel_ : "default")
              << ") started; waiting...";

    return Success();
}

Result<Success> Service::Start() {
    bool disabled = (flags_ & (SVC_DISABLED | SVC_RESET));
    // Starting a service removes it from the disabled or reset state and
    // immediately takes it out of the restarting state if it was in there.
    flags_ &= (~(SVC_DISABLED|SVC_RESTARTING|SVC_RESET|SVC_RESTART|SVC_DISABLED_START));

    // Running processes require no additional work --- if they're in the
    // process of exiting, we've ensured that they will immediately restart
    // on exit, unless they are ONESHOT. For ONESHOT service, if it's in
    // stopping status, we just set SVC_RESTART flag so it will get restarted
    // in Reap().
    if (flags_ & SVC_RUNNING) {
        if ((flags_ & SVC_ONESHOT) && disabled) {
            flags_ |= SVC_RESTART;
        }
        // It is not an error to try to start a service that is already running.
        return Success();
    }

    bool needs_console = (flags_ & SVC_CONSOLE);
    if (needs_console) {
        if (console_.empty()) {
            console_ = default_console;
        }

        // Make sure that open call succeeds to ensure a console driver is
        // properly registered for the device node
        int console_fd = open(console_.c_str(), O_RDWR | O_CLOEXEC);
        if (console_fd < 0) {
            flags_ |= SVC_DISABLED;
            return ErrnoError() << "Couldn't open console '" << console_ << "'";
        }
        close(console_fd);
    }

    struct stat sb;
    if (stat(args_[0].c_str(), &sb) == -1) {
        flags_ |= SVC_DISABLED;
        return ErrnoError() << "Cannot find '" << args_[0] << "'";
    }

    std::string scon;
    if (!seclabel_.empty()) {
        scon = seclabel_;
    } else {
        auto result = ComputeContextFromExecutable(name_, args_[0]);
        if (!result) {
            return result.error();
        }
        scon = *result;
    }

    LOG(INFO) << "starting service '" << name_ << "'...";

    pid_t pid = -1;
    if (namespace_flags_) {
        pid = clone(nullptr, nullptr, namespace_flags_ | SIGCHLD, nullptr);
    } else {
        pid = fork();
    }

    if (pid == 0) {
        umask(077);

        if (namespace_flags_ & CLONE_NEWPID) {
            // This will fork again to run an init process inside the PID
            // namespace.
            SetUpPidNamespace(name_);
        }

        for (const auto& [key, value] : environment_vars_) {
            setenv(key.c_str(), value.c_str(), 1);
        }

        std::for_each(descriptors_.begin(), descriptors_.end(),
                      std::bind(&DescriptorInfo::CreateAndPublish, std::placeholders::_1, scon));

        // See if there were "writepid" instructions to write to files under /dev/cpuset/.
        auto cpuset_predicate = [](const std::string& path) {
            return StartsWith(path, "/dev/cpuset/");
        };
        auto iter = std::find_if(writepid_files_.begin(), writepid_files_.end(), cpuset_predicate);
        if (iter == writepid_files_.end()) {
            // There were no "writepid" instructions for cpusets, check if the system default
            // cpuset is specified to be used for the process.
            std::string default_cpuset = GetProperty("ro.cpuset.default", "");
            if (!default_cpuset.empty()) {
                // Make sure the cpuset name starts and ends with '/'.
                // A single '/' means the 'root' cpuset.
                if (default_cpuset.front() != '/') {
                    default_cpuset.insert(0, 1, '/');
                }
                if (default_cpuset.back() != '/') {
                    default_cpuset.push_back('/');
                }
                writepid_files_.push_back(
                    StringPrintf("/dev/cpuset%stasks", default_cpuset.c_str()));
            }
        }
        std::string pid_str = std::to_string(getpid());
        for (const auto& file : writepid_files_) {
            if (!WriteStringToFile(pid_str, file)) {
                PLOG(ERROR) << "couldn't write " << pid_str << " to " << file;
            }
        }

        if (ioprio_class_ != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), ioprio_class_, ioprio_pri_)) {
                PLOG(ERROR) << "failed to set pid " << getpid()
                            << " ioprio=" << ioprio_class_ << "," << ioprio_pri_;
            }
        }

        if (needs_console) {
            setsid();
            OpenConsole();
        } else {
            ZapStdio();
        }

        // As requested, set our gid, supplemental gids, uid, context, and
        // priority. Aborts on failure.
        SetProcessAttributes();

        if (!ExpandArgsAndExecv(args_)) {
            PLOG(ERROR) << "cannot execve('" << args_[0] << "')";
        }

        _exit(127);
    }

    if (pid < 0) {
        pid_ = 0;
        return ErrnoError() << "Failed to fork";
    }

    if (oom_score_adjust_ != -1000) {
        std::string oom_str = std::to_string(oom_score_adjust_);
        std::string oom_file = StringPrintf("/proc/%d/oom_score_adj", pid);
        if (!WriteStringToFile(oom_str, oom_file)) {
            PLOG(ERROR) << "couldn't write oom_score_adj: " << strerror(errno);
        }
    }

    time_started_ = boot_clock::now();
    pid_ = pid;
    flags_ |= SVC_RUNNING;
    start_order_ = next_start_order_++;
    process_cgroup_empty_ = false;

    errno = -createProcessGroup(uid_, pid_);
    if (errno != 0) {
        PLOG(ERROR) << "createProcessGroup(" << uid_ << ", " << pid_ << ") failed for service '"
                    << name_ << "'";
    } else {
        if (swappiness_ != -1) {
            if (!setProcessGroupSwappiness(uid_, pid_, swappiness_)) {
                PLOG(ERROR) << "setProcessGroupSwappiness failed";
            }
        }

        if (soft_limit_in_bytes_ != -1) {
            if (!setProcessGroupSoftLimit(uid_, pid_, soft_limit_in_bytes_)) {
                PLOG(ERROR) << "setProcessGroupSoftLimit failed";
            }
        }

        if (limit_in_bytes_ != -1) {
            if (!setProcessGroupLimit(uid_, pid_, limit_in_bytes_)) {
                PLOG(ERROR) << "setProcessGroupLimit failed";
            }
        }
    }

    NotifyStateChange("running");
    return Success();
}

Result<Success> Service::StartIfNotDisabled() {
    if (!(flags_ & SVC_DISABLED)) {
        return Start();
    } else {
        flags_ |= SVC_DISABLED_START;
    }
    return Success();
}

Result<Success> Service::Enable() {
    flags_ &= ~(SVC_DISABLED | SVC_RC_DISABLED);
    if (flags_ & SVC_DISABLED_START) {
        return Start();
    }
    return Success();
}

void Service::Reset() {
    StopOrReset(SVC_RESET);
}

void Service::Stop() {
    StopOrReset(SVC_DISABLED);
}

void Service::Terminate() {
    flags_ &= ~(SVC_RESTARTING | SVC_DISABLED_START);
    flags_ |= SVC_DISABLED;
    if (pid_) {
        KillProcessGroup(SIGTERM);
        NotifyStateChange("stopping");
    }
}

void Service::Restart() {
    if (flags_ & SVC_RUNNING) {
        /* Stop, wait, then start the service. */
        StopOrReset(SVC_RESTART);
    } else if (!(flags_ & SVC_RESTARTING)) {
        /* Just start the service since it's not running. */
        if (auto result = Start(); !result) {
            LOG(ERROR) << "Could not restart '" << name_ << "': " << result.error();
        }
    } /* else: Service is restarting anyways. */
}

// The how field should be either SVC_DISABLED, SVC_RESET, or SVC_RESTART.
void Service::StopOrReset(int how) {
    // The service is still SVC_RUNNING until its process exits, but if it has
    // already exited it shoudn't attempt a restart yet.
    flags_ &= ~(SVC_RESTARTING | SVC_DISABLED_START);

    if ((how != SVC_DISABLED) && (how != SVC_RESET) && (how != SVC_RESTART)) {
        // An illegal flag: default to SVC_DISABLED.
        how = SVC_DISABLED;
    }

    // If the service has not yet started, prevent it from auto-starting with its class.
    if (how == SVC_RESET) {
        flags_ |= (flags_ & SVC_RC_DISABLED) ? SVC_DISABLED : SVC_RESET;
    } else {
        flags_ |= how;
    }
    // Make sure it's in right status when a restart immediately follow a
    // stop/reset or vice versa.
    if (how == SVC_RESTART) {
        flags_ &= (~(SVC_DISABLED | SVC_RESET));
    } else {
        flags_ &= (~SVC_RESTART);
    }

    if (pid_) {
        KillProcessGroup(SIGKILL);
        NotifyStateChange("stopping");
    } else {
        NotifyStateChange("stopped");
    }
}

void Service::ZapStdio() const {
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

void Service::OpenConsole() const {
    int fd = open(console_.c_str(), O_RDWR);
    if (fd == -1) fd = open("/dev/null", O_RDWR);
    ioctl(fd, TIOCSCTTY, 0);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

ServiceList::ServiceList() {}

ServiceList& ServiceList::GetInstance() {
    static ServiceList instance;
    return instance;
}

void ServiceList::AddService(std::unique_ptr<Service> service) {
    services_.emplace_back(std::move(service));
}

std::unique_ptr<Service> Service::MakeTemporaryOneshotService(const std::vector<std::string>& args) {
    // Parse the arguments: exec [SECLABEL [UID [GID]*] --] COMMAND ARGS...
    // SECLABEL can be a - to denote default
    std::size_t command_arg = 1;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--") {
            command_arg = i + 1;
            break;
        }
    }
    if (command_arg > 4 + NR_SVC_SUPP_GIDS) {
        LOG(ERROR) << "exec called with too many supplementary group ids";
        return nullptr;
    }

    if (command_arg >= args.size()) {
        LOG(ERROR) << "exec called without command";
        return nullptr;
    }
    std::vector<std::string> str_args(args.begin() + command_arg, args.end());

    static size_t exec_count = 0;
    exec_count++;
    std::string name = "exec " + std::to_string(exec_count) + " (" + Join(str_args, " ") + ")";

    unsigned flags = SVC_ONESHOT | SVC_TEMPORARY;
    CapSet no_capabilities;
    unsigned namespace_flags = 0;

    std::string seclabel = "";
    if (command_arg > 2 && args[1] != "-") {
        seclabel = args[1];
    }
    Result<uid_t> uid = 0;
    if (command_arg > 3) {
        uid = DecodeUid(args[2]);
        if (!uid) {
            LOG(ERROR) << "Unable to decode UID for '" << args[2] << "': " << uid.error();
            return nullptr;
        }
    }
    Result<gid_t> gid = 0;
    std::vector<gid_t> supp_gids;
    if (command_arg > 4) {
        gid = DecodeUid(args[3]);
        if (!gid) {
            LOG(ERROR) << "Unable to decode GID for '" << args[3] << "': " << gid.error();
            return nullptr;
        }
        std::size_t nr_supp_gids = command_arg - 1 /* -- */ - 4 /* exec SECLABEL UID GID */;
        for (size_t i = 0; i < nr_supp_gids; ++i) {
            auto supp_gid = DecodeUid(args[4 + i]);
            if (!supp_gid) {
                LOG(ERROR) << "Unable to decode GID for '" << args[4 + i]
                           << "': " << supp_gid.error();
                return nullptr;
            }
            supp_gids.push_back(*supp_gid);
        }
    }

    return std::make_unique<Service>(name, flags, *uid, *gid, supp_gids, no_capabilities,
                                     namespace_flags, seclabel, nullptr, str_args);
}

// Shutdown services in the opposite order that they were started.
const std::vector<Service*> ServiceList::services_in_shutdown_order() const {
    std::vector<Service*> shutdown_services;
    for (const auto& service : services_) {
        if (service->start_order() > 0) shutdown_services.emplace_back(service.get());
    }
    std::sort(shutdown_services.begin(), shutdown_services.end(),
              [](const auto& a, const auto& b) { return a->start_order() > b->start_order(); });
    return shutdown_services;
}

void ServiceList::RemoveService(const Service& svc) {
    auto svc_it = std::find_if(services_.begin(), services_.end(),
                               [&svc] (const std::unique_ptr<Service>& s) {
                                   return svc.name() == s->name();
                               });
    if (svc_it == services_.end()) {
        return;
    }

    services_.erase(svc_it);
}

void ServiceList::DumpState() const {
    for (const auto& s : services_) {
        s->DumpState();
    }
}

Result<Success> ServiceParser::ParseSection(std::vector<std::string>&& args,
                                            const std::string& filename, int line) {
    if (args.size() < 3) {
        return Error() << "services must have a name and a program";
    }

    const std::string& name = args[1];
    if (!IsValidName(name)) {
        return Error() << "invalid service name '" << name << "'";
    }

    Subcontext* restart_action_subcontext = nullptr;
    if (subcontexts_) {
        for (auto& subcontext : *subcontexts_) {
            if (StartsWith(filename, subcontext.path_prefix().c_str())) {
                restart_action_subcontext = &subcontext;
                break;
            }
        }
    }

    std::vector<std::string> str_args(args.begin() + 2, args.end());
    service_ = std::make_unique<Service>(name, restart_action_subcontext, str_args);
    return Success();
}

Result<Success> ServiceParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    return service_ ? service_->ParseLine(std::move(args)) : Success();
}

Result<Success> ServiceParser::EndSection() {
    if (service_) {
        Service* old_service = service_list_->FindService(service_->name());
        if (old_service) {
            return Error() << "ignored duplicate definition of service '" << service_->name() << "'";
        }

        service_list_->AddService(std::move(service_));
    }

    return Success();
}

bool ServiceParser::IsValidName(const std::string& name) const {
    // Property names can be any length, but may only contain certain characters.
    // Property values can contain any characters, but may only be a certain length.
    // (The latter restriction is needed because `start` and `stop` work by writing
    // the service name to the "ctl.start" and "ctl.stop" properties.)
    return is_legal_property_name("init.svc." + name) && name.size() <= PROP_VALUE_MAX;
}

}  // namespace init
}  // namespace android

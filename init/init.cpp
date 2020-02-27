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

#include "init.h"

#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/signalfd.h>
#include <sys/types.h>
#include <unistd.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <fs_avb/fs_avb.h>
#include <fs_mgr_vendor_overlay.h>
#include <keyutils.h>
#include <libavb/libavb.h>
#include <libgsi/libgsi.h>
#include <processgroup/processgroup.h>
#include <processgroup/setup.h>
#include <selinux/android.h>

#include "action_parser.h"
#include "builtins.h"
#include "epoll.h"
#include "first_stage_init.h"
#include "first_stage_mount.h"
#include "import_parser.h"
#include "keychords.h"
#include "lmkd_service.h"
#include "mount_handler.h"
#include "mount_namespace.h"
#include "property_service.h"
#include "proto_utils.h"
#include "reboot.h"
#include "reboot_utils.h"
#include "security.h"
#include "selabel.h"
#include "selinux.h"
#include "service.h"
#include "service_parser.h"
#include "sigchld_handler.h"
#include "system/core/init/property_service.pb.h"
#include "util.h"

using namespace std::chrono_literals;
using namespace std::string_literals;

using android::base::boot_clock;
using android::base::GetProperty;
using android::base::ReadFileToString;
using android::base::SetProperty;
using android::base::StringPrintf;
using android::base::Timer;
using android::base::Trim;
using android::fs_mgr::AvbHandle;

namespace android {
namespace init {

static int property_triggers_enabled = 0;

static int signal_fd = -1;
static int property_fd = -1;

static std::unique_ptr<Subcontext> subcontext;

// Init epolls various FDs to wait for various inputs.  It previously waited on property changes
// with a blocking socket that contained the information related to the change, however, it was easy
// to fill that socket and deadlock the system.  Now we use locks to handle the property changes
// directly in the property thread, however we still must wake the epoll to inform init that there
// is a change to process, so we use this FD.  It is non-blocking, since we do not care how many
// times WakeEpoll() is called, only that the epoll will wake.
static int wake_epoll_fd = -1;
static void InstallInitNotifier(Epoll* epoll) {
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0, sockets) != 0) {
        PLOG(FATAL) << "Failed to socketpair() between property_service and init";
    }
    int epoll_fd = sockets[0];
    wake_epoll_fd = sockets[1];

    auto drain_socket = [epoll_fd] {
        char buf[512];
        while (read(epoll_fd, buf, sizeof(buf)) > 0) {
        }
    };

    if (auto result = epoll->RegisterHandler(epoll_fd, drain_socket); !result) {
        LOG(FATAL) << result.error();
    }
}

static void WakeEpoll() {
    constexpr char value[] = "1";
    write(wake_epoll_fd, value, sizeof(value));
}

static class PropWaiterState {
  public:
    bool StartWaiting(const char* name, const char* value) {
        auto lock = std::lock_guard{lock_};
        if (waiting_for_prop_) {
            return false;
        }
        if (GetProperty(name, "") != value) {
            // Current property value is not equal to expected value
            wait_prop_name_ = name;
            wait_prop_value_ = value;
            waiting_for_prop_.reset(new Timer());
        } else {
            LOG(INFO) << "start_waiting_for_property(\"" << name << "\", \"" << value
                      << "\"): already set";
        }
        return true;
    }

    void ResetWaitForProp() {
        auto lock = std::lock_guard{lock_};
        ResetWaitForPropLocked();
    }

    void CheckAndResetWait(const std::string& name, const std::string& value) {
        auto lock = std::lock_guard{lock_};
        // We always record how long init waited for ueventd to tell us cold boot finished.
        // If we aren't waiting on this property, it means that ueventd finished before we even
        // started to wait.
        if (name == kColdBootDoneProp) {
            auto time_waited = waiting_for_prop_ ? waiting_for_prop_->duration().count() : 0;
            std::thread([time_waited] {
                SetProperty("ro.boottime.init.cold_boot_wait", std::to_string(time_waited));
            }).detach();
        }

        if (waiting_for_prop_) {
            if (wait_prop_name_ == name && wait_prop_value_ == value) {
                LOG(INFO) << "Wait for property '" << wait_prop_name_ << "=" << wait_prop_value_
                          << "' took " << *waiting_for_prop_;
                ResetWaitForPropLocked();
                WakeEpoll();
            }
        }
    }

    // This is not thread safe because it releases the lock when it returns, so the waiting state
    // may change.  However, we only use this function to prevent running commands in the main
    // thread loop when we are waiting, so we do not care about false positives; only false
    // negatives.  StartWaiting() and this function are always called from the same thread, so false
    // negatives are not possible and therefore we're okay.
    bool MightBeWaiting() {
        auto lock = std::lock_guard{lock_};
        return static_cast<bool>(waiting_for_prop_);
    }

  private:
    void ResetWaitForPropLocked() {
        wait_prop_name_.clear();
        wait_prop_value_.clear();
        waiting_for_prop_.reset();
    }

    std::mutex lock_;
    std::unique_ptr<Timer> waiting_for_prop_{nullptr};
    std::string wait_prop_name_;
    std::string wait_prop_value_;

} prop_waiter_state;

bool start_waiting_for_property(const char* name, const char* value) {
    return prop_waiter_state.StartWaiting(name, value);
}

void ResetWaitForProp() {
    prop_waiter_state.ResetWaitForProp();
}

static class ShutdownState {
  public:
    void TriggerShutdown(const std::string& command) {
        // We can't call HandlePowerctlMessage() directly in this function,
        // because it modifies the contents of the action queue, which can cause the action queue
        // to get into a bad state if this function is called from a command being executed by the
        // action queue.  Instead we set this flag and ensure that shutdown happens before the next
        // command is run in the main init loop.
        auto lock = std::lock_guard{shutdown_command_lock_};
        shutdown_command_ = command;
        do_shutdown_ = true;
        WakeEpoll();
    }

    std::optional<std::string> CheckShutdown() {
        auto lock = std::lock_guard{shutdown_command_lock_};
        if (do_shutdown_ && !IsShuttingDown()) {
            do_shutdown_ = false;
            return shutdown_command_;
        }
        return {};
    }

  private:
    std::mutex shutdown_command_lock_;
    std::string shutdown_command_;
    bool do_shutdown_ = false;
} shutdown_state;

void DumpState() {
    auto lock = std::lock_guard{service_lock};
    ServiceList::GetInstance().DumpState();
    ActionManager::GetInstance().DumpState();
}

Parser CreateParser(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser;

    parser.AddSectionParser("service", std::make_unique<ServiceParser>(
                                               &service_list, subcontext.get(), std::nullopt));
    parser.AddSectionParser("on",
                            std::make_unique<ActionParser>(&action_manager, subcontext.get()));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    return parser;
}

// parser that only accepts new services
Parser CreateServiceOnlyParser(ServiceList& service_list, bool from_apex) {
    Parser parser;

    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(&service_list, subcontext.get(),
                                                            std::nullopt, from_apex));
    return parser;
}

static void LoadBootScripts(ActionManager& action_manager, ServiceList& service_list) {
    Parser parser = CreateParser(action_manager, service_list);

    std::string bootscript = GetProperty("ro.boot.init_rc", "");
    if (bootscript.empty()) {
        parser.ParseConfig("/system/etc/init/hw/init.rc");
        if (!parser.ParseConfig("/system/etc/init")) {
            late_import_paths.emplace_back("/system/etc/init");
        }
        // late_import is available only in Q and earlier release. As we don't
        // have system_ext in those versions, skip late_import for system_ext.
        parser.ParseConfig("/system_ext/etc/init");
        if (!parser.ParseConfig("/product/etc/init")) {
            late_import_paths.emplace_back("/product/etc/init");
        }
        if (!parser.ParseConfig("/odm/etc/init")) {
            late_import_paths.emplace_back("/odm/etc/init");
        }
        if (!parser.ParseConfig("/vendor/etc/init")) {
            late_import_paths.emplace_back("/vendor/etc/init");
        }
    } else {
        parser.ParseConfig(bootscript);
    }
}

void PropertyChanged(const std::string& name, const std::string& value) {
    // If the property is sys.powerctl, we bypass the event queue and immediately handle it.
    // This is to ensure that init will always and immediately shutdown/reboot, regardless of
    // if there are other pending events to process or if init is waiting on an exec service or
    // waiting on a property.
    // In non-thermal-shutdown case, 'shutdown' trigger will be fired to let device specific
    // commands to be executed.
    if (name == "sys.powerctl") {
        trigger_shutdown(value);
    }

    if (property_triggers_enabled) {
        ActionManager::GetInstance().QueuePropertyChange(name, value);
        WakeEpoll();
    }

    prop_waiter_state.CheckAndResetWait(name, value);
}

static std::optional<boot_clock::time_point> HandleProcessActions() {
    std::optional<boot_clock::time_point> next_process_action_time;
    auto lock = std::lock_guard{service_lock};
    for (const auto& s : ServiceList::GetInstance()) {
        if ((s->flags() & SVC_RUNNING) && s->timeout_period()) {
            auto timeout_time = s->time_started() + *s->timeout_period();
            if (boot_clock::now() > timeout_time) {
                s->Timeout();
            } else {
                if (!next_process_action_time || timeout_time < *next_process_action_time) {
                    next_process_action_time = timeout_time;
                }
            }
        }

        if (!(s->flags() & SVC_RESTARTING)) continue;

        auto restart_time = s->time_started() + s->restart_period();
        if (boot_clock::now() > restart_time) {
            if (auto result = s->Start(); !result.ok()) {
                LOG(ERROR) << "Could not restart process '" << s->name() << "': " << result.error();
            }
        } else {
            if (!next_process_action_time || restart_time < *next_process_action_time) {
                next_process_action_time = restart_time;
            }
        }
    }
    return next_process_action_time;
}

static Result<void> DoControlStart(Service* service) REQUIRES(service_lock) {
    return service->Start();
}

static Result<void> DoControlStop(Service* service) {
    service->Stop();
    return {};
}

static Result<void> DoControlRestart(Service* service) REQUIRES(service_lock) {
    service->Restart();
    return {};
}

enum class ControlTarget {
    SERVICE,    // function gets called for the named service
    INTERFACE,  // action gets called for every service that holds this interface
};

struct ControlMessageFunction {
    ControlTarget target;
    std::function<Result<void>(Service*)> action;
};

static const std::map<std::string, ControlMessageFunction>& get_control_message_map() {
    // clang-format off
    static const std::map<std::string, ControlMessageFunction> control_message_functions = {
        {"sigstop_on",        {ControlTarget::SERVICE,
                               [](auto* service) { service->set_sigstop(true); return Result<void>{}; }}},
        {"sigstop_off",       {ControlTarget::SERVICE,
                               [](auto* service) { service->set_sigstop(false); return Result<void>{}; }}},
        {"start",             {ControlTarget::SERVICE,   DoControlStart}},
        {"stop",              {ControlTarget::SERVICE,   DoControlStop}},
        {"restart",           {ControlTarget::SERVICE,   DoControlRestart}},
        {"interface_start",   {ControlTarget::INTERFACE, DoControlStart}},
        {"interface_stop",    {ControlTarget::INTERFACE, DoControlStop}},
        {"interface_restart", {ControlTarget::INTERFACE, DoControlRestart}},
    };
    // clang-format on

    return control_message_functions;
}

bool HandleControlMessage(const std::string& msg, const std::string& name, pid_t from_pid) {
    const auto& map = get_control_message_map();
    const auto it = map.find(msg);

    if (it == map.end()) {
        LOG(ERROR) << "Unknown control msg '" << msg << "'";
        return false;
    }

    std::string cmdline_path = StringPrintf("proc/%d/cmdline", from_pid);
    std::string process_cmdline;
    if (ReadFileToString(cmdline_path, &process_cmdline)) {
        std::replace(process_cmdline.begin(), process_cmdline.end(), '\0', ' ');
        process_cmdline = Trim(process_cmdline);
    } else {
        process_cmdline = "unknown process";
    }

    const ControlMessageFunction& function = it->second;

    auto lock = std::lock_guard{service_lock};

    Service* svc = nullptr;

    switch (function.target) {
        case ControlTarget::SERVICE:
            svc = ServiceList::GetInstance().FindService(name);
            break;
        case ControlTarget::INTERFACE:
            svc = ServiceList::GetInstance().FindInterface(name);
            break;
        default:
            LOG(ERROR) << "Invalid function target from static map key ctl." << msg << ": "
                       << static_cast<std::underlying_type<ControlTarget>::type>(function.target);
            return false;
    }

    if (svc == nullptr) {
        LOG(ERROR) << "Control message: Could not find '" << name << "' for ctl." << msg
                   << " from pid: " << from_pid << " (" << process_cmdline << ")";
        return false;
    }

    if (auto result = function.action(svc); !result.ok()) {
        LOG(ERROR) << "Control message: Could not ctl." << msg << " for '" << name
                   << "' from pid: " << from_pid << " (" << process_cmdline
                   << "): " << result.error();
        return false;
    }

    LOG(INFO) << "Control message: Processed ctl." << msg << " for '" << name
              << "' from pid: " << from_pid << " (" << process_cmdline << ")";
    return true;
}

static Result<void> wait_for_coldboot_done_action(const BuiltinArguments& args) {
    if (!prop_waiter_state.StartWaiting(kColdBootDoneProp, "true")) {
        LOG(FATAL) << "Could not wait for '" << kColdBootDoneProp << "'";
    }

    return {};
}

static Result<void> SetupCgroupsAction(const BuiltinArguments&) {
    // Have to create <CGROUPS_RC_DIR> using make_dir function
    // for appropriate sepolicy to be set for it
    make_dir(android::base::Dirname(CGROUPS_RC_PATH), 0711);
    if (!CgroupSetup()) {
        return ErrnoError() << "Failed to setup cgroups";
    }

    return {};
}

static void export_oem_lock_status() {
    if (!android::base::GetBoolProperty("ro.oem_unlock_supported", false)) {
        return;
    }
    ImportKernelCmdline([](const std::string& key, const std::string& value) {
        if (key == "androidboot.verifiedbootstate") {
            SetProperty("ro.boot.flash.locked", value == "orange" ? "0" : "1");
        }
    });
}

static Result<void> property_enable_triggers_action(const BuiltinArguments& args) {
    /* Enable property triggers. */
    property_triggers_enabled = 1;
    return {};
}

static Result<void> queue_property_triggers_action(const BuiltinArguments& args) {
    ActionManager::GetInstance().QueueBuiltinAction(property_enable_triggers_action, "enable_property_trigger");
    ActionManager::GetInstance().QueueAllPropertyActions();
    return {};
}

// Set the UDC controller for the ConfigFS USB Gadgets.
// Read the UDC controller in use from "/sys/class/udc".
// In case of multiple UDC controllers select the first one.
static void set_usb_controller() {
    std::unique_ptr<DIR, decltype(&closedir)>dir(opendir("/sys/class/udc"), closedir);
    if (!dir) return;

    dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (dp->d_name[0] == '.') continue;

        SetProperty("sys.usb.controller", dp->d_name);
        break;
    }
}

static void HandleSigtermSignal(const signalfd_siginfo& siginfo) {
    if (siginfo.ssi_pid != 0) {
        // Drop any userspace SIGTERM requests.
        LOG(DEBUG) << "Ignoring SIGTERM from pid " << siginfo.ssi_pid;
        return;
    }

    HandlePowerctlMessage("shutdown,container");
}

static void HandleSignalFd() {
    signalfd_siginfo siginfo;
    ssize_t bytes_read = TEMP_FAILURE_RETRY(read(signal_fd, &siginfo, sizeof(siginfo)));
    if (bytes_read != sizeof(siginfo)) {
        PLOG(ERROR) << "Failed to read siginfo from signal_fd";
        return;
    }

    switch (siginfo.ssi_signo) {
        case SIGCHLD:
            ReapAnyOutstandingChildren();
            break;
        case SIGTERM:
            HandleSigtermSignal(siginfo);
            break;
        default:
            PLOG(ERROR) << "signal_fd: received unexpected signal " << siginfo.ssi_signo;
            break;
    }
}

static void UnblockSignals() {
    const struct sigaction act { .sa_handler = SIG_DFL };
    sigaction(SIGCHLD, &act, nullptr);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigaddset(&mask, SIGTERM);

    if (sigprocmask(SIG_UNBLOCK, &mask, nullptr) == -1) {
        PLOG(FATAL) << "failed to unblock signals for PID " << getpid();
    }
}

static void InstallSignalFdHandler(Epoll* epoll) {
    // Applying SA_NOCLDSTOP to a defaulted SIGCHLD handler prevents the signalfd from receiving
    // SIGCHLD when a child process stops or continues (b/77867680#comment9).
    const struct sigaction act { .sa_handler = SIG_DFL, .sa_flags = SA_NOCLDSTOP };
    sigaction(SIGCHLD, &act, nullptr);

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    if (!IsRebootCapable()) {
        // If init does not have the CAP_SYS_BOOT capability, it is running in a container.
        // In that case, receiving SIGTERM will cause the system to shut down.
        sigaddset(&mask, SIGTERM);
    }

    if (sigprocmask(SIG_BLOCK, &mask, nullptr) == -1) {
        PLOG(FATAL) << "failed to block signals";
    }

    // Register a handler to unblock signals in the child processes.
    const int result = pthread_atfork(nullptr, nullptr, &UnblockSignals);
    if (result != 0) {
        LOG(FATAL) << "Failed to register a fork handler: " << strerror(result);
    }

    signal_fd = signalfd(-1, &mask, SFD_CLOEXEC);
    if (signal_fd == -1) {
        PLOG(FATAL) << "failed to create signalfd";
    }

    if (auto result = epoll->RegisterHandler(signal_fd, HandleSignalFd); !result.ok()) {
        LOG(FATAL) << result.error();
    }
}

void HandleKeychord(const std::vector<int>& keycodes) {
    // Only handle keychords if adb is enabled.
    std::string adb_enabled = android::base::GetProperty("init.svc.adbd", "");
    if (adb_enabled != "running") {
        LOG(WARNING) << "Not starting service for keychord " << android::base::Join(keycodes, ' ')
                     << " because ADB is disabled";
        return;
    }

    auto found = false;
    auto lock = std::lock_guard{service_lock};
    for (const auto& service : ServiceList::GetInstance()) {
        auto svc = service.get();
        if (svc->keycodes() == keycodes) {
            found = true;
            LOG(INFO) << "Starting service '" << svc->name() << "' from keychord "
                      << android::base::Join(keycodes, ' ');
            if (auto result = svc->Start(); !result.ok()) {
                LOG(ERROR) << "Could not start service '" << svc->name() << "' from keychord "
                           << android::base::Join(keycodes, ' ') << ": " << result.error();
            }
        }
    }
    if (!found) {
        LOG(ERROR) << "Service for keychord " << android::base::Join(keycodes, ' ') << " not found";
    }
}

static void UmountDebugRamdisk() {
    if (umount("/debug_ramdisk") != 0) {
        PLOG(ERROR) << "Failed to umount /debug_ramdisk";
    }
}

static void MountExtraFilesystems() {
#define CHECKCALL(x) \
    if ((x) != 0) PLOG(FATAL) << #x " failed.";

    // /apex is used to mount APEXes
    CHECKCALL(mount("tmpfs", "/apex", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=0"));

    // /linkerconfig is used to keep generated linker configuration
    CHECKCALL(mount("tmpfs", "/linkerconfig", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=0"));
#undef CHECKCALL
}

static void RecordStageBoottimes(const boot_clock::time_point& second_stage_start_time) {
    int64_t first_stage_start_time_ns = -1;
    if (auto first_stage_start_time_str = getenv(kEnvFirstStageStartedAt);
        first_stage_start_time_str) {
        SetProperty("ro.boottime.init", first_stage_start_time_str);
        android::base::ParseInt(first_stage_start_time_str, &first_stage_start_time_ns);
    }
    unsetenv(kEnvFirstStageStartedAt);

    int64_t selinux_start_time_ns = -1;
    if (auto selinux_start_time_str = getenv(kEnvSelinuxStartedAt); selinux_start_time_str) {
        android::base::ParseInt(selinux_start_time_str, &selinux_start_time_ns);
    }
    unsetenv(kEnvSelinuxStartedAt);

    if (selinux_start_time_ns == -1) return;
    if (first_stage_start_time_ns == -1) return;

    SetProperty("ro.boottime.init.first_stage",
                std::to_string(selinux_start_time_ns - first_stage_start_time_ns));
    SetProperty("ro.boottime.init.selinux",
                std::to_string(second_stage_start_time.time_since_epoch().count() -
                               selinux_start_time_ns));
}

void SendLoadPersistentPropertiesMessage() {
    auto init_message = InitMessage{};
    init_message.set_load_persistent_properties(true);
    if (auto result = SendMessage(property_fd, init_message); !result.ok()) {
        LOG(ERROR) << "Failed to send load persistent properties message: " << result.error();
    }
}

void SendStopSendingMessagesMessage() {
    auto init_message = InitMessage{};
    init_message.set_stop_sending_messages(true);
    if (auto result = SendMessage(property_fd, init_message); !result.ok()) {
        LOG(ERROR) << "Failed to send 'stop sending messages' message: " << result.error();
    }
}

void SendStartSendingMessagesMessage() {
    auto init_message = InitMessage{};
    init_message.set_start_sending_messages(true);
    if (auto result = SendMessage(property_fd, init_message); !result.ok()) {
        LOG(ERROR) << "Failed to send 'start sending messages' message: " << result.error();
    }
}

int SecondStageMain(int argc, char** argv) {
    if (REBOOT_BOOTLOADER_ON_PANIC) {
        InstallRebootSignalHandlers();
    }

    boot_clock::time_point start_time = boot_clock::now();

    trigger_shutdown = [](const std::string& command) { shutdown_state.TriggerShutdown(command); };

    SetStdioToDevNull(argv);
    InitKernelLogging(argv);
    LOG(INFO) << "init second stage started!";

    // Will handle EPIPE at the time of write by checking the errno
    signal(SIGPIPE, SIG_IGN);

    // Set init and its forked children's oom_adj.
    if (auto result =
                WriteFile("/proc/1/oom_score_adj", StringPrintf("%d", DEFAULT_OOM_SCORE_ADJUST));
        !result.ok()) {
        LOG(ERROR) << "Unable to write " << DEFAULT_OOM_SCORE_ADJUST
                   << " to /proc/1/oom_score_adj: " << result.error();
    }

    // Set up a session keyring that all processes will have access to. It
    // will hold things like FBE encryption keys. No process should override
    // its session keyring.
    keyctl_get_keyring_ID(KEY_SPEC_SESSION_KEYRING, 1);

    // Indicate that booting is in progress to background fw loaders, etc.
    close(open("/dev/.booting", O_WRONLY | O_CREAT | O_CLOEXEC, 0000));

    // See if need to load debug props to allow adb root, when the device is unlocked.
    const char* force_debuggable_env = getenv("INIT_FORCE_DEBUGGABLE");
    bool load_debug_prop = false;
    if (force_debuggable_env && AvbHandle::IsDeviceUnlocked()) {
        load_debug_prop = "true"s == force_debuggable_env;
    }
    unsetenv("INIT_FORCE_DEBUGGABLE");

    // Umount the debug ramdisk so property service doesn't read .prop files from there, when it
    // is not meant to.
    if (!load_debug_prop) {
        UmountDebugRamdisk();
    }

    PropertyInit();

    // Umount the debug ramdisk after property service has read the .prop files when it means to.
    if (load_debug_prop) {
        UmountDebugRamdisk();
    }

    // Mount extra filesystems required during second stage init
    MountExtraFilesystems();

    // Now set up SELinux for second stage.
    SelinuxSetupKernelLogging();
    SelabelInitialize();
    SelinuxRestoreContext();

    Epoll epoll;
    if (auto result = epoll.Open(); !result.ok()) {
        PLOG(FATAL) << result.error();
    }

    InstallSignalFdHandler(&epoll);
    InstallInitNotifier(&epoll);
    StartPropertyService(&property_fd);

    // Make the time that init stages started available for bootstat to log.
    RecordStageBoottimes(start_time);

    // Set libavb version for Framework-only OTA match in Treble build.
    if (const char* avb_version = getenv("INIT_AVB_VERSION"); avb_version != nullptr) {
        SetProperty("ro.boot.avb_version", avb_version);
    }
    unsetenv("INIT_AVB_VERSION");

    fs_mgr_vendor_overlay_mount_all();
    export_oem_lock_status();
    MountHandler mount_handler(&epoll);
    set_usb_controller();

    const BuiltinFunctionMap& function_map = GetBuiltinFunctionMap();
    Action::set_function_map(&function_map);

    if (!SetupMountNamespaces()) {
        PLOG(FATAL) << "SetupMountNamespaces failed";
    }

    subcontext = InitializeSubcontext();

    ActionManager& am = ActionManager::GetInstance();
    ServiceList& sm = ServiceList::GetInstance();

    LoadBootScripts(am, sm);

    // Turning this on and letting the INFO logging be discarded adds 0.2s to
    // Nexus 9 boot time, so it's disabled by default.
    if (false) DumpState();

    // Make the GSI status available before scripts start running.
    if (android::gsi::IsGsiRunning()) {
        SetProperty("ro.gsid.image_running", "1");
    } else {
        SetProperty("ro.gsid.image_running", "0");
    }

    am.QueueBuiltinAction(SetupCgroupsAction, "SetupCgroups");
    am.QueueBuiltinAction(SetKptrRestrictAction, "SetKptrRestrict");
    am.QueueBuiltinAction(TestPerfEventSelinuxAction, "TestPerfEventSelinux");
    am.QueueEventTrigger("early-init");

    // Queue an action that waits for coldboot done so we know ueventd has set up all of /dev...
    am.QueueBuiltinAction(wait_for_coldboot_done_action, "wait_for_coldboot_done");
    // ... so that we can start queuing up actions that require stuff from /dev.
    am.QueueBuiltinAction(MixHwrngIntoLinuxRngAction, "MixHwrngIntoLinuxRng");
    am.QueueBuiltinAction(SetMmapRndBitsAction, "SetMmapRndBits");
    Keychords keychords;
    am.QueueBuiltinAction(
            [&epoll, &keychords](const BuiltinArguments& args) -> Result<void> {
                auto lock = std::lock_guard{service_lock};
                for (const auto& svc : ServiceList::GetInstance()) {
                    keychords.Register(svc->keycodes());
                }
                keychords.Start(&epoll, HandleKeychord);
                return {};
            },
            "KeychordInit");

    // Trigger all the boot actions to get us started.
    am.QueueEventTrigger("init");

    // Repeat mix_hwrng_into_linux_rng in case /dev/hw_random or /dev/random
    // wasn't ready immediately after wait_for_coldboot_done
    am.QueueBuiltinAction(MixHwrngIntoLinuxRngAction, "MixHwrngIntoLinuxRng");

    // Don't mount filesystems or start core system services in charger mode.
    std::string bootmode = GetProperty("ro.bootmode", "");
    if (bootmode == "charger") {
        am.QueueEventTrigger("charger");
    } else {
        am.QueueEventTrigger("late-init");
    }

    // Run all property triggers based on current state of the properties.
    am.QueueBuiltinAction(queue_property_triggers_action, "queue_property_triggers");

    while (true) {
        // By default, sleep until something happens.
        auto epoll_timeout = std::optional<std::chrono::milliseconds>{};

        auto shutdown_command = shutdown_state.CheckShutdown();
        if (shutdown_command) {
            HandlePowerctlMessage(*shutdown_command);
        }

        if (!(prop_waiter_state.MightBeWaiting() || Service::is_exec_service_running())) {
            am.ExecuteOneCommand();
        }
        if (!IsShuttingDown()) {
            auto next_process_action_time = HandleProcessActions();

            // If there's a process that needs restarting, wake up in time for that.
            if (next_process_action_time) {
                epoll_timeout = std::chrono::ceil<std::chrono::milliseconds>(
                        *next_process_action_time - boot_clock::now());
                if (*epoll_timeout < 0ms) epoll_timeout = 0ms;
            }
        }

        if (!(prop_waiter_state.MightBeWaiting() || Service::is_exec_service_running())) {
            // If there's more work to do, wake up again immediately.
            if (am.HasMoreCommands()) epoll_timeout = 0ms;
        }

        auto pending_functions = epoll.Wait(epoll_timeout);
        if (!pending_functions.ok()) {
            LOG(ERROR) << pending_functions.error();
        } else if (!pending_functions->empty()) {
            // We always reap children before responding to the other pending functions. This is to
            // prevent a race where other daemons see that a service has exited and ask init to
            // start it again via ctl.start before init has reaped it.
            ReapAnyOutstandingChildren();
            for (const auto& function : *pending_functions) {
                (*function)();
            }
        }
    }

    return 0;
}

}  // namespace init
}  // namespace android

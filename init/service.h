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

#ifndef _INIT_SERVICE_H
#define _INIT_SERVICE_H

#include <sys/types.h>

#include <cutils/iosched_policy.h>

#include <memory>
#include <string>
#include <vector>

#include "action.h"
#include "init_parser.h"
#include "keyword_map.h"

#define SVC_DISABLED       0x001  // do not autostart with class
#define SVC_ONESHOT        0x002  // do not restart on exit
#define SVC_RUNNING        0x004  // currently active
#define SVC_RESTARTING     0x008  // waiting to restart
#define SVC_CONSOLE        0x010  // requires console
#define SVC_CRITICAL       0x020  // will reboot into recovery if keeps crashing
#define SVC_RESET          0x040  // Use when stopping a process,
                                  // but not disabling so it can be restarted with its class.
#define SVC_RC_DISABLED    0x080  // Remember if the disabled flag was set in the rc script.
#define SVC_RESTART        0x100  // Use to safely restart (stop, wait, start) a service.
#define SVC_DISABLED_START 0x200  // A start was requested but it was disabled at the time.
#define SVC_EXEC           0x400  // This synthetic service corresponds to an 'exec'.

#define NR_SVC_SUPP_GIDS 12    // twelve supplementary groups

class Action;
class ServiceManager;

struct SocketInfo {
    SocketInfo();
    SocketInfo(const std::string& name, const std::string& type, uid_t uid,
                       gid_t gid, int perm, const std::string& socketcon);
    std::string name;
    std::string type;
    uid_t uid;
    gid_t gid;
    int perm;
    std::string socketcon;
};

struct ServiceEnvironmentInfo {
    ServiceEnvironmentInfo();
    ServiceEnvironmentInfo(const std::string& name, const std::string& value);
    std::string name;
    std::string value;
};

class Service {
public:
    Service(const std::string& name, const std::string& classname,
            const std::vector<std::string>& args);

    Service(const std::string& name, const std::string& classname,
            unsigned flags, uid_t uid, gid_t gid, const std::vector<gid_t>& supp_gids,
            const std::string& seclabel,  const std::vector<std::string>& args);

    bool HandleLine(const std::vector<std::string>& args, std::string* err);
    bool Start(const std::vector<std::string>& dynamic_args);
    bool Start();
    bool StartIfNotDisabled();
    bool Enable();
    void Reset();
    void Stop();
    void Terminate();
    void Restart();
    void RestartIfNeeded(time_t& process_needs_restart);
    bool Reap();
    void DumpState() const;

    const std::string& name() const { return name_; }
    const std::string& classname() const { return classname_; }
    unsigned flags() const { return flags_; }
    pid_t pid() const { return pid_; }
    uid_t uid() const { return uid_; }
    gid_t gid() const { return gid_; }
    const std::vector<gid_t>& supp_gids() const { return supp_gids_; }
    const std::string& seclabel() const { return seclabel_; }
    const std::vector<int>& keycodes() const { return keycodes_; }
    int keychord_id() const { return keychord_id_; }
    void set_keychord_id(int keychord_id) { keychord_id_ = keychord_id; }
    const std::vector<std::string>& args() const { return args_; }

private:
    using OptionHandler = bool (Service::*) (const std::vector<std::string>& args,
                                             std::string* err);
    class OptionHandlerMap;

    void NotifyStateChange(const std::string& new_state) const;
    void StopOrReset(int how);
    void ZapStdio() const;
    void OpenConsole() const;
    void PublishSocket(const std::string& name, int fd) const;

    bool HandleClass(const std::vector<std::string>& args, std::string* err);
    bool HandleConsole(const std::vector<std::string>& args, std::string* err);
    bool HandleCritical(const std::vector<std::string>& args, std::string* err);
    bool HandleDisabled(const std::vector<std::string>& args, std::string* err);
    bool HandleGroup(const std::vector<std::string>& args, std::string* err);
    bool HandleIoprio(const std::vector<std::string>& args, std::string* err);
    bool HandleKeycodes(const std::vector<std::string>& args, std::string* err);
    bool HandleOneshot(const std::vector<std::string>& args, std::string* err);
    bool HandleOnrestart(const std::vector<std::string>& args, std::string* err);
    bool HandleSeclabel(const std::vector<std::string>& args, std::string* err);
    bool HandleSetenv(const std::vector<std::string>& args, std::string* err);
    bool HandleSocket(const std::vector<std::string>& args, std::string* err);
    bool HandleUser(const std::vector<std::string>& args, std::string* err);
    bool HandleWritepid(const std::vector<std::string>& args, std::string* err);

    std::string name_;
    std::string classname_;
    std::string console_;

    unsigned flags_;
    pid_t pid_;
    time_t time_started_;    // time of last start
    time_t time_crashed_;    // first crash within inspection window
    int nr_crashed_;         // number of times crashed within window

    uid_t uid_;
    gid_t gid_;
    std::vector<gid_t> supp_gids_;

    std::string seclabel_;

    std::vector<SocketInfo> sockets_;
    std::vector<ServiceEnvironmentInfo> envvars_;

    Action onrestart_;  // Commands to execute on restart.

    std::vector<std::string> writepid_files_;

    // keycodes for triggering this service via /dev/keychord
    std::vector<int> keycodes_;
    int keychord_id_;

    IoSchedClass ioprio_class_;
    int ioprio_pri_;

    std::vector<std::string> args_;
};

class ServiceManager {
public:
    static ServiceManager& GetInstance();

    void AddService(std::unique_ptr<Service> service);
    Service* MakeExecOneshotService(const std::vector<std::string>& args);
    Service* FindServiceByName(const std::string& name) const;
    Service* FindServiceByPid(pid_t pid) const;
    Service* FindServiceByKeychord(int keychord_id) const;
    void ForEachService(std::function<void(Service*)> callback) const;
    void ForEachServiceInClass(const std::string& classname,
                               void (*func)(Service* svc)) const;
    void ForEachServiceWithFlags(unsigned matchflags,
                             void (*func)(Service* svc)) const;
    void ReapAnyOutstandingChildren();
    void RemoveService(const Service& svc);
    void DumpState() const;

private:
    ServiceManager();

    // Cleans up a child process that exited.
    // Returns true iff a children was cleaned up.
    bool ReapOneProcess();

    static int exec_count_; // Every service needs a unique name.
    std::vector<std::unique_ptr<Service>> services_;
};

class ServiceParser : public SectionParser {
public:
    ServiceParser() : service_(nullptr) {
    }
    bool ParseSection(const std::vector<std::string>& args,
                      std::string* err) override;
    bool ParseLineSection(const std::vector<std::string>& args,
                          const std::string& filename, int line,
                          std::string* err) const override;
    void EndSection() override;
    void EndFile(const std::string&) override {
    }
private:
    bool IsValidName(const std::string& name) const;

    std::unique_ptr<Service> service_;
};

#endif

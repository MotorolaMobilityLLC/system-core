/*
 * Copyright (C) 2019 The Android Open Source Project
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

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <fcntl.h>
#include <task_profiles.h>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/threads.h>

#include <cutils/android_filesystem_config.h>

#include <json/reader.h>
#include <json/value.h>

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)
#include <sys/prctl.h>
#endif

using android::base::GetThreadId;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;

#define TASK_PROFILE_DB_FILE "/etc/task_profiles.json"
#define TASK_PROFILE_DB_VENDOR_FILE "/vendor/etc/task_profiles.json"

bool ProfileAttribute::GetPathForTask(int tid, std::string* path) const {
    std::string subgroup;
    if (!controller()->GetTaskGroup(tid, &subgroup)) {
        return false;
    }

    if (path == nullptr) {
        return true;
    }

    if (subgroup.empty()) {
        *path = StringPrintf("%s/%s", controller()->path(), file_name_.c_str());
    } else {
        *path = StringPrintf("%s/%s/%s", controller()->path(), subgroup.c_str(),
                             file_name_.c_str());
    }
    return true;
}

bool SetClampsAction::ExecuteForProcess(uid_t, pid_t) const {
    // TODO: add support when kernel supports util_clamp
    LOG(WARNING) << "SetClampsAction::ExecuteForProcess is not supported";
    return false;
}

bool SetClampsAction::ExecuteForTask(int) const {
    // TODO: add support when kernel supports util_clamp
    LOG(WARNING) << "SetClampsAction::ExecuteForTask is not supported";
    return false;
}

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

bool SetTimerSlackAction::IsTimerSlackSupported(int tid) {
    auto file = StringPrintf("/proc/%d/timerslack_ns", tid);

    return (access(file.c_str(), W_OK) == 0);
}

bool SetTimerSlackAction::ExecuteForTask(int tid) const {
    static bool sys_supports_timerslack = IsTimerSlackSupported(tid);

    // v4.6+ kernels support the /proc/<tid>/timerslack_ns interface.
    // TODO: once we've backported this, log if the open(2) fails.
    if (sys_supports_timerslack) {
        auto file = StringPrintf("/proc/%d/timerslack_ns", tid);
        if (!WriteStringToFile(std::to_string(slack_), file)) {
            if (errno == ENOENT) {
                // This happens when process is already dead
                return true;
            }
            PLOG(ERROR) << "set_timerslack_ns write failed";
        }
    }

    // TODO: Remove when /proc/<tid>/timerslack_ns interface is backported.
    if (tid == 0 || tid == GetThreadId()) {
        if (prctl(PR_SET_TIMERSLACK, slack_) == -1) {
            PLOG(ERROR) << "set_timerslack_ns prctl failed";
        }
    }

    return true;
}

#endif

bool SetAttributeAction::ExecuteForProcess(uid_t, pid_t pid) const {
    return ExecuteForTask(pid);
}

bool SetAttributeAction::ExecuteForTask(int tid) const {
    std::string path;

    if (!attribute_->GetPathForTask(tid, &path)) {
        LOG(ERROR) << "Failed to find cgroup for tid " << tid;
        return false;
    }

    if (!WriteStringToFile(value_, path)) {
        PLOG(ERROR) << "Failed to write '" << value_ << "' to " << path;
        return false;
    }

    return true;
}

bool SetCgroupAction::IsAppDependentPath(const std::string& path) {
    return path.find("<uid>", 0) != std::string::npos || path.find("<pid>", 0) != std::string::npos;
}

SetCgroupAction::SetCgroupAction(const CgroupController& c, const std::string& p)
    : controller_(c), path_(p) {
    // file descriptors for app-dependent paths can't be cached
    if (IsAppDependentPath(path_)) {
        // file descriptor is not cached
        fd_.reset(FDS_APP_DEPENDENT);
        return;
    }

    // file descriptor can be cached later on request
    fd_.reset(FDS_NOT_CACHED);
}

void SetCgroupAction::EnableResourceCaching() {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (fd_ != FDS_NOT_CACHED) {
        return;
    }

    std::string tasks_path = controller_.GetTasksFilePath(path_);

    if (access(tasks_path.c_str(), W_OK) != 0) {
        // file is not accessible
        fd_.reset(FDS_INACCESSIBLE);
        return;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(tasks_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to cache fd '" << tasks_path << "'";
        fd_.reset(FDS_INACCESSIBLE);
        return;
    }

    fd_ = std::move(fd);
}

void SetCgroupAction::DropResourceCaching() {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (fd_ == FDS_NOT_CACHED) {
        return;
    }

    fd_.reset(FDS_NOT_CACHED);
}

bool SetCgroupAction::AddTidToCgroup(int tid, int fd) {
    if (tid <= 0) {
        return true;
    }

    std::string value = std::to_string(tid);

    if (TEMP_FAILURE_RETRY(write(fd, value.c_str(), value.length())) < 0) {
        // If the thread is in the process of exiting, don't flag an error
        if (errno != ESRCH) {
            PLOG(ERROR) << "AddTidToCgroup failed to write '" << value << "'; fd=" << fd;
            return false;
        }
    }

    return true;
}

bool SetCgroupAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (IsFdValid()) {
        // fd is cached, reuse it
        if (!AddTidToCgroup(pid, fd_)) {
            LOG(ERROR) << "Failed to add task into cgroup";
            return false;
        }
        return true;
    }

    if (fd_ == FDS_INACCESSIBLE) {
        // no permissions to access the file, ignore
        return true;
    }

    // this is app-dependent path and fd is not cached or cached fd can't be used
    std::string procs_path = controller()->GetProcsFilePath(path_, uid, pid);
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(procs_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (tmp_fd < 0) {
        PLOG(WARNING) << "Failed to open " << procs_path;
        return false;
    }
    if (!AddTidToCgroup(pid, tmp_fd)) {
        LOG(ERROR) << "Failed to add task into cgroup";
        return false;
    }

    return true;
}

bool SetCgroupAction::ExecuteForTask(int tid) const {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (IsFdValid()) {
        // fd is cached, reuse it
        if (!AddTidToCgroup(tid, fd_)) {
            LOG(ERROR) << "Failed to add task into cgroup";
            return false;
        }
        return true;
    }

    if (fd_ == FDS_INACCESSIBLE) {
        // no permissions to access the file, ignore
        return true;
    }

    if (fd_ == FDS_APP_DEPENDENT) {
        // application-dependent path can't be used with tid
        PLOG(ERROR) << "Application profile can't be applied to a thread";
        return false;
    }

    // fd was not cached because cached fd can't be used
    std::string tasks_path = controller()->GetTasksFilePath(path_);
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(tasks_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (tmp_fd < 0) {
        PLOG(WARNING) << "Failed to open " << tasks_path << ": " << strerror(errno);
        return false;
    }
    if (!AddTidToCgroup(tid, tmp_fd)) {
        LOG(ERROR) << "Failed to add task into cgroup";
        return false;
    }

    return true;
}

bool TaskProfile::ExecuteForProcess(uid_t uid, pid_t pid) const {
    for (const auto& element : elements_) {
        if (!element->ExecuteForProcess(uid, pid)) {
            return false;
        }
    }
    return true;
}

bool TaskProfile::ExecuteForTask(int tid) const {
    if (tid == 0) {
        tid = GetThreadId();
    }
    for (const auto& element : elements_) {
        if (!element->ExecuteForTask(tid)) {
            return false;
        }
    }
    return true;
}

void TaskProfile::EnableResourceCaching() {
    if (res_cached_) {
        return;
    }

    for (auto& element : elements_) {
        element->EnableResourceCaching();
    }

    res_cached_ = true;
}

void TaskProfile::DropResourceCaching() {
    if (!res_cached_) {
        return;
    }

    for (auto& element : elements_) {
        element->DropResourceCaching();
    }

    res_cached_ = false;
}

void TaskProfiles::DropResourceCaching() const {
    for (auto& iter : profiles_) {
        iter.second->DropResourceCaching();
    }
}

TaskProfiles& TaskProfiles::GetInstance() {
    // Deliberately leak this object to avoid a race between destruction on
    // process exit and concurrent access from another thread.
    static auto* instance = new TaskProfiles;
    return *instance;
}

TaskProfiles::TaskProfiles() {
    // load system task profiles
    if (!Load(CgroupMap::GetInstance(), TASK_PROFILE_DB_FILE)) {
        LOG(ERROR) << "Loading " << TASK_PROFILE_DB_FILE << " for [" << getpid() << "] failed";
    }

    // load vendor task profiles if the file exists
    if (!access(TASK_PROFILE_DB_VENDOR_FILE, F_OK) &&
        !Load(CgroupMap::GetInstance(), TASK_PROFILE_DB_VENDOR_FILE)) {
        LOG(ERROR) << "Loading " << TASK_PROFILE_DB_VENDOR_FILE << " for [" << getpid()
                   << "] failed";
    }
}

bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
    std::string json_doc;

    if (!android::base::ReadFileToString(file_name, &json_doc)) {
        LOG(ERROR) << "Failed to read task profiles from " << file_name;
        return false;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse task profiles: " << reader.getFormattedErrorMessages();
        return false;
    }

    const Json::Value& attr = root["Attributes"];
    for (Json::Value::ArrayIndex i = 0; i < attr.size(); ++i) {
        std::string name = attr[i]["Name"].asString();
        std::string controller_name = attr[i]["Controller"].asString();
        std::string file_attr = attr[i]["File"].asString();

        if (attributes_.find(name) == attributes_.end()) {
            auto controller = cg_map.FindController(controller_name);
            if (controller.HasValue()) {
                attributes_[name] = std::make_unique<ProfileAttribute>(controller, file_attr);
            } else {
                LOG(WARNING) << "Controller " << controller_name << " is not found";
            }
        } else {
            LOG(WARNING) << "Attribute " << name << " is already defined";
        }
    }

    std::map<std::string, std::string> params;

    const Json::Value& profiles_val = root["Profiles"];
    for (Json::Value::ArrayIndex i = 0; i < profiles_val.size(); ++i) {
        const Json::Value& profile_val = profiles_val[i];

        std::string profile_name = profile_val["Name"].asString();
        const Json::Value& actions = profile_val["Actions"];
        auto profile = std::make_unique<TaskProfile>();

        for (Json::Value::ArrayIndex act_idx = 0; act_idx < actions.size(); ++act_idx) {
            const Json::Value& action_val = actions[act_idx];
            std::string action_name = action_val["Name"].asString();
            const Json::Value& params_val = action_val["Params"];
            if (action_name == "JoinCgroup") {
                std::string controller_name = params_val["Controller"].asString();
                std::string path = params_val["Path"].asString();

                auto controller = cg_map.FindController(controller_name);
                if (controller.HasValue()) {
                    profile->Add(std::make_unique<SetCgroupAction>(controller, path));
                } else {
                    LOG(WARNING) << "JoinCgroup: controller " << controller_name << " is not found";
                }
            } else if (action_name == "SetTimerSlack") {
                std::string slack_value = params_val["Slack"].asString();
                char* end;
                unsigned long slack;

                slack = strtoul(slack_value.c_str(), &end, 10);
                if (end > slack_value.c_str()) {
                    profile->Add(std::make_unique<SetTimerSlackAction>(slack));
                } else {
                    LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slack_value;
                }
            } else if (action_name == "SetAttribute") {
                std::string attr_name = params_val["Name"].asString();
                std::string attr_value = params_val["Value"].asString();

                auto iter = attributes_.find(attr_name);
                if (iter != attributes_.end()) {
                    profile->Add(
                            std::make_unique<SetAttributeAction>(iter->second.get(), attr_value));
                } else {
                    LOG(WARNING) << "SetAttribute: unknown attribute: " << attr_name;
                }
            } else if (action_name == "SetClamps") {
                std::string boost_value = params_val["Boost"].asString();
                std::string clamp_value = params_val["Clamp"].asString();
                char* end;
                unsigned long boost;

                boost = strtoul(boost_value.c_str(), &end, 10);
                if (end > boost_value.c_str()) {
                    unsigned long clamp = strtoul(clamp_value.c_str(), &end, 10);
                    if (end > clamp_value.c_str()) {
                        profile->Add(std::make_unique<SetClampsAction>(boost, clamp));
                    } else {
                        LOG(WARNING) << "SetClamps: invalid parameter " << clamp_value;
                    }
                } else {
                    LOG(WARNING) << "SetClamps: invalid parameter: " << boost_value;
                }
            } else {
                LOG(WARNING) << "Unknown profile action: " << action_name;
            }
        }
        profiles_[profile_name] = std::move(profile);
    }

    return true;
}

TaskProfile* TaskProfiles::GetProfile(const std::string& name) const {
    auto iter = profiles_.find(name);

    if (iter != profiles_.end()) {
        return iter->second.get();
    }
    return nullptr;
}

const ProfileAttribute* TaskProfiles::GetAttribute(const std::string& name) const {
    auto iter = attributes_.find(name);

    if (iter != attributes_.end()) {
        return iter->second.get();
    }
    return nullptr;
}

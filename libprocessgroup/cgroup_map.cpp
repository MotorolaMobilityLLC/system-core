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

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <regex>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cgroup_map.h>
#include <json/reader.h>
#include <json/value.h>
#include <processgroup/processgroup.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

static constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
static constexpr const char* CGROUPS_DESC_VENDOR_FILE = "/vendor/etc/cgroups.json";

static constexpr const char* CGROUP_PROCS_FILE = "/cgroup.procs";
static constexpr const char* CGROUP_TASKS_FILE = "/tasks";
static constexpr const char* CGROUP_TASKS_FILE_V2 = "/cgroup.tasks";

static bool Mkdir(const std::string& path, mode_t mode, const std::string& uid,
                  const std::string& gid) {
    if (mode == 0) {
        mode = 0755;
    }

    if (mkdir(path.c_str(), mode) != 0) {
        /* chmod in case the directory already exists */
        if (errno == EEXIST) {
            if (fchmodat(AT_FDCWD, path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0) {
                // /acct is a special case when the directory already exists
                // TODO: check if file mode is already what we want instead of using EROFS
                if (errno != EROFS) {
                    PLOG(ERROR) << "fchmodat() failed for " << path;
                    return false;
                }
            }
        } else {
            PLOG(ERROR) << "mkdir() failed for " << path;
            return false;
        }
    }

    if (uid.empty()) {
        return true;
    }

    passwd* uid_pwd = getpwnam(uid.c_str());
    if (!uid_pwd) {
        PLOG(ERROR) << "Unable to decode UID for '" << uid << "'";
        return false;
    }

    uid_t pw_uid = uid_pwd->pw_uid;
    gid_t gr_gid = -1;
    if (!gid.empty()) {
        group* gid_pwd = getgrnam(gid.c_str());
        if (!gid_pwd) {
            PLOG(ERROR) << "Unable to decode GID for '" << gid << "'";
            return false;
        }
        gr_gid = gid_pwd->gr_gid;
    }

    if (lchown(path.c_str(), pw_uid, gr_gid) < 0) {
        PLOG(ERROR) << "lchown() failed for " << path;
        return false;
    }

    /* chown may have cleared S_ISUID and S_ISGID, chmod again */
    if (mode & (S_ISUID | S_ISGID)) {
        if (fchmodat(AT_FDCWD, path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0) {
            PLOG(ERROR) << "fchmodat() failed for " << path;
            return false;
        }
    }

    return true;
}

static bool ReadDescriptorsFromFile(const std::string& file_name,
                                    std::map<std::string, CgroupDescriptor>* descriptors) {
    std::vector<CgroupDescriptor> result;
    std::string json_doc;

    if (!android::base::ReadFileToString(file_name, &json_doc)) {
        PLOG(ERROR) << "Failed to read task profiles from " << file_name;
        return false;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse cgroups description: " << reader.getFormattedErrorMessages();
        return false;
    }

    if (root.isMember("Cgroups")) {
        const Json::Value& cgroups = root["Cgroups"];
        for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
            std::string name = cgroups[i]["Controller"].asString();
            auto iter = descriptors->find(name);
            if (iter == descriptors->end()) {
                descriptors->emplace(name, CgroupDescriptor(1, name, cgroups[i]["Path"].asString(),
                                     std::strtoul(cgroups[i]["Mode"].asString().c_str(), 0, 8),
                                     cgroups[i]["UID"].asString(), cgroups[i]["GID"].asString()));
            } else {
                iter->second = CgroupDescriptor(1, name, cgroups[i]["Path"].asString(),
                                     std::strtoul(cgroups[i]["Mode"].asString().c_str(), 0, 8),
                                     cgroups[i]["UID"].asString(), cgroups[i]["GID"].asString());
            }
        }
    }

    if (root.isMember("Cgroups2")) {
        const Json::Value& cgroups2 = root["Cgroups2"];
        auto iter = descriptors->find(CGROUPV2_CONTROLLER_NAME);
        if (iter == descriptors->end()) {
            descriptors->emplace(CGROUPV2_CONTROLLER_NAME, CgroupDescriptor(2, CGROUPV2_CONTROLLER_NAME, cgroups2["Path"].asString(),
                                 std::strtoul(cgroups2["Mode"].asString().c_str(), 0, 8),
                                 cgroups2["UID"].asString(), cgroups2["GID"].asString()));
        } else {
            iter->second = CgroupDescriptor(2, CGROUPV2_CONTROLLER_NAME, cgroups2["Path"].asString(),
                                 std::strtoul(cgroups2["Mode"].asString().c_str(), 0, 8),
                                 cgroups2["UID"].asString(), cgroups2["GID"].asString());
        }
    }

    return true;
}

static bool ReadDescriptors(std::map<std::string, CgroupDescriptor>* descriptors) {
    // load system cgroup descriptors
    if (!ReadDescriptorsFromFile(CGROUPS_DESC_FILE, descriptors)) {
        return false;
    }

    // load vendor cgroup descriptors if the file exists
    if (!access(CGROUPS_DESC_VENDOR_FILE, F_OK) &&
        !ReadDescriptorsFromFile(CGROUPS_DESC_VENDOR_FILE, descriptors)) {
        return false;
    }

    return true;
}

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

static bool SetupCgroup(const CgroupDescriptor& descriptor) {
    const CgroupController* controller = descriptor.controller();

    // mkdir <path> [mode] [owner] [group]
    if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
        LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
        return false;
    }

    int result;
    if (controller->version() == 2) {
        result = mount("none", controller->path(), "cgroup2", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                       nullptr);
    } else {
        // Unfortunately historically cpuset controller was mounted using a mount command
        // different from all other controllers. This results in controller attributes not
        // to be prepended with controller name. For example this way instead of
        // /dev/cpuset/cpuset.cpus the attribute becomes /dev/cpuset/cpus which is what
        // the system currently expects.
        if (!strcmp(controller->name(), "cpuset")) {
            // mount cpuset none /dev/cpuset nodev noexec nosuid
            result = mount("none", controller->path(), controller->name(),
                           MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr);
        } else {
            // mount cgroup none <path> nodev noexec nosuid <controller>
            result = mount("none", controller->path(), "cgroup", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                           controller->name());
        }
    }

    if (result < 0) {
        PLOG(ERROR) << "Failed to mount " << controller->name() << " cgroup";
        return false;
    }

    return true;
}

#else

// Stubs for non-Android targets.
static bool SetupCgroup(const CgroupDescriptor&) {
    return false;
}

#endif

// WARNING: This function should be called only from SetupCgroups and only once.
// It intentionally leaks an FD, so additional invocation will result in additional leak.
static bool WriteRcFile(const std::map<std::string, CgroupDescriptor>& descriptors) {
    // WARNING: We are intentionally leaking the FD to keep the file open forever.
    // Let init keep the FD open to prevent file mappings from becoming invalid in
    // case the file gets deleted somehow.
    int fd = TEMP_FAILURE_RETRY(open(CGROUPS_RC_PATH, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
                                     S_IRUSR | S_IRGRP | S_IROTH));
    if (fd < 0) {
        PLOG(ERROR) << "open() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    CgroupFile fl;
    fl.version_ = CgroupFile::FILE_CURR_VERSION;
    fl.controller_count_ = descriptors.size();
    int ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
    if (ret < 0) {
        PLOG(ERROR) << "write() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    for (const auto& [name, descriptor] : descriptors) {
        ret = TEMP_FAILURE_RETRY(write(fd, descriptor.controller(), sizeof(CgroupController)));
        if (ret < 0) {
            PLOG(ERROR) << "write() failed for " << CGROUPS_RC_PATH;
            return false;
        }
    }

    return true;
}

CgroupController::CgroupController(uint32_t version, const std::string& name,
                                   const std::string& path) {
    version_ = version;
    strncpy(name_, name.c_str(), sizeof(name_) - 1);
    name_[sizeof(name_) - 1] = '\0';
    strncpy(path_, path.c_str(), sizeof(path_) - 1);
    path_[sizeof(path_) - 1] = '\0';
}

std::string CgroupController::GetTasksFilePath(const std::string& path) const {
    std::string tasks_path = path_;

    if (!path.empty()) {
        tasks_path += "/" + path;
    }
    return (version_ == 1) ? tasks_path + CGROUP_TASKS_FILE : tasks_path + CGROUP_TASKS_FILE_V2;
}

std::string CgroupController::GetProcsFilePath(const std::string& path, uid_t uid,
                                               pid_t pid) const {
    std::string proc_path(path_);
    proc_path.append("/").append(path);
    proc_path = regex_replace(proc_path, std::regex("<uid>"), std::to_string(uid));
    proc_path = regex_replace(proc_path, std::regex("<pid>"), std::to_string(pid));

    return proc_path.append(CGROUP_PROCS_FILE);
}

bool CgroupController::GetTaskGroup(int tid, std::string* group) const {
    std::string file_name = StringPrintf("/proc/%d/cgroup", tid);
    std::string content;
    if (!android::base::ReadFileToString(file_name, &content)) {
        PLOG(ERROR) << "Failed to read " << file_name;
        return false;
    }

    // if group is null and tid exists return early because
    // user is not interested in cgroup membership
    if (group == nullptr) {
        return true;
    }

    std::string cg_tag = StringPrintf(":%s:", name_);
    size_t start_pos = content.find(cg_tag);
    if (start_pos == std::string::npos) {
        return false;
    }

    start_pos += cg_tag.length() + 1;  // skip '/'
    size_t end_pos = content.find('\n', start_pos);
    if (end_pos == std::string::npos) {
        *group = content.substr(start_pos, std::string::npos);
    } else {
        *group = content.substr(start_pos, end_pos - start_pos);
    }

    return true;
}

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid)
    : controller_(version, name, path), mode_(mode), uid_(uid), gid_(gid) {}

CgroupMap::CgroupMap() : cg_file_data_(nullptr), cg_file_size_(0) {
    if (!LoadRcFile()) {
        LOG(ERROR) << "CgroupMap::LoadRcFile called for [" << getpid() << "] failed";
    }
}

CgroupMap::~CgroupMap() {
    if (cg_file_data_) {
        munmap(cg_file_data_, cg_file_size_);
        cg_file_data_ = nullptr;
        cg_file_size_ = 0;
    }
}

CgroupMap& CgroupMap::GetInstance() {
    // Deliberately leak this object to avoid a race between destruction on
    // process exit and concurrent access from another thread.
    static auto* instance = new CgroupMap;
    return *instance;
}

bool CgroupMap::LoadRcFile() {
    struct stat sb;

    if (cg_file_data_) {
        // Data already initialized
        return true;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_PATH, O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "open() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    if (fstat(fd, &sb) < 0) {
        PLOG(ERROR) << "fstat() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    size_t file_size = sb.st_size;
    if (file_size < sizeof(CgroupFile)) {
        LOG(ERROR) << "Invalid file format " << CGROUPS_RC_PATH;
        return false;
    }

    CgroupFile* file_data = (CgroupFile*)mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (file_data == MAP_FAILED) {
        PLOG(ERROR) << "Failed to mmap " << CGROUPS_RC_PATH;
        return false;
    }

    if (file_data->version_ != CgroupFile::FILE_CURR_VERSION) {
        LOG(ERROR) << CGROUPS_RC_PATH << " file version mismatch";
        munmap(file_data, file_size);
        return false;
    }

    if (file_size != sizeof(CgroupFile) + file_data->controller_count_ * sizeof(CgroupController)) {
        LOG(ERROR) << CGROUPS_RC_PATH << " file has invalid size";
        munmap(file_data, file_size);
        return false;
    }

    cg_file_data_ = file_data;
    cg_file_size_ = file_size;

    return true;
}

void CgroupMap::Print() const {
    if (!cg_file_data_) {
        LOG(ERROR) << "CgroupMap::Print called for [" << getpid()
                   << "] failed, RC file was not initialized properly";
        return;
    }
    LOG(INFO) << "File version = " << cg_file_data_->version_;
    LOG(INFO) << "File controller count = " << cg_file_data_->controller_count_;

    LOG(INFO) << "Mounted cgroups:";
    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        LOG(INFO) << "\t" << controller->name() << " ver " << controller->version() << " path "
                  << controller->path();
    }
}

bool CgroupMap::SetupCgroups() {
    std::map<std::string, CgroupDescriptor> descriptors;

    if (getpid() != 1) {
        LOG(ERROR) << "Cgroup setup can be done only by init process";
        return false;
    }

    // Make sure we do this only one time. No need for std::call_once because
    // init is a single-threaded process
    if (access(CGROUPS_RC_PATH, F_OK) == 0) {
        LOG(WARNING) << "Attempt to call SetupCgroups more than once";
        return true;
    }

    // load cgroups.json file
    if (!ReadDescriptors(&descriptors)) {
        LOG(ERROR) << "Failed to load cgroup description file";
        return false;
    }

    // setup cgroups
    for (const auto& [name, descriptor] : descriptors) {
        if (!SetupCgroup(descriptor)) {
            // issue a warning and proceed with the next cgroup
            // TODO: mark the descriptor as invalid and skip it in WriteRcFile()
            LOG(WARNING) << "Failed to setup " << name << " cgroup";
        }
    }

    // mkdir <CGROUPS_RC_DIR> 0711 system system
    if (!Mkdir(android::base::Dirname(CGROUPS_RC_PATH), 0711, "system", "system")) {
        LOG(ERROR) << "Failed to create directory for " << CGROUPS_RC_PATH << " file";
        return false;
    }

    // Generate <CGROUPS_RC_FILE> file which can be directly mmapped into
    // process memory. This optimizes performance, memory usage
    // and limits infrormation shared with unprivileged processes
    // to the minimum subset of information from cgroups.json
    if (!WriteRcFile(descriptors)) {
        LOG(ERROR) << "Failed to write " << CGROUPS_RC_PATH << " file";
        return false;
    }

    // chmod 0644 <CGROUPS_RC_PATH>
    if (fchmodat(AT_FDCWD, CGROUPS_RC_PATH, 0644, AT_SYMLINK_NOFOLLOW) < 0) {
        PLOG(ERROR) << "fchmodat() failed";
        return false;
    }

    return true;
}

const CgroupController* CgroupMap::FindController(const std::string& name) const {
    if (!cg_file_data_) {
        LOG(ERROR) << "CgroupMap::FindController called for [" << getpid()
                   << "] failed, RC file was not initialized properly";
        return nullptr;
    }

    // skip the file header to get to the first controller
    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        if (name == controller->name()) {
            return controller;
        }
    }

    return nullptr;
}

/*
 *  Copyright 2014 Google, Inc
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#pragma once

#include <sys/cdefs.h>
#include <sys/types.h>
#include <string>
#include <vector>

__BEGIN_DECLS

static constexpr const char* CGROUPV2_CONTROLLER_NAME = "cgroup2";
static constexpr const char* CGROUPS_RC_PATH = "/dev/cgroup_info/cgroup.rc";

bool CgroupGetControllerPath(const std::string& cgroup_name, std::string* path);
bool CgroupGetAttributePath(const std::string& attr_name, std::string* path);
bool CgroupGetAttributePathForTask(const std::string& attr_name, int tid, std::string* path);

bool UsePerAppMemcg();

bool SetTaskProfiles(int tid, const std::vector<std::string>& profiles, bool use_fd_cache = false);
bool SetProcessProfiles(uid_t uid, pid_t pid, const std::vector<std::string>& profiles,
                        bool use_fd_cache = false);

// Return 0 and removes the cgroup if there are no longer any processes in it.
// Returns -1 in the case of an error occurring or if there are processes still running
// even after retrying for up to 200ms.
int killProcessGroup(uid_t uid, int initialPid, int signal);

// Returns the same as killProcessGroup(), however it does not retry, which means
// that it only returns 0 in the case that the cgroup exists and it contains no processes.
int killProcessGroupOnce(uid_t uid, int initialPid, int signal);

int createProcessGroup(uid_t uid, int initialPid, bool memControl = false);

// Set various properties of a process group. For these functions to work, the process group must
// have been created by passing memControl=true to createProcessGroup.
bool setProcessGroupSwappiness(uid_t uid, int initialPid, int swappiness);
bool setProcessGroupSoftLimit(uid_t uid, int initialPid, int64_t softLimitInBytes);
bool setProcessGroupLimit(uid_t uid, int initialPid, int64_t limitInBytes);

void removeAllProcessGroups(void);

__END_DECLS

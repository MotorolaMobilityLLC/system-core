// Copyright (C) 2020 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include <android-base/unique_fd.h>

namespace android {
namespace snapshot {

static constexpr uint32_t PACKET_SIZE = 512;

static constexpr char kSnapuserdSocketFirstStage[] = "snapuserd_first_stage";
static constexpr char kSnapuserdSocket[] = "snapuserd";

static constexpr char kSnapuserdFirstStagePidVar[] = "FIRST_STAGE_SNAPUSERD_PID";

// Ensure that the second-stage daemon for snapuserd is running.
bool EnsureSnapuserdStarted();

// Start the first-stage version of snapuserd, returning its pid. This is used
// by first-stage init, as well as vts_libsnapshot_test. On failure, -1 is returned.
pid_t StartFirstStageSnapuserd();

class SnapuserdClient {
  private:
    android::base::unique_fd sockfd_;

    bool Sendmsg(const std::string& msg);
    std::string Receivemsg();

    bool ValidateConnection();

  public:
    explicit SnapuserdClient(android::base::unique_fd&& sockfd);

    static std::unique_ptr<SnapuserdClient> Connect(const std::string& socket_name,
                                                    std::chrono::milliseconds timeout_ms);

    bool StopSnapuserd();
    uint64_t InitDmUserCow(const std::string& cow_device);
    bool InitializeSnapuserd(const std::string& cow_device, const std::string& backing_device,
                             const std::string& control_device);

    // Wait for snapuserd to disassociate with a dm-user control device. This
    // must ONLY be called if the control device has already been deleted.
    bool WaitForDeviceDelete(const std::string& control_device);
};

}  // namespace snapshot
}  // namespace android

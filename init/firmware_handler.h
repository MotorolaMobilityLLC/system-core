/*
 * Copyright (C) 2007 The Android Open Source Project
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

#pragma once

#include <grp.h>
#include <pwd.h>

#include <functional>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>

#include "result.h"
#include "uevent.h"
#include "uevent_handler.h"

namespace android {
namespace init {

struct ExternalFirmwareHandler {
    ExternalFirmwareHandler(std::string devpath, uid_t uid, std::string handler_path);
    ExternalFirmwareHandler(std::string devpath, uid_t uid, gid_t gid, std::string handler_path);

    std::string devpath;
    uid_t uid;
    gid_t gid;
    std::string handler_path;

    std::function<bool(const std::string&)> match;
};

class FirmwareHandler : public UeventHandler {
  public:
    FirmwareHandler(std::vector<std::string> firmware_directories,
                    std::vector<ExternalFirmwareHandler> external_firmware_handlers,
                    bool serial_handler_after_coldboot);
    virtual ~FirmwareHandler() = default;

    void HandleUevent(const Uevent& uevent) override;
    void ColdbootDone() override;
    void EnqueueUevent(const Uevent& uevent, ThreadPool& thread_pool) override;

  private:
    friend void FirmwareTestWithExternalHandler(const std::string& test_name,
                                                bool expect_new_firmware);
    void HandleUeventInternal(const Uevent& uevent, bool in_thread_pool) const;

    std::string GetFirmwarePath(const Uevent& uevent) const;
    void ProcessFirmwareEvent(const std::string& path, const std::string& firmware,
                              bool in_thread_pool, base::Timer t) const;
    bool ForEachFirmwareDirectory(std::function<bool(const std::string&)> handler) const;

    std::atomic_bool enables_parallel_handlers_ = true;
    const std::vector<std::string> firmware_directories_;
    const std::vector<ExternalFirmwareHandler> external_firmware_handlers_;
    const bool serial_handler_after_coldboot_ = true;
};

}  // namespace init
}  // namespace android

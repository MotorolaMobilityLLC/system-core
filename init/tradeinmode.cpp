/*
 * Copyright (C) 2025 The Android Open Source Project
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
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>

#include "reboot_utils.h"

namespace android {
namespace init {

void RequestTradeInModeWipeIfNeeded() {
    static constexpr const char* kWipeIndicator = "/metadata/tradeinmode/wipe";
    static constexpr size_t kWipeAttempts = 3;

    if (access(kWipeIndicator, R_OK) == -1) {
        return;
    }

    // Write a counter to the wipe indicator, to try and prevent boot loops if
    // recovery fails to wipe data.
    uint32_t counter = 0;
    std::string contents;
    if (android::base::ReadFileToString(kWipeIndicator, &contents)) {
        android::base::ParseUint(contents, &counter);
        contents = std::to_string(++counter);
        if (android::base::WriteStringToFile(contents, kWipeIndicator)) {
            sync();
        } else {
            PLOG(ERROR) << "Failed to update " << kWipeIndicator;
        }
    } else {
        PLOG(ERROR) << "Failed to read " << kWipeIndicator;
    }

    std::string err;
    auto misc_device = get_misc_blk_device(&err);
    if (misc_device.empty()) {
        LOG(FATAL) << "Could not find misc device: " << err;
    }

    // If we've failed to wipe three times, don't include the wipe command. This
    // will force us to boot into the recovery menu instead where a manual wipe
    // can be attempted.
    std::vector<std::string> options;
    if (counter <= kWipeAttempts) {
        options.emplace_back("--wipe_data");
        options.emplace_back("--reason=tradeinmode");
    }
    if (!write_bootloader_message(options, &err)) {
        LOG(FATAL) << "Could not issue wipe: " << err;
    }
    RebootSystem(ANDROID_RB_RESTART2, "recovery", "reboot,tradeinmode,wipe");
}

}  // namespace init
}  // namespace android

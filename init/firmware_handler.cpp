/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "firmware_handler.h"

#include <fcntl.h>
#include <sys/sendfile.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

using android::base::Timer;
using android::base::unique_fd;
using android::base::WriteFully;

namespace android {
namespace init {

static void LoadFirmware(const Uevent& uevent, const std::string& root, int fw_fd, size_t fw_size,
                         int loading_fd, int data_fd) {
    // Start transfer.
    WriteFully(loading_fd, "1", 1);

    // Copy the firmware.
    int rc = sendfile(data_fd, fw_fd, nullptr, fw_size);
    if (rc == -1) {
        PLOG(ERROR) << "firmware: sendfile failed { '" << root << "', '" << uevent.firmware
                    << "' }";
    }

    // Tell the firmware whether to abort or commit.
    const char* response = (rc != -1) ? "0" : "-1";
    WriteFully(loading_fd, response, strlen(response));
}

static bool IsBooting() {
    return access("/dev/.booting", F_OK) == 0;
}

/*
   Special firmware look-up functionality intended for non-system media firmware (ie.
   downloaded firmware). The folders provided must be protected via SELinux policy.
*/
struct extended_fw_path {
    const char *fw_substring;
    const char *fw_path;
};

const struct extended_fw_path extended_paths[] = {
#ifdef MOTO_AOV_WITH_XMCS
    {
        .fw_substring = "-aov-",
        .fw_path = "/data/adspd",
    },
    {
        .fw_substring = "-ultrasound",
        .fw_path = "/data/adspd",
    },
#endif
#ifdef MOTO_GREYBUS_FIRMWARE
    {
        .fw_substring = "upd-",
        .fw_path = "/data/gbfirmware",
    },
#endif
};

static int is_hard_link(const char *path)
{
    int rv = 1;
    struct stat sb;

    if(stat(path, &sb) == 0) {
        if((S_ISDIR(sb.st_mode)) || (sb.st_nlink == 1))
            rv = 0;
        else
            LOG(ERROR) << "Invalid hard link (" << path << "), nlink=" << sb.st_nlink << " ignoring!";
    } else if (errno == ENOENT)
        rv = 0;
    return(rv);
}

static int LoadOneExtended(uevent* uevent, int loading_fd, int data_fd, size_t index)
{
    int ret = 0;
    std::string root = StringPrintf("/sys%s", uevent->path);

    /* look for naming convention for the target firmware */
    if (strstr(uevent->firmware, extended_paths[index].fw_substring) == NULL) {
        return 0;
    }

    std::string file = StringPrintf("%s/%s", extended_paths[index].fw_path, uevent->firmware);

    if (is_hard_link(file.c_str())) {
        return 0;
    }

    /* Do not consider the case /data folder is still encrypted. It is assumed
       userspace apps needing these files are started only after data partition
       is decrypted. */
    unique_fd fw_fd(open(file.c_str(), O_RDONLY|O_NOFOLLOW));
    struct stat sb;
    if (fw_fd != -1 && fstat(fw_fd, &sb) != -1) {
        LoadFirmware(uevent, root, fw_fd, sb.st_size, loading_fd, data_fd);
        ret = -1;
    } else {
        return 0;
    }

    return ret;
}

/*
    -   The function returns the following values:
    -   -1 - Firmware loading was either success or failure. No need to look for further folders.
    -    0 - Firmware was not loaded. Further folders need to be looked up.
*/
static int LoadFromExtended(uevent* uevent, int loading_fd, int data_fd)
{
    size_t i;

    /* Loop through all possible extended folders unless we find a firmware */
    for (i = 0; i < arraysize(extended_paths); i++)
        if (LoadOneExtended(uevent, loading_fd, data_fd, i) == -1)
            return -1;

    return 0;
}

static void ProcessFirmwareEvent(const Uevent& uevent) {
    int booting = IsBooting();

    LOG(INFO) << "firmware: loading '" << uevent.firmware << "' for '" << uevent.path << "'";

    std::string root = "/sys" + uevent.path;
    std::string loading = root + "/loading";
    std::string data = root + "/data";

    unique_fd loading_fd(open(loading.c_str(), O_WRONLY | O_CLOEXEC));
    if (loading_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware loading fd for " << uevent.firmware;
        return;
    }

    unique_fd data_fd(open(data.c_str(), O_WRONLY | O_CLOEXEC));
    if (data_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware data fd for " << uevent.firmware;
        return;
    }

    if (LoadFromExtended(uevent, loading_fd, data_fd) < 0) {
        return;
    }

    static const char* firmware_dirs[] = {"/etc/firmware/", "/odm/firmware/",
                                          "/vendor/firmware/", "/firmware/image/"};

try_loading_again:
    for (size_t i = 0; i < arraysize(firmware_dirs); i++) {
        std::string file = firmware_dirs[i] + uevent.firmware;
        unique_fd fw_fd(open(file.c_str(), O_RDONLY | O_CLOEXEC));
        struct stat sb;
        if (fw_fd != -1 && fstat(fw_fd, &sb) != -1) {
            LoadFirmware(uevent, root, fw_fd, sb.st_size, loading_fd, data_fd);
            return;
        }
    }

    if (booting) {
        // If we're not fully booted, we may be missing
        // filesystems needed for firmware, wait and retry.
        std::this_thread::sleep_for(100ms);
        booting = IsBooting();
        goto try_loading_again;
    }

    LOG(ERROR) << "firmware: could not find firmware for " << uevent.firmware;

    // Write "-1" as our response to the kernel's firmware request, since we have nothing for it.
    write(loading_fd, "-1", 2);
}

void HandleFirmwareEvent(const Uevent& uevent) {
    if (uevent.subsystem != "firmware" || uevent.action != "add") return;

    // Loading the firmware in a child means we can do that in parallel...
    auto pid = fork();
    if (pid == -1) {
        PLOG(ERROR) << "could not fork to process firmware event for " << uevent.firmware;
    }
    if (pid == 0) {
        Timer t;
        ProcessFirmwareEvent(uevent);
        LOG(INFO) << "loading " << uevent.path << " took " << t;
        _exit(EXIT_SUCCESS);
    }
}

}  // namespace init
}  // namespace android

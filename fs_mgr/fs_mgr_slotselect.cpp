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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/properties.h>

#include "fs_mgr.h"
#include "fs_mgr_priv.h"

#include "bootloader.h"

// Copies slot_suffix from misc into |out_suffix|. Returns 0 on
// success, -1 on error or if there is no non-empty slot_suffix.
static int get_active_slot_suffix_from_misc(struct fstab *fstab,
                                            char *out_suffix,
                                            size_t suffix_len)
{
    int n;
    int misc_fd;
    ssize_t num_read;
    struct bootloader_message_ab msg;

    misc_fd = -1;
    for (n = 0; n < fstab->num_entries; n++) {
        if (strcmp(fstab->recs[n].mount_point, "/misc") == 0) {
            misc_fd = open(fstab->recs[n].blk_device, O_RDONLY);
            if (misc_fd == -1) {
                PERROR << "Error opening misc partition '"
                       << fstab->recs[n].blk_device << "'";
                return -1;
            } else {
                break;
            }
        }
    }

    if (misc_fd == -1) {
        LERROR << "Error finding misc partition";
        return -1;
    }

    num_read = TEMP_FAILURE_RETRY(read(misc_fd, &msg, sizeof(msg)));
    // Linux will never return partial reads when reading from block
    // devices so no need to worry about them.
    if (num_read != sizeof(msg)) {
        PERROR << "Error reading bootloader_message";
        close(misc_fd);
        return -1;
    }
    close(misc_fd);
    if (msg.slot_suffix[0] == '\0')
        return -1;
    strncpy(out_suffix, msg.slot_suffix, suffix_len);
    return 0;
}

// finds slot_suffix in androidboot.slot_suffix kernel command line argument
// or in the device tree node at /firmware/android/slot_suffix property
static int get_active_slot_suffix_from_kernel(char *out_suffix,
                                              size_t suffix_len)
{
    std::string cmdline;
    if (android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        for (const auto& entry : android::base::Split(android::base::Trim(cmdline), " ")) {
            std::vector<std::string> pieces = android::base::Split(entry, "=");
            if (pieces.size() == 2) {
                if (pieces[0] == "androidboot.slot_suffix") {
                    strncpy(out_suffix, pieces[1].c_str(), suffix_len);
                    return 0;
                }
            }
        }
    }

    // if we can't find slot_suffix in cmdline, check the DT
    static constexpr char android_dt_dir[] = "/proc/device-tree/firmware/android";
    std::string file_name = android::base::StringPrintf("%s/compatible", android_dt_dir);
    std::string dt_value;
    if (android::base::ReadFileToString(file_name, &dt_value)) {
        if (!dt_value.compare("android,firmware")) {
            LERROR << "Error finding compatible android DT node";
            return -1;
        }

        file_name = android::base::StringPrintf("%s/%s", android_dt_dir, "slot_suffix");
        if (!android::base::ReadFileToString(file_name, &dt_value)) {
            LERROR << "Error finding slot_suffix in device tree";
            return -1;
        }

        // DT entries have a terminating '\0', so 'suffix_len' is safe.
        strncpy(out_suffix, dt_value.c_str(), suffix_len);
        return 0;
    }

    // slot_suffix missing in kernel cmdline or device tree
    return -1;
}

// Gets slot_suffix from either the kernel cmdline / device tree / firmware
// or the misc partition. Sets |out_suffix| on success and returns 0. Returns
// -1 if slot_suffix could not be determined.
static int get_active_slot_suffix(struct fstab *fstab, char *out_suffix,
                                  size_t suffix_len)
{
    char propbuf[PROPERTY_VALUE_MAX];

    // Get the suffix from the kernel commandline (note that we don't
    // allow the empty suffix). On bootloaders natively supporting A/B
    // we'll hit this path every time so don't bother logging it.
    property_get("ro.boot.slot_suffix", propbuf, "");
    if (propbuf[0] != '\0') {
        strncpy(out_suffix, propbuf, suffix_len);
        return 0;
    }

    // if the property is not set, we are either being invoked too early
    // or the slot suffix in mentioned in the misc partition. If its
    // "too early", try to find the slotsuffix ourselves in the kernel command
    // line or the device tree
    if (get_active_slot_suffix_from_kernel(out_suffix, suffix_len) == 0) {
        LINFO << "Using slot suffix '" << out_suffix << "' from kernel";
        return 0;
    }

    // If we couldn't get the suffix from the kernel cmdline, try the
    // the misc partition.
    if (get_active_slot_suffix_from_misc(fstab, out_suffix, suffix_len) == 0) {
        LINFO << "Using slot suffix '" << out_suffix << "' from misc";
        return 0;
    }

    LERROR << "Error determining slot_suffix";

    return -1;
}

// Updates |fstab| for slot_suffix. Returns 0 on success, -1 on error.
int fs_mgr_update_for_slotselect(struct fstab *fstab)
{
    int n;
    char suffix[PROPERTY_VALUE_MAX];
    int got_suffix = 0;

    for (n = 0; n < fstab->num_entries; n++) {
        if (fstab->recs[n].fs_mgr_flags & MF_SLOTSELECT) {
            char *tmp;

            if (!got_suffix) {
                memset(suffix, '\0', sizeof(suffix));
                if (get_active_slot_suffix(fstab, suffix,
                                           sizeof(suffix) - 1) != 0) {
                  return -1;
                }
                got_suffix = 1;
            }

            if (asprintf(&tmp, "%s%s", fstab->recs[n].blk_device,
                         suffix) > 0) {
                free(fstab->recs[n].blk_device);
                fstab->recs[n].blk_device = tmp;
            } else {
                return -1;
            }
        }
    }
    return 0;
}

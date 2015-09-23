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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

#include <string>

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "cutils/properties.h"
#include "fs_mgr.h"

const std::string kFstab_Prefix = "/fstab.";

// Returns the device used to mount a directory in /proc/mounts.
static std::string find_proc_mount(const char* dir) {
    std::unique_ptr<FILE, int(*)(FILE*)> fp(setmntent("/proc/mounts", "r"), endmntent);
    if (!fp) {
        return "";
    }

    mntent* e;
    while ((e = getmntent(fp.get())) != nullptr) {
        if (strcmp(dir, e->mnt_dir) == 0) {
            return e->mnt_fsname;
        }
    }
    return "";
}

// Returns the device used to mount a directory in the fstab.
static std::string find_fstab_mount(const char* dir) {
    char propbuf[PROPERTY_VALUE_MAX];

    property_get("ro.hardware", propbuf, "");
    std::string fstab_filename = kFstab_Prefix + propbuf;
    struct fstab* fstab = fs_mgr_read_fstab(fstab_filename.c_str());
    struct fstab_rec* rec = fs_mgr_get_entry_for_mount_point(fstab, dir);
    std::string dev = rec ? std::string(rec->blk_device) : "";
    fs_mgr_free_fstab(fstab);
    return dev;
}

// The proc entry for / is full of lies, so check fstab instead.
// /proc/mounts lists rootfs and /dev/root, neither of which is what we want.
static std::string find_mount(const char* dir) {
    if (strcmp(dir, "/") == 0) {
       return find_fstab_mount(dir);
    } else {
       return find_proc_mount(dir);
    }
}

bool make_block_device_writable(const std::string& dev) {
    int fd = unix_open(dev.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return false;
    }

    int OFF = 0;
    bool result = (ioctl(fd, BLKROSET, &OFF) != -1);
    unix_close(fd);
    return result;
}

static bool remount_partition(int fd, const char* dir) {
    if (!directory_exists(dir)) {
        return true;
    }
    std::string dev = find_mount(dir);
    if (dev.empty()) {
        return true;
    }
    if (!make_block_device_writable(dev)) {
        WriteFdFmt(fd, "remount of %s failed; couldn't make block device %s writable: %s\n",
                   dir, dev.c_str(), strerror(errno));
        return false;
    }
    if (mount(dev.c_str(), dir, "none", MS_REMOUNT, nullptr) == -1) {
        WriteFdFmt(fd, "remount of %s failed: %s\n", dir, strerror(errno));
        return false;
    }
    return true;
}

void remount_service(int fd, void* cookie) {
    if (getuid() != 0) {
        WriteFdExactly(fd, "Not running as root. Try \"adb root\" first.\n");
        adb_close(fd);
        return;
    }

    char prop_buf[PROPERTY_VALUE_MAX];
    property_get("partition.system.verified", prop_buf, "");
    bool system_verified = (strlen(prop_buf) > 0);

    property_get("partition.vendor.verified", prop_buf, "");
    bool vendor_verified = (strlen(prop_buf) > 0);

    if (system_verified || vendor_verified) {
        // Allow remount but warn of likely bad effects
        bool both = system_verified && vendor_verified;
        WriteFdFmt(fd,
                   "dm_verity is enabled on the %s%s%s partition%s.\n",
                   system_verified ? "system" : "",
                   both ? " and " : "",
                   vendor_verified ? "vendor" : "",
                   both ? "s" : "");
        WriteFdExactly(fd,
                       "Use \"adb disable-verity\" to disable verity.\n"
                       "If you do not, remount may succeed, however, you will still "
                       "not be able to write to these volumes.\n");
    }

    bool success = true;
    property_get("ro.build.system_root_image", prop_buf, "");
    bool system_root = !strcmp(prop_buf, "true");
    if (system_root) {
        success &= remount_partition(fd, "/");
    } else {
        success &= remount_partition(fd, "/system");
    }
    success &= remount_partition(fd, "/vendor");
    success &= remount_partition(fd, "/oem");

    WriteFdExactly(fd, success ? "remount succeeded\n" : "remount failed\n");

    adb_close(fd);
}

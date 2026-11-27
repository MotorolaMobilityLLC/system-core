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

#include <cutils/ashmem.h>

#define LOG_TAG "ashmem"

#include <errno.h>
#include <fcntl.h>
#include <linux/ashmem.h>
#include <linux/memfd.h>
#include <log/log.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>

#include "ashmem-internal.h"

#include <atomic>

/*
 * Implementation of the userspace ashmem API for devices.
 *
 * This may use ashmem or memfd. See use_memfd().
 *
 * See ashmem-host.cpp for the temporary file based alternative for the host.
 */

/* ashmem identity */
static std::atomic<dev_t> __ashmem_rdev;

/* set to true for verbose logging and other debug  */
static bool debug_log = false;

static bool __use_memfd() {
    // Used to force enable memfd usage. In the future this property will be removed once we switch
    // everything over to memfd.
    if (android::base::GetBoolProperty("sys.use_memfd", false)) {
        if (debug_log) {
            ALOGD("sys.use_memfd=true so using memfd");
        }
        return true;
    }

    // Ensure that the kernel supports the memfd_class policy capability.
    if (access("/sys/fs/selinux/policy_capabilities/memfd_class", F_OK) != 0) {
        if (debug_log) {
            ALOGD("Not using memfd: kernel does not support memfd_class sepolicy capability");
        }
        return false;
    }

    // Per VSR-3.5.2-004, the memfd_class policy capability is required for devices with vendor API
    // level 202604+, so use memfd on those devices.
    const int min_vendor_api_level = 202604;
    const int vendor_api_level = android::base::GetIntProperty("ro.vendor.api_level", -1);
    if (vendor_api_level < min_vendor_api_level) {
        if (debug_log) {
            ALOGD("Not using memfd: device vendor API level %d < %d the minimum vendor API level required for memfd",
                  vendor_api_level, min_vendor_api_level);
        }
        return false;
    }

    // Make the minimum target SDK version match vendor API level 202604 to avoid breaking
    // assumptions that older applications might make about the fd they allocate.
    const int min_app_target_sdk_version = 37;
    const int app_target_sdk_version = android_get_application_target_sdk_version();
    if (app_target_sdk_version < min_app_target_sdk_version) {
        if (debug_log) {
            ALOGD("Not using memfd: application target SDK version %d < %d the minimum target SDK version required for memfd",
                  app_target_sdk_version, min_app_target_sdk_version);
        }
        return false;
    }

    if (debug_log) {
        ALOGD("memfd requirements satisfied: memfd_class capability supported, device vendor API level: %d, and application target SDK version: %d",
              vendor_api_level, app_target_sdk_version);
    }

    return true;
}

bool use_memfd() {
    static bool use_memfd = __use_memfd();
    return use_memfd;
}

static std::string get_ashmem_device_path() {
    static const std::string boot_id_path = "/proc/sys/kernel/random/boot_id";
    std::string boot_id;
    if (!android::base::ReadFileToString(boot_id_path, &boot_id)) {
        ALOGE("Failed to read %s: %m", boot_id_path.c_str());
        return "";
    }
    boot_id = android::base::Trim(boot_id);

    return "/dev/ashmem" + boot_id;
}

static bool __init_ashmem_rdev() {
    const std::string ashmem_device_path = get_ashmem_device_path();
    if (ashmem_device_path.empty()) {
        return false;
    }

    struct stat st;
    if (TEMP_FAILURE_RETRY(stat(ashmem_device_path.c_str(), &st)) == -1) {
        ALOGE("Unable to stat ashmem device: %m");
        return false;
    }
    if (!S_ISCHR(st.st_mode)) {
        ALOGE("ashmem device is not a character device");
        errno = ENOTTY;
        return false;
    }

    __ashmem_rdev = st.st_rdev;
    return true;
}

int __ashmem_open() {
    static const std::string ashmem_device_path = get_ashmem_device_path();

    if (ashmem_device_path.empty()) {
        return -1;
    }

    if (__ashmem_rdev == 0 && !__init_ashmem_rdev()) {
        return -1;
    }

    android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(ashmem_device_path.c_str(), O_RDWR | O_CLOEXEC)));
    if (!fd.ok()) {
        ALOGE("Unable to open ashmem device: %m");
        return -1;
    }

    return fd.release();
}

/* Make sure file descriptor references ashmem, negative number means false */
// TODO: return bool
static int __ashmem_is_ashmem(int fd, bool fatal) {
    if (__ashmem_rdev == 0 && !__init_ashmem_rdev()) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) == -1) return -1;
    if (S_ISCHR(st.st_mode) && st.st_rdev == __ashmem_rdev) {
      return 0;
    }

    // TODO: move this to the single caller that actually wants it
    if (fatal) {
        LOG_ALWAYS_FATAL("illegal fd=%d mode=0%o rdev=%d:%d expected 0%o %d:%d",
            fd, st.st_mode, major(st.st_rdev), minor(st.st_rdev),
            S_IFCHR | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IRGRP,
            major(__ashmem_rdev), minor(__ashmem_rdev));
        /* NOTREACHED */
    }

    errno = ENOTTY;
    return -1;
}

static int __ashmem_check_failure(int fd, int result) {
    if (result == -1 && errno == ENOTTY) __ashmem_is_ashmem(fd, true);
    return result;
}

static bool is_memfd_fd(int fd) {
    std::string fd_path = android::base::StringPrintf("/proc/self/fd/%d", fd);
    std::string result;
    if (!android::base::Readlink(fd_path, &result)) {
        ALOGE("readlink(%s) failed: %m", fd_path.c_str());
        return false;
    }

    if (!result.starts_with("/memfd:")) {
        return false;
    }

    // b/498720726: Ensure that the memfd has the same restrictions on its size that an ashmem fd
    // would. Otherwise, memfds that aren't sealed against size changes can be treated as valid
    // ashmem fds. The size of the memory associated with those fds can then be changed while a
    // process is using it, leading to time of check to time of use issues.
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals == -1) {
        ALOGE("is_memfd_fd(%d): F_GET_SEALS failed: %m", fd);
        return false;
    }

    if ((seals & (F_SEAL_GROW | F_SEAL_SHRINK)) != (F_SEAL_GROW | F_SEAL_SHRINK)) {
        return false;
    }

    return true;
}

int ashmem_valid(int fd) {
    if (is_memfd_fd(fd)) {
        return 1;
    }

    return __ashmem_is_ashmem(fd, false) >= 0;
}

int __memfd_create_region(const char* name, size_t size) {
    // This code needs to build on API levels before 30,
    // so we can't use the libc wrapper.
    android::base::unique_fd fd(syscall(__NR_memfd_create, name, MFD_CLOEXEC | MFD_ALLOW_SEALING));

    if (fd == -1) {
        ALOGE("memfd_create(%s, %zd) failed: %m", name, size);
        return -1;
    }

    if (ftruncate(fd, size) == -1) {
        ALOGE("ftruncate(%s, %zd) failed for memfd creation: %m", name, size);
        return -1;
    }

    // forbid size changes to match ashmem behaviour
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_GROW | F_SEAL_SHRINK) == -1) {
        ALOGE("memfd_create(%s, %zd) F_ADD_SEALS failed: %m", name, size);
        return -1;
    }

    if (debug_log) {
        ALOGE("memfd_create(%s, %zd) success. fd=%d", name, size, fd.get());
    }
    return fd.release();
}

int __ashmem_create_region(const char* name, size_t size) {
    android::base::unique_fd fd(__ashmem_open());
    if (!fd.ok() || TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_NAME, name)) < 0 ||
        TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_SIZE, size)) < 0) {
        return -1;
    }
    return fd.release();
}

/*
 * ashmem_create_region - creates a new ashmem region and returns the file
 * descriptor, or <0 on error
 *
 * `name' is an optional label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
int ashmem_create_region(const char* name, size_t size) {
    if (name == NULL) name = "none";

    auto create_region = use_memfd() ? __memfd_create_region : __ashmem_create_region;
    return create_region(name, size);
}

static int memfd_set_prot_region(int fd, int prot) {
    int seals = fcntl(fd, F_GET_SEALS);
    if (seals == -1) {
        ALOGE("memfd_set_prot_region(%d, %d): F_GET_SEALS failed: %m", fd, prot);
        return -1;
    }

    if (prot & PROT_WRITE) {
        /* Now we want the buffer to be read-write, let's check if the buffer
         * has been previously marked as read-only before, if so return error
         */
        if (seals & F_SEAL_FUTURE_WRITE) {
            ALOGE("memfd_set_prot_region(%d, %d): region is write protected", fd, prot);
            errno = EINVAL;  // inline with ashmem error code, if already in
                             // read-only mode
            return -1;
        }
        return 0;
    }

    /* We would only allow read-only for any future file operations */
    if (fcntl(fd, F_ADD_SEALS, F_SEAL_FUTURE_WRITE) == -1) {
        ALOGE("memfd_set_prot_region(%d, %d): F_SEAL_FUTURE_WRITE seal failed: %m", fd, prot);
        return -1;
    }

    return 0;
}

int ashmem_set_prot_region(int fd, int prot) {
    if (is_memfd_fd(fd)) {
        return memfd_set_prot_region(fd, prot);
    }

    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_SET_PROT_MASK, prot)));
}

static int do_pin(int op, int fd, size_t offset, size_t length) {
    static bool already_warned_about_pin_deprecation = false;
    if (!already_warned_about_pin_deprecation || debug_log) {
        ALOGE("Pinning is deprecated since Android Q. Please use trim or other methods.");
        already_warned_about_pin_deprecation = true;
    }

    if (is_memfd_fd(fd)) {
        return 0;
    }

    // TODO: should LP64 reject too-large offset/len?
    ashmem_pin pin = { static_cast<uint32_t>(offset), static_cast<uint32_t>(length) };
    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, op, &pin)));
}

int ashmem_pin_region(int fd, size_t offset, size_t length) {
    return do_pin(ASHMEM_PIN, fd, offset, length);
}

int ashmem_unpin_region(int fd, size_t offset, size_t length) {
    return do_pin(ASHMEM_UNPIN, fd, offset, length);
}

int ashmem_get_size_region(int fd) {
    if (is_memfd_fd(fd)) {
        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            ALOGE("ashmem_get_size_region(%d): fstat failed: %m", fd);
            return -1;
        }
        return sb.st_size;
    }

    return __ashmem_check_failure(fd, TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL)));
}

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

#include "security.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>

#include <string>
#include <fstream>

#include <android-base/logging.h>

namespace android {
namespace init {

static bool SetHighestAvailableOptionValue(const std::string& path, int min, int max) {
    std::ifstream inf(path, std::fstream::in);
    if (!inf) {
        LOG(ERROR) << "Cannot open for reading: " << path;
        return false;
    }

    int current = max;
    while (current >= min) {
        // try to write out new value
        std::string str_val = std::to_string(current);
        std::ofstream of(path, std::fstream::out);
        if (!of) {
            LOG(ERROR) << "Cannot open for writing: " << path;
            return false;
        }
        of << str_val << std::endl;
        of.close();

        // check to make sure it was recorded
        inf.seekg(0);
        std::string str_rec;
        inf >> str_rec;
        if (str_val.compare(str_rec) == 0) {
            break;
        }
        current--;
    }
    inf.close();

    if (current < min) {
        LOG(ERROR) << "Unable to set minimum option value " << min << " in " << path;
        return false;
    }
    return true;
}

#define MMAP_RND_PATH "/proc/sys/vm/mmap_rnd_bits"
#define MMAP_RND_COMPAT_PATH "/proc/sys/vm/mmap_rnd_compat_bits"

static bool SetMmapRndBitsMin(int start, int min, bool compat) {
    std::string path;
    if (compat) {
        path = MMAP_RND_COMPAT_PATH;
    } else {
        path = MMAP_RND_PATH;
    }

    return SetHighestAvailableOptionValue(path, min, start);
}

// Set /proc/sys/vm/mmap_rnd_bits and potentially
// /proc/sys/vm/mmap_rnd_compat_bits to the maximum supported values.
// Returns an error if unable to set these to an acceptable value.
//
// To support this sysctl, the following upstream commits are needed:
//
// d07e22597d1d mm: mmap: add new /proc tunable for mmap_base ASLR
// e0c25d958f78 arm: mm: support ARCH_MMAP_RND_BITS
// 8f0d3aa9de57 arm64: mm: support ARCH_MMAP_RND_BITS
// 9e08f57d684a x86: mm: support ARCH_MMAP_RND_BITS
// ec9ee4acd97c drivers: char: random: add get_random_long()
// 5ef11c35ce86 mm: ASLR: use get_random_long()
Result<void> SetMmapRndBitsAction(const BuiltinArguments&) {
// values are arch-dependent
#if defined(USER_MODE_LINUX)
    // uml does not support mmap_rnd_bits
    return {};
#elif defined(__aarch64__)
    // arm64 supports 14 - 33 rnd bits depending on page size and ARM64_VA_BITS.
    // The kernel (6.5) still defaults to 39 va bits for 4KiB pages, so shipping
    // devices are only getting 24 bits of randomness in practice.
    if (SetMmapRndBitsMin(33, 24, false) && (!Has32BitAbi() || SetMmapRndBitsMin(16, 16, true))) {
        return {};
    }
#elif defined(__riscv)
    // riscv64 supports 24 rnd bits with Sv39, and starting with the 6.9 kernel,
    // 33 bits with Sv48 and Sv57.
    if (SetMmapRndBitsMin(33, 24, false)) {
        return {};
    }
#elif defined(__x86_64__)
    // x86_64 supports 28 - 32 rnd bits, but Android wants to ensure that the
    // theoretical maximum of 32 bits is always supported and used; except in
    // the case of the x86 page size emulator which supports a maximum
    // of 30 bits for 16k page size, or 28 bits for 64k page size.
    int max_bits = 32 - (static_cast<int>(log2(getpagesize())) - 12);
    if (SetMmapRndBitsMin(max_bits, max_bits, false) &&
        (!Has32BitAbi() || SetMmapRndBitsMin(16, 16, true))) {
        return {};
    }
#elif defined(__arm__) || defined(__i386__)
    // check to see if we're running on 64-bit kernel
    bool h64 = !access(MMAP_RND_COMPAT_PATH, F_OK);
    // supported 32-bit architecture must have 16 bits set
    if (SetMmapRndBitsMin(16, 16, h64)) {
        return {};
    }
#else
    LOG(ERROR) << "Unknown architecture";
#endif

    LOG(FATAL) << "Unable to set adequate mmap entropy value!";
    return Error();
}

}  // namespace init
}  // namespace android

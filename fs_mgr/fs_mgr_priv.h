/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <chrono>
#include <string>

#include <android-base/logging.h>
#include <fs_mgr.h>
#include <fstab/fstab.h>

#include "fs_mgr_priv_boot_config.h"

/* The CHECK() in logging.h will use program invocation name as the tag.
 * Thus, the log will have prefix "init: " when libfs_mgr is statically
 * linked in the init process. This might be opaque when debugging.
 * Appends "in libfs_mgr" at the end of the abort message to explicitly
 * indicate the check happens in fs_mgr.
 */
#define FS_MGR_CHECK(x) CHECK(x) << "in libfs_mgr "

#define FS_MGR_TAG "[libfs_mgr]"

// Logs a message to kernel
#define LINFO    LOG(INFO) << FS_MGR_TAG
#define LWARNING LOG(WARNING) << FS_MGR_TAG
#define LERROR   LOG(ERROR) << FS_MGR_TAG
#define LFATAL LOG(FATAL) << FS_MGR_TAG

// Logs a message with strerror(errno) at the end
#define PINFO    PLOG(INFO) << FS_MGR_TAG
#define PWARNING PLOG(WARNING) << FS_MGR_TAG
#define PERROR   PLOG(ERROR) << FS_MGR_TAG
#define PFATAL PLOG(FATAL) << FS_MGR_TAG

#define CRYPTO_TMPFS_OPTIONS "size=512m,mode=0771,uid=1000,gid=1000"

#ifdef MTK_FSTAB_FLAGS
#define MAX_PATH_LEN        64
#define MAX_VOLUME_NAME     512
#define F2FS_MAX_EXTENSION  64  /* # of extension entries */
#define VERSION_LEN         256
#define MAX_DEVICES         8
#define F2FS_MAX_QUOTAS     3

struct f2fs_dev_info {
    __u8 path[MAX_PATH_LEN];
    __le32 total_segments;
};

struct f2fs_super_block {
    __le32 magic;
    __le16 major_ver;
    __le16 minor_ver;
    __le32 log_sectorsize;
    __le32 log_sectors_per_block;
    __le32 log_blocksize;
    __le32 log_blocks_per_seg;
    __le32 segs_per_sec;
    __le32 secs_per_zone;
    __le32 checksum_offset;
    __le64 block_count;
    __le32 section_count;
    __le32 segment_count;
    __le32 segment_count_ckpt;
    __le32 segment_count_sit;
    __le32 segment_count_nat;
    __le32 segment_count_ssa;
    __le32 segment_count_main;
    __le32 segment0_blkaddr;
    __le32 cp_blkaddr;
    __le32 sit_blkaddr;
    __le32 nat_blkaddr;
    __le32 ssa_blkaddr;
    __le32 main_blkaddr;
    __le32 root_ino;
    __le32 node_ino;
    __le32 meta_ino;
    __u8 uuid[16];
    __le16 volume_name[MAX_VOLUME_NAME];
    __le32 extension_count;
    __u8 extension_list[F2FS_MAX_EXTENSION][8];
    __le32 cp_payload;
    __u8 version[VERSION_LEN];
    __u8 init_version[VERSION_LEN];
    __le32 feature;
    __u8 encryption_level;
    __u8 encrypt_pw_salt[16];
    struct f2fs_dev_info devs[MAX_DEVICES];
    __le32 qf_ino[F2FS_MAX_QUOTAS];
    __u8 hot_ext_count;
    __u8 reserved[310];
    __le32 crc;
};
#endif

/* fstab has the following format:
 *
 * Any line starting with a # is a comment and ignored
 *
 * Any blank line is ignored
 *
 * All other lines must be in this format:
 *   <source>  <mount_point> <fs_type> <mount_flags> <fs_options> <fs_mgr_options>
 *
 *   <mount_flags> is a comma separated list of flags that can be passed to the
 *                 mount command.  The list includes noatime, nosuid, nodev, nodiratime,
 *                 ro, rw, remount, defaults.
 *
 *   <fs_options> is a comma separated list of options accepted by the filesystem being
 *                mounted.  It is passed directly to mount without being parsed
 *
 *   <fs_mgr_options> is a comma separated list of flags that control the operation of
 *                     the fs_mgr program.  The list includes "wait", which will wait till
 *                     the <source> file exists, and "check", which requests that the fs_mgr
 *                     run an fscheck program on the <source> before mounting the filesystem.
 *                     If check is specifed on a read-only filesystem, it is ignored.
 *                     Also, "encryptable" means that filesystem can be encrypted.
 *                     The "encryptable" flag _MUST_ be followed by a = and a string which
 *                     is the location of the encryption keys.  It can either be a path
 *                     to a file or partition which contains the keys, or the word "footer"
 *                     which means the keys are in the last 16 Kbytes of the partition
 *                     containing the filesystem.
 *
 * When the fs_mgr is requested to mount all filesystems, it will first mount all the
 * filesystems that do _NOT_ specify check (including filesystems that are read-only and
 * specify check, because check is ignored in that case) and then it will check and mount
 * filesystem marked with check.
 *
 */

#define DM_BUF_SIZE 4096

using namespace std::chrono_literals;

enum class FileWaitMode { Exists, DoesNotExist };

bool fs_mgr_wait_for_file(const std::string& filename,
                          const std::chrono::milliseconds relative_timeout,
                          FileWaitMode wait_mode = FileWaitMode::Exists);

bool fs_mgr_set_blk_ro(const std::string& blockdev, bool readonly = true);
bool fs_mgr_update_for_slotselect(android::fs_mgr::Fstab* fstab);
bool fs_mgr_is_device_unlocked();
const std::string& get_android_dt_dir();
bool is_dt_compatible();
int load_verity_state(const android::fs_mgr::FstabEntry& entry, int* mode);

bool fs_mgr_is_ext4(const std::string& blk_device);
bool fs_mgr_is_f2fs(const std::string& blk_device);

bool fs_mgr_teardown_verity(android::fs_mgr::FstabEntry* fstab, bool wait);

namespace android {
namespace fs_mgr {
bool UnmapDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms);
}  // namespace fs_mgr
}  // namespace android

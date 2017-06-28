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

#ifndef __CORE_FS_TAB_H
#define __CORE_FS_TAB_H

#include <linux/dm-ioctl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// C++ only headers
// TODO: move this into separate header files under include/fs_mgr/*.h
#ifdef __cplusplus
#include <string>
#endif

__BEGIN_DECLS

/*
 * The entries must be kept in the same order as they were seen in the fstab.
 * Unless explicitly requested, a lookup on mount point should always
 * return the 1st one.
 */
struct fstab {
    int num_entries;
    struct fstab_rec* recs;
    char* fstab_filename;
};

struct fstab_rec {
    char* blk_device;
    char* mount_point;
    char* fs_type;
    unsigned long flags;
    char* fs_options;
    int fs_mgr_flags;
    char* key_loc;
    char* verity_loc;
    long long length;
    char* label;
    int partnum;
    int swap_prio;
    int max_comp_streams;
    unsigned int zram_size;
    uint64_t reserved_size;
    unsigned int file_contents_mode;
    unsigned int file_names_mode;
    unsigned int erase_blk_size;
    unsigned int logical_blk_size;
};

struct fstab* fs_mgr_read_fstab_default();
struct fstab* fs_mgr_read_fstab_dt();
struct fstab* fs_mgr_read_fstab(const char* fstab_path);
void fs_mgr_free_fstab(struct fstab* fstab);

int fs_mgr_add_entry(struct fstab* fstab, const char* mount_point, const char* fs_type,
                     const char* blk_device);
struct fstab_rec* fs_mgr_get_entry_for_mount_point(struct fstab* fstab, const char* path);
int fs_mgr_is_voldmanaged(const struct fstab_rec* fstab);
int fs_mgr_is_nonremovable(const struct fstab_rec* fstab);
int fs_mgr_is_verified(const struct fstab_rec* fstab);
int fs_mgr_is_verifyatboot(const struct fstab_rec* fstab);
int fs_mgr_is_avb(const struct fstab_rec* fstab);
int fs_mgr_is_encryptable(const struct fstab_rec* fstab);
int fs_mgr_is_file_encrypted(const struct fstab_rec* fstab);
void fs_mgr_get_file_encryption_modes(const struct fstab_rec* fstab, const char** contents_mode_ret,
                                      const char** filenames_mode_ret);
int fs_mgr_is_convertible_to_fbe(const struct fstab_rec* fstab);
int fs_mgr_is_noemulatedsd(const struct fstab_rec* fstab);
int fs_mgr_is_notrim(struct fstab_rec* fstab);
int fs_mgr_is_formattable(struct fstab_rec* fstab);
int fs_mgr_is_slotselect(struct fstab_rec* fstab);
int fs_mgr_is_nofail(struct fstab_rec* fstab);
int fs_mgr_is_latemount(struct fstab_rec* fstab);
int fs_mgr_is_quota(struct fstab_rec* fstab);

__END_DECLS

// C++ only functions
// TODO: move this into separate header files under include/fs_mgr/*.h
#ifdef __cplusplus
std::string fs_mgr_get_slot_suffix();
#endif

#endif /* __CORE_FS_TAB_H */

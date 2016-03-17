/*
* Copyright (C) 2014 MediaTek Inc.
* Modification based on code covered by the mentioned copyright
* and/or permission notice(s).
*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <libgen.h>
#include <time.h>
#include <sys/swap.h>
#include <dirent.h>
#include <ext4.h>
#include <ext4_sb.h>
#include <ext4_crypt_init_extensions.h>

#include <linux/loop.h>
#include <private/android_filesystem_config.h>
#include <cutils/android_reboot.h>
#include <cutils/partition_utils.h>
#include <cutils/properties.h>
#include <logwrap/logwrap.h>

#include "mincrypt/rsa.h"
#include "mincrypt/sha.h"
#include "mincrypt/sha256.h"

#include "ext4_utils.h"
#include "wipe.h"

#include "fs_mgr_priv.h"
#include "fs_mgr_priv_verity.h"

#define KEY_LOC_PROP   "ro.crypto.keyfile.userdata"
#define KEY_IN_FOOTER  "footer"

#define E2FSCK_BIN      "/system/bin/e2fsck"
#define F2FS_FSCK_BIN  "/system/bin/fsck.f2fs"
#define MKSWAP_BIN      "/system/bin/mkswap"


#define FSCK_LOG_FILE   "/dev/fscklogs/log"

#define ZRAM_CONF_DEV   "/sys/block/zram0/disksize"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))

#ifdef MTK_FSTAB_FLAGS
#define RESIZE_EXT4   "/system/bin/resize_ext4"
#endif
#define PROTECT_1_MNT_POINT "/protect_f"
#define PROTECT_2_MNT_POINT "/protect_s"

int execute_cmd(char *cmd_argv[], int argc);
#ifdef MTK_FSTAB_FLAGS
static void resize_fs(char *blk_device, char *key_loc);
#endif

#if defined(MTK_UBIFS_SUPPORT) || defined (MTK_FTL_SUPPORT)
struct ubi_blkcreate_req {
    __s8  padding[128];
}  __packed;
#define UBI_VOL_IOC_MAGIC 'O'
#define UBI_IOCVOLCRBLK _IOW(UBI_VOL_IOC_MAGIC, 7, struct ubi_blkcreate_req)
static int mtd_name_to_number(const char *name);
static int ubi_attach_mtd(const char *name);
#endif

/*
 * gettime() - returns the time in seconds of the system's monotonic clock or
 * zero on error.
 */
static time_t gettime(void)
{
    struct timespec ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &ts);
    if (ret < 0) {
        ERROR("clock_gettime(CLOCK_MONOTONIC) failed: %s\n", strerror(errno));
        return 0;
    }

    return ts.tv_sec;
}

static int wait_for_file(const char *filename, int timeout)
{
    struct stat info;
    time_t timeout_time = gettime() + timeout;
    int ret = -1;

    while (gettime() < timeout_time && ((ret = stat(filename, &info)) < 0))
        usleep(10000);

    return ret;
}

static void check_fs(char *blk_device, char *fs_type, char *target)
{
    int status;
    int ret;
    long tmpmnt_flags = MS_NOATIME | MS_NOEXEC | MS_NOSUID;
    char *tmpmnt_opts = "nomblk_io_submit,errors=remount-ro";
    char *e2fsck_argv[] = {
        E2FSCK_BIN,
        "-y",
        blk_device
    };

    /* Check for the types of filesystems we know how to check */
    if (!strcmp(fs_type, "ext2") || !strcmp(fs_type, "ext3") || !strcmp(fs_type, "ext4")) {
        /*
         * First try to mount and unmount the filesystem.  We do this because
         * the kernel is more efficient than e2fsck in running the journal and
         * processing orphaned inodes, and on at least one device with a
         * performance issue in the emmc firmware, it can take e2fsck 2.5 minutes
         * to do what the kernel does in about a second.
         *
         * After mounting and unmounting the filesystem, run e2fsck, and if an
         * error is recorded in the filesystem superblock, e2fsck will do a full
         * check.  Otherwise, it does nothing.  If the kernel cannot mount the
         * filesytsem due to an error, e2fsck is still run to do a full check
         * fix the filesystem.
         */
        errno = 0;
        ret = mount(blk_device, target, fs_type, tmpmnt_flags, tmpmnt_opts);
        INFO("%s(): mount(%s,%s,%s)=%d: %s\n",
             __func__, blk_device, target, fs_type, ret, strerror(errno));
        if (!ret) {
            int i;
            for (i = 0; i < 5; i++) {
                // Try to umount 5 times before continuing on.
                // Should we try rebooting if all attempts fail?
                int result = umount(target);
                if (result == 0) {
                    INFO("%s(): unmount(%s) succeeded\n", __func__, target);
                    break;
                }
                ERROR("%s(): umount(%s)=%d: %s\n", __func__, target, result, strerror(errno));
                sleep(1);
            }
        }

        /*
         * Some system images do not have e2fsck for licensing reasons
         * (e.g. recent SDK system images). Detect these and skip the check.
         */
        if (access(E2FSCK_BIN, X_OK)) {
            INFO("Not running %s on %s (executable not in system image)\n",
                 E2FSCK_BIN, blk_device);
        } else {
            INFO("Running %s on %s\n", E2FSCK_BIN, blk_device);

            ret = android_fork_execvp_ext(ARRAY_SIZE(e2fsck_argv), e2fsck_argv,
                                        &status, true, LOG_KLOG | LOG_FILE,
                                        true, FSCK_LOG_FILE);

            if (ret < 0) {
                /* No need to check for error in fork, we can't really handle it now */
                ERROR("Failed trying to run %s\n", E2FSCK_BIN);
            }
        }
    } else if (!strcmp(fs_type, "f2fs")) {
            char *f2fs_fsck_argv[] = {
                    F2FS_FSCK_BIN,
                    "-f",
                    blk_device
            };
        INFO("Running %s -f %s\n", F2FS_FSCK_BIN, blk_device);

        ret = android_fork_execvp_ext(ARRAY_SIZE(f2fs_fsck_argv), f2fs_fsck_argv,
                                      &status, true, LOG_KLOG | LOG_FILE,
                                      true, FSCK_LOG_FILE);
        if (ret < 0) {
            /* No need to check for error in fork, we can't really handle it now */
            ERROR("Failed trying to run %s\n", F2FS_FSCK_BIN);
        }
    }

    return;
}

int misc_set_phone_encrypt_state(const struct phone_encrypt_state *in, struct fstab *fstab) {
#ifdef MTK_EMMC_SUPPORT
    int dev = -1;
    char dev_name[256];
    int count;
    struct fstab_rec* rec;

    if ((rec = fs_mgr_get_entry_for_mount_point(fstab, "/misc"))) {
       strcpy(dev_name, rec->blk_device);
    }
    else {
       strcpy(dev_name, "/dev/misc");
    }

    dev = open(dev_name, O_WRONLY);
    if (dev < 0)  {
        ERROR("Can't open %s\n(%s)\n", dev_name, strerror(errno));
        return -1;
    }

    if (lseek(dev, PHONE_ENCRYPT_OFFSET, SEEK_SET) == -1) {
        ERROR("Failed seeking %s\n(%s)\n", dev_name, strerror(errno));
        close(dev);
        return -1;
    }

    count = write(dev, in, sizeof(*in));
    if (count != sizeof(*in)) {
        ERROR("Failed writing %s\n(%s)\n", dev_name, strerror(errno));
        close(dev);
        return -1;
    }
    if (close(dev) != 0) {
        ERROR("Failed closing %s\n(%s)\n", dev_name, strerror(errno));
        return -1;
    }
#else
     (void*)in;
     (void*)fstab;
#endif
    return 0;
}

int misc_get_phone_encrypt_state(struct phone_encrypt_state *in, struct fstab *fstab) {
#ifdef MTK_EMMC_SUPPORT
    int dev = -1;
    char dev_name[256];
    int count;
    struct fstab_rec* rec;

    if ((rec = fs_mgr_get_entry_for_mount_point(fstab, "/misc"))) {
       strcpy(dev_name, rec->blk_device);
    }
    else {
       strcpy(dev_name, "/dev/misc");
    }

    dev = open(dev_name, O_RDONLY);
    if (dev < 0)  {
        ERROR("Can't open %s\n(%s)\n", dev_name, strerror(errno));
        return -1;
    }

    if (lseek(dev, PHONE_ENCRYPT_OFFSET, SEEK_SET) == -1) {
        ERROR("Failed seeking %s\n(%s)\n", dev_name, strerror(errno));
        close(dev);
        return -1;
    }

    count = read(dev, in, sizeof(*in));
    if (count != sizeof(*in)) {
        ERROR("Failed reading %s\n(%s)\n", dev_name, strerror(errno));
        close(dev);
        return -1;
    }
    if (close(dev) != 0) {
        ERROR("Failed closing %s\n(%s)\n", dev_name, strerror(errno));
        return -1;
    }
#else
     (void*)in;
     (void*)fstab;
#endif
    return 0;
}

static void remove_trailing_slashes(char *n)
{
    int len;

    len = strlen(n) - 1;
    while ((*(n + len) == '/') && len) {
      *(n + len) = '\0';
      len--;
    }
}

/*
 * Mark the given block device as read-only, using the BLKROSET ioctl.
 * Return 0 on success, and -1 on error.
 */
int fs_mgr_set_blk_ro(const char *blockdev)
{
    int fd;
    int rc = -1;
    int ON = 1;

    fd = TEMP_FAILURE_RETRY(open(blockdev, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        // should never happen
        return rc;
    }

    rc = ioctl(fd, BLKROSET, &ON);
    close(fd);

    return rc;
}

/*
 * __mount(): wrapper around the mount() system call which also
 * sets the underlying block device to read-only if the mount is read-only.
 * See "man 2 mount" for return values.
 */
static int __mount(const char *source, const char *target, const struct fstab_rec *rec, int encryptable, struct fstab *fstab)
{
    unsigned long mountflags = rec->flags;
    int ret;
    int save_errno;
    bool is_nvram_in_data = true;

    /* We need this because sometimes we have legacy symlinks
     * that are lingering around and need cleaning up.
     */
    struct stat info;
    if (!lstat(target, &info))
        if ((info.st_mode & S_IFMT) == S_IFLNK)
            unlink(target);
    mkdir(target, 0755);

    NOTICE("%s: target='%s, encryptable=%d \n", __FUNCTION__, target, encryptable);

    if (fs_mgr_get_entry_for_mount_point(fstab, "/nvdata")) {
         NOTICE("%s: 'nvdata' partition exists!", __FUNCTION__);
         is_nvram_in_data = false;
    }
    if(encryptable == FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED && is_nvram_in_data && (!strcmp(target, PROTECT_1_MNT_POINT) || !strcmp(target, PROTECT_2_MNT_POINT))) {
         NOTICE("encryptable is FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED. Need to mount '%s' as tmpfs\n", target);
         if ((ret = fs_mgr_do_tmpfs_mount((char *)target))) {
             ERROR("Mount '%s' to tmpfs fail. \n", target);
         }
         else {
             NOTICE("Try to copy modem nvram from emmc to the tmpfs of '%s'\n", target);
             char tmp_mnt_point[256];

             snprintf(tmp_mnt_point, sizeof(tmp_mnt_point),  "/mnt%s", target);
             char *mkdir_argv[] = {"/system/bin/mkdir", tmp_mnt_point};
             execute_cmd(mkdir_argv, ARRAY_SIZE(mkdir_argv));

             if (!access(tmp_mnt_point, F_OK) && (ret = mount(source, tmp_mnt_point, rec->fs_type, mountflags, rec->fs_options))) {
                 ERROR("Fail: mount '%s', errno=%d \n", tmp_mnt_point, errno);
             }
             else {
                char *cp_argv[] = {"/system/bin/cp", "-Rp", tmp_mnt_point, "/"};
                execute_cmd(cp_argv, ARRAY_SIZE(cp_argv));

                char *umount_argv[] = {"/system/bin/umount", tmp_mnt_point};
                if(!execute_cmd(umount_argv, ARRAY_SIZE(umount_argv))) {
                    char *rm_argv[] = {"/system/bin/rm", "-rf", tmp_mnt_point};
                    execute_cmd(rm_argv, ARRAY_SIZE(rm_argv));
                }
             }
         }
    }
    else {
        ret = mount(source, target, rec->fs_type, mountflags, rec->fs_options);
        save_errno = errno;
        INFO("%s(source=%s,target=%s,type=%s)=%d\n", __func__, source, target, rec->fs_type, ret);
        if ((ret == 0) && (mountflags & MS_RDONLY) != 0) {
            fs_mgr_set_blk_ro(source);
        }

        #ifdef MTK_EMMC_SUPPORT
        if ((ret == 0) && rec->fs_mgr_flags & (MF_CRYPT | MF_FORCECRYPT)) {
            struct phone_encrypt_state ps;
            if (misc_get_phone_encrypt_state(&ps, fstab) < 0) {
                ERROR("Failed to get encrypted status in MISC \n");
            }
            else {
                NOTICE("Success: get encrypted status: 0x%x in MISC \n", ps.state);
                if (ps.state == PHONE_ENCRYPTED) {
                   ps.state = PHONE_UNCRYPTED;
                   if (misc_set_phone_encrypt_state(&ps, fstab) < 0) {
                       ERROR("Failed to set encrypted status to 0x%x in MISC \n", ps.state);
                   }
                   else {
                       NOTICE("Success: Set encrypted status to 0x%x in MISC \n", ps.state);
                   }
                }
            }
        }
        #endif
        errno = save_errno;
    }
    return ret;
}

static int fs_match(char *in1, char *in2)
{
    char *n1;
    char *n2;
    int ret;

    n1 = strdup(in1);
    n2 = strdup(in2);

    remove_trailing_slashes(n1);
    remove_trailing_slashes(n2);

    ret = !strcmp(n1, n2);

    free(n1);
    free(n2);

    return ret;
}

static int device_is_debuggable() {
    int ret = -1;
    char value[PROP_VALUE_MAX];
    ret = __system_property_get("ro.debuggable", value);
    if (ret < 0)
        return ret;
    return strcmp(value, "1") ? 0 : 1;
}

static int device_is_secure() {
    int ret = -1;
    char value[PROP_VALUE_MAX];
    ret = __system_property_get("ro.secure", value);
    /* If error, we want to fail secure */
    if (ret < 0)
        return 1;
    return strcmp(value, "0") ? 1 : 0;
}

static int device_is_force_encrypted() {
    int ret = -1;
    char value[PROP_VALUE_MAX];
    ret = __system_property_get("ro.vold.forceencryption", value);
    if (ret < 0)
        return 0;
    return strcmp(value, "1") ? 0 : 1;
}

/*
 * Tries to mount any of the consecutive fstab entries that match
 * the mountpoint of the one given by fstab->recs[start_idx].
 *
 * end_idx: On return, will be the last rec that was looked at.
 * attempted_idx: On return, will indicate which fstab rec
 *     succeeded. In case of failure, it will be the start_idx.
 * Returns
 *   -1 on failure with errno set to match the 1st mount failure.
 *   0 on success.
 */
static int mount_with_alternatives(struct fstab *fstab, int start_idx, int *end_idx, int *attempted_idx, int encryptable)
{
    int i;
    int mount_errno = 0;
    int mounted = 0;

    if (!end_idx || !attempted_idx || start_idx >= fstab->num_entries) {
      errno = EINVAL;
      if (end_idx) *end_idx = start_idx;
      if (attempted_idx) *end_idx = start_idx;
      return -1;
    }

    /* Hunt down an fstab entry for the same mount point that might succeed */
    for (i = start_idx;
         /* We required that fstab entries for the same mountpoint be consecutive */
         i < fstab->num_entries && !strcmp(fstab->recs[start_idx].mount_point, fstab->recs[i].mount_point);
         i++) {
            /*
             * Don't try to mount/encrypt the same mount point again.
             * Deal with alternate entries for the same point which are required to be all following
             * each other.
             */
            if (mounted) {
                ERROR("%s(): skipping fstab dup mountpoint=%s rec[%d].fs_type=%s already mounted as %s.\n", __func__,
                     fstab->recs[i].mount_point, i, fstab->recs[i].fs_type, fstab->recs[*attempted_idx].fs_type);
                continue;
            }
#ifdef MTK_FSTAB_FLAGS
            if(fstab->recs[i].fs_mgr_flags & MF_RESIZE) {
                check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                         fstab->recs[i].mount_point);
                resize_fs(fstab->recs[i].blk_device, fstab->recs[i].key_loc);
            }
#endif

            if (fstab->recs[i].fs_mgr_flags & MF_CHECK) {
                check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                         fstab->recs[i].mount_point);
            }
            if (!__mount(fstab->recs[i].blk_device, fstab->recs[i].mount_point, &fstab->recs[i], encryptable, fstab)) {
                *attempted_idx = i;
                mounted = 1;
                if (i != start_idx) {
                    ERROR("%s(): Mounted %s on %s with fs_type=%s instead of %s\n", __func__,
                         fstab->recs[i].blk_device, fstab->recs[i].mount_point, fstab->recs[i].fs_type,
                         fstab->recs[start_idx].fs_type);
                }
            } else {
                /* back up errno for crypto decisions */
                mount_errno = errno;
            }
    }

    /* Adjust i for the case where it was still withing the recs[] */
    if (i < fstab->num_entries) --i;

    *end_idx = i;
    if (!mounted) {
        *attempted_idx = start_idx;
        errno = mount_errno;
        return -1;
    }
    return 0;
}

static int translate_ext_labels(struct fstab_rec *rec)
{
    DIR *blockdir = NULL;
    struct dirent *ent;
    char *label;
    size_t label_len;
    int ret = -1;

    if (strncmp(rec->blk_device, "LABEL=", 6))
        return 0;

    label = rec->blk_device + 6;
    label_len = strlen(label);

    if (label_len > 16) {
        ERROR("FS label is longer than allowed by filesystem\n");
        goto out;
    }


    blockdir = opendir("/dev/block");
    if (!blockdir) {
        ERROR("couldn't open /dev/block\n");
        goto out;
    }

    while ((ent = readdir(blockdir))) {
        int fd;
        char super_buf[1024];
        struct ext4_super_block *sb;

        if (ent->d_type != DT_BLK)
            continue;

        fd = openat(dirfd(blockdir), ent->d_name, O_RDONLY);
        if (fd < 0) {
            ERROR("Cannot open block device /dev/block/%s\n", ent->d_name);
            goto out;
        }

        if (TEMP_FAILURE_RETRY(lseek(fd, 1024, SEEK_SET)) < 0 ||
            TEMP_FAILURE_RETRY(read(fd, super_buf, 1024)) != 1024) {
            /* Probably a loopback device or something else without a readable
             * superblock.
             */
            close(fd);
            continue;
        }

        sb = (struct ext4_super_block *)super_buf;
        if (sb->s_magic != EXT4_SUPER_MAGIC) {
            INFO("/dev/block/%s not ext{234}\n", ent->d_name);
            continue;
        }

        if (!strncmp(label, sb->s_volume_name, label_len)) {
            char *new_blk_device;

            if (asprintf(&new_blk_device, "/dev/block/%s", ent->d_name) < 0) {
                ERROR("Could not allocate block device string\n");
                goto out;
            }

            INFO("resolved label %s to %s\n", rec->blk_device, new_blk_device);

            free(rec->blk_device);
            rec->blk_device = new_blk_device;
            ret = 0;
            break;
        }
    }

out:
    closedir(blockdir);
    return ret;
}

// Check to see if a mountable volume has encryption requirements
static int handle_encryptable(struct fstab *fstab, const struct fstab_rec* rec)
{
    /* If this is block encryptable, need to trigger encryption */
    if (   (rec->fs_mgr_flags & MF_FORCECRYPT)
        || (device_is_force_encrypted() && fs_mgr_is_encryptable(rec))) {
        if (umount(rec->mount_point) == 0) {
            return FS_MGR_MNTALL_DEV_NEEDS_ENCRYPTION;
        } else {
            WARNING("Could not umount %s (%s) - allow continue unencrypted\n",
                    rec->mount_point, strerror(errno));
            return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
        }
    }

    // Deal with file level encryption
    if (rec->fs_mgr_flags & MF_FILEENCRYPTION) {
        // Default or not yet initialized encryption requires no more work here
        if (!e4crypt_non_default_key(rec->mount_point)) {
            INFO("%s is default file encrypted\n", rec->mount_point);
            return FS_MGR_MNTALL_DEV_DEFAULT_FILE_ENCRYPTED;
        }

        INFO("%s is non-default file encrypted\n", rec->mount_point);

        // Uses non-default key, so must unmount and set up temp file system
        if (umount(rec->mount_point)) {
            ERROR("Failed to umount %s - rebooting\n", rec->mount_point);
            return FS_MGR_MNTALL_FAIL;
        }

        if (fs_mgr_do_tmpfs_mount(rec->mount_point) != 0) {
            ERROR("Failed to mount a tmpfs at %s\n", rec->mount_point);
            return FS_MGR_MNTALL_FAIL;
        }

        // Mount data temporarily so we can access unencrypted dir
        char tmp_mnt[PATH_MAX];
        strlcpy(tmp_mnt, rec->mount_point, sizeof(tmp_mnt));
        strlcat(tmp_mnt, "/tmp_mnt", sizeof(tmp_mnt));
        if (mkdir(tmp_mnt, 0700)) {
            ERROR("Failed to create temp mount point\n");
            return FS_MGR_MNTALL_FAIL;
        }

        if (fs_mgr_do_mount(fstab, rec->mount_point,
                            rec->blk_device, tmp_mnt)) {
            ERROR("Error temp mounting encrypted file system\n");
            return FS_MGR_MNTALL_FAIL;
        }

        return FS_MGR_MNTALL_DEV_NON_DEFAULT_FILE_ENCRYPTED;
    }

    return FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
}

#ifdef MTK_FTL_SUPPORT
static int ftl_attach_ubi(int ubi_num)
{
    int err = 0;
    int ubi_vol;
    char tmp[25];
    int n = sprintf(tmp, "/dev/ubi%d_0", ubi_num);
    ubi_vol = open(tmp, O_RDWR);
    err = ioctl(ubi_vol, UBI_IOCVOLCRBLK, NULL);

    if (err) {
        if (errno == ENOSYS)
            ERROR("MTK FTL is not present in the system");
        if (errno == ENOTTY)
            ERROR("MTK FTL not supported (check your kernel version)");
        ERROR("cannot create block device %d\n", err);
        goto out_close;
    }

    close(ubi_vol);
    return 0;

out_close:
    close(ubi_vol);
    return -1;

}
#endif

/* When multiple fstab records share the same mount_point, it will
 * try to mount each one in turn, and ignore any duplicates after a
 * first successful mount.
 * Returns -1 on error, and  FS_MGR_MNTALL_* otherwise.
 */
int fs_mgr_mount_all(struct fstab *fstab)
{
    int i = 0;
    int encryptable = FS_MGR_MNTALL_DEV_NOT_ENCRYPTED;
    int error_count = 0;
    int mret = -1;
    int mount_errno = 0;
    int attempted_idx = -1;

    if (!fstab) {
        return -1;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't mount entries that are managed by vold */
        if (fstab->recs[i].fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) {
            continue;
        }

        /* Skip swap and raw partition entries such as boot, recovery, etc */
        if (!strcmp(fstab->recs[i].fs_type, "swap") ||
            !strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            continue;
        }

        /* Translate LABEL= file system labels into block devices */
        if (!strcmp(fstab->recs[i].fs_type, "ext2") ||
            !strcmp(fstab->recs[i].fs_type, "ext3") ||
            !strcmp(fstab->recs[i].fs_type, "ext4")) {
            int tret = translate_ext_labels(&fstab->recs[i]);
            if (tret < 0) {
                ERROR("Could not translate label to block device\n");
                continue;
            }
        }
       ERROR("blk device name %s\n", fstab->recs[i].blk_device);
#if defined(MTK_UBIFS_SUPPORT) || defined (MTK_FTL_SUPPORT)
    if (strcmp(fstab->recs[i].fs_type, "ubifs") == 0 && strncmp("ubi@", fstab->recs[i].blk_device, 4) == 0) {
        char tmp[25];
        int n = ubi_attach_mtd(fstab->recs[i].blk_device + 4);
        if (n < 0) {
            ERROR("ubi_attach_mtd fail device name %s\n", fstab->recs[i].blk_device+4);
            return -1;
        }

        n = sprintf(tmp, "/dev/ubi%d_0", n);
        free(fstab->recs[i].blk_device);
        fstab->recs[i].blk_device = malloc(n+1);
        sprintf(fstab->recs[i].blk_device, "%s", tmp);
        ERROR("debug : ubifs blk_device %s", fstab->recs[i].blk_device);
    } else if (!strcmp(fstab->recs[i].fs_type, "rawfs") || !strcmp(fstab->recs[i].fs_type, "yaffs2")) {
        char tmp[25];
        int n = mtd_name_to_number(fstab->recs[i].blk_device + 4);
        if (n < 0) {
            return -1;
        }

       n = sprintf(tmp, "/dev/block/mtdblock%d", n);
       free(fstab->recs[i].blk_device);
       fstab->recs[i].blk_device = malloc(n+1);
       sprintf(fstab->recs[i].blk_device, "%s", tmp);
       ERROR("debug : rawfs blk_device %s", fstab->recs[i].blk_device);
    }
#ifdef MTK_FTL_SUPPORT
    else if (!strcmp(fstab->recs[i].fs_type, "ext4") && strstr(fstab->recs[i].blk_device, "ftl")) {
        char tmp[30];
        int err = 0;
        int n = -1;
        int ubi_num = fstab->recs[i].blk_device[21] - '0';
        ERROR("debug : mtk_ftl_blk %s ubi_num %d\n", fstab->recs[i].blk_device, ubi_num);
        if(strstr(fstab->recs[i].mount_point, "system")){
            n = ubi_attach_mtd("system");
        }else if(strstr(fstab->recs[i].mount_point, "data")){
            n = ubi_attach_mtd("userdata");
        }else if(strstr(fstab->recs[i].mount_point, "cache")){
            n = ubi_attach_mtd("cache");
        }
        if((n != ubi_num) && (n >= 0))
        {
            ERROR("ubi number: %d == %d\n", n, ubi_num);
            ubi_num = n;
        }
        n = sprintf(tmp, "/dev/ubi%d_0", ubi_num);
        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            int ret = wait_for_file(tmp, WAIT_TIMEOUT);
            ERROR("wait_for_file(%s) ret = %d, errno = %s\n", fstab->recs[i].blk_device, ret, strerror(errno));
        }
        err = ftl_attach_ubi(ubi_num);
        if (err < 0) {
            return -1;
        }
    }
#endif
#endif
        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
        }

        if ((fstab->recs[i].fs_mgr_flags & MF_VERIFY) && device_is_secure()) {
            int rc = fs_mgr_setup_verity(&fstab->recs[i]);
            if (device_is_debuggable() && rc == FS_MGR_SETUP_VERITY_DISABLED) {
                INFO("Verity disabled");
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                ERROR("Could not set up verified partition, skipping!\n");
                continue;
            }
        }
        int last_idx_inspected;
        int top_idx = i;

        mret = mount_with_alternatives(fstab, i, &last_idx_inspected, &attempted_idx, encryptable);
        i = last_idx_inspected;
        mount_errno = errno;

        /* Deal with encryptability. */
        if (!mret) {
            int status = handle_encryptable(fstab, &fstab->recs[attempted_idx]);

            if (status == FS_MGR_MNTALL_FAIL) {
                /* Fatal error - no point continuing */
                return status;
            }

            if (status != FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
                if (encryptable != FS_MGR_MNTALL_DEV_NOT_ENCRYPTED) {
                    // Log and continue
                    ERROR("Only one encryptable/encrypted partition supported\n");
                }
                encryptable = status;
            }

            /* Success!  Go get the next one */
            continue;
        }

        /* mount(2) returned an error, handle the encryptable/formattable case */
        bool wiped = partition_wiped(fstab->recs[top_idx].blk_device);
        if (mret && mount_errno != EBUSY && mount_errno != EACCES &&
            fs_mgr_is_formattable(&fstab->recs[top_idx]) && wiped) {
            /* top_idx and attempted_idx point at the same partition, but sometimes
             * at two different lines in the fstab.  Use the top one for formatting
             * as that is the preferred one.
             */
            ERROR("%s(): %s is wiped and %s %s is formattable. Format it.\n", __func__,
                  fstab->recs[top_idx].blk_device, fstab->recs[top_idx].mount_point,
                  fstab->recs[top_idx].fs_type);
            if (fs_mgr_is_encryptable(&fstab->recs[top_idx]) &&
                strcmp(fstab->recs[top_idx].key_loc, KEY_IN_FOOTER)) {
                int fd = open(fstab->recs[top_idx].key_loc, O_WRONLY, 0644);
                if (fd >= 0) {
                    INFO("%s(): also wipe %s\n", __func__, fstab->recs[top_idx].key_loc);
                    wipe_block_device(fd, get_file_size(fd));
                    close(fd);
                } else {
                    ERROR("%s(): %s wouldn't open (%s)\n", __func__,
                          fstab->recs[top_idx].key_loc, strerror(errno));
                }
            }
            if (fs_mgr_do_format(&fstab->recs[top_idx]) == 0) {
                /* Let's replay the mount actions. */
                i = top_idx - 1;
                continue;
            }
        }
        if (mret && mount_errno != EBUSY && mount_errno != EACCES &&
            fs_mgr_is_encryptable(&fstab->recs[attempted_idx])) {
            if (wiped) {
                ERROR("%s(): %s is wiped and %s %s is encryptable. Suggest recovery...\n", __func__,
                      fstab->recs[attempted_idx].blk_device, fstab->recs[attempted_idx].mount_point,
                      fstab->recs[attempted_idx].fs_type);
                encryptable = FS_MGR_MNTALL_DEV_NEEDS_RECOVERY;
                continue;
            } else {
                /* Need to mount a tmpfs at this mountpoint for now, and set
                 * properties that vold will query later for decrypting
                 */
                ERROR("%s(): possibly an encryptable blkdev %s for mount %s type %s )\n", __func__,
                      fstab->recs[attempted_idx].blk_device, fstab->recs[attempted_idx].mount_point,
                      fstab->recs[attempted_idx].fs_type);
                if (fs_mgr_do_tmpfs_mount(fstab->recs[attempted_idx].mount_point) < 0) {
                    ++error_count;
                    continue;
                }
            }
            encryptable = FS_MGR_MNTALL_DEV_MIGHT_BE_ENCRYPTED;
        } else {
            ERROR("Failed to mount an un-encryptable or wiped partition on"
                   "%s at %s options: %s error: %s\n",
                   fstab->recs[attempted_idx].blk_device, fstab->recs[attempted_idx].mount_point,
                   fstab->recs[attempted_idx].fs_options, strerror(mount_errno));
            ++error_count;
            continue;
        }
    }

    if (error_count) {
        return -1;
    } else {
        return encryptable;
    }
}

/* If tmp_mount_point is non-null, mount the filesystem there.  This is for the
 * tmp mount we do to check the user password
 * If multiple fstab entries are to be mounted on "n_name", it will try to mount each one
 * in turn, and stop on 1st success, or no more match.
 */
int fs_mgr_do_mount(struct fstab *fstab, char *n_name, char *n_blk_device,
                    char *tmp_mount_point)
{
    int i = 0;
    int ret = FS_MGR_DOMNT_FAILED;
    int mount_errors = 0;
    int first_mount_errno = 0;
    char *m;

    if (!fstab) {
        return ret;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        if (!fs_match(fstab->recs[i].mount_point, n_name)) {
            continue;
        }

        /* We found our match */
        /* If this swap or a raw partition, report an error */
        if (!strcmp(fstab->recs[i].fs_type, "swap") ||
            !strcmp(fstab->recs[i].fs_type, "emmc") ||
            !strcmp(fstab->recs[i].fs_type, "mtd")) {
            ERROR("Cannot mount filesystem of type %s on %s\n",
                  fstab->recs[i].fs_type, n_blk_device);
            goto out;
        }

        /* First check the filesystem if requested */
        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(n_blk_device, WAIT_TIMEOUT);
        }
#ifdef MTK_FSTAB_FLAGS
            if(fstab->recs[i].fs_mgr_flags & MF_RESIZE) {
                check_fs(fstab->recs[i].blk_device, fstab->recs[i].fs_type,
                         fstab->recs[i].mount_point);
                resize_fs(fstab->recs[i].blk_device, fstab->recs[i].key_loc);
            }
#endif

        if (fstab->recs[i].fs_mgr_flags & MF_CHECK) {
            check_fs(n_blk_device, fstab->recs[i].fs_type,
                     fstab->recs[i].mount_point);
        }

        if ((fstab->recs[i].fs_mgr_flags & MF_VERIFY) && device_is_secure()) {
            int rc = fs_mgr_setup_verity(&fstab->recs[i]);
            if (device_is_debuggable() && rc == FS_MGR_SETUP_VERITY_DISABLED) {
                INFO("Verity disabled");
            } else if (rc != FS_MGR_SETUP_VERITY_SUCCESS) {
                ERROR("Could not set up verified partition, skipping!\n");
                continue;
            }
        }

        /* Now mount it where requested */
        if (tmp_mount_point) {
            m = tmp_mount_point;
        } else {
            m = fstab->recs[i].mount_point;
        }
        if (__mount(n_blk_device, m, &fstab->recs[i], FS_MGR_MNTALL_DEV_NOT_ENCRYPTED, fstab)) {
            if (!first_mount_errno) first_mount_errno = errno;
            mount_errors++;
            continue;
        } else {
            ret = 0;
            goto out;
        }
    }
    if (mount_errors) {
        ERROR("Cannot mount filesystem on %s at %s. error: %s\n",
            n_blk_device, m, strerror(first_mount_errno));
        if (first_mount_errno == EBUSY) {
            ret = FS_MGR_DOMNT_BUSY;
        } else {
            ret = FS_MGR_DOMNT_FAILED;
        }
    } else {
        /* We didn't find a match, say so and return an error */
        ERROR("Cannot find mount point %s in fstab\n", fstab->recs[i].mount_point);
    }

out:
    return ret;
}

/*
 * mount a tmpfs filesystem at the given point.
 * return 0 on success, non-zero on failure.
 */
int fs_mgr_do_tmpfs_mount(char *n_name)
{
    int ret;

    ret = mount("tmpfs", n_name, "tmpfs",
                MS_NOATIME | MS_NOSUID | MS_NODEV, CRYPTO_TMPFS_OPTIONS);
    if (ret < 0) {
        ERROR("Cannot mount tmpfs filesystem at %s\n", n_name);
        return -1;
    }

    /* Success */
    return 0;
}

int fs_mgr_unmount_all(struct fstab *fstab)
{
    int i = 0;
    int ret = 0;

    if (!fstab) {
        return -1;
    }

    while (fstab->recs[i].blk_device) {
        if (umount(fstab->recs[i].mount_point)) {
            ERROR("Cannot unmount filesystem at %s\n", fstab->recs[i].mount_point);
            ret = -1;
        }
        i++;
    }

    return ret;
}

/* This must be called after mount_all, because the mkswap command needs to be
 * available.
 */
int fs_mgr_swapon_all(struct fstab *fstab)
{
    int i = 0;
    int flags = 0;
    int err = 0;
    int ret = 0;
    int status;
    char *mkswap_argv[2] = {
        MKSWAP_BIN,
        NULL
    };

    if (!fstab) {
        return -1;
    }

    for (i = 0; i < fstab->num_entries; i++) {
        /* Skip non-swap entries */
        if (strcmp(fstab->recs[i].fs_type, "swap")) {
            continue;
        }

        if (fstab->recs[i].zram_size > 0) {
            /* A zram_size was specified, so we need to configure the
             * device.  There is no point in having multiple zram devices
             * on a system (all the memory comes from the same pool) so
             * we can assume the device number is 0.
             */
            FILE *zram_fp;

            zram_fp = fopen(ZRAM_CONF_DEV, "r+");
            if (zram_fp == NULL) {
                ERROR("Unable to open zram conf device %s\n", ZRAM_CONF_DEV);
                ret = -1;
                continue;
            }
            fprintf(zram_fp, "%d\n", fstab->recs[i].zram_size);
            fclose(zram_fp);
        }

        if (fstab->recs[i].fs_mgr_flags & MF_WAIT) {
            wait_for_file(fstab->recs[i].blk_device, WAIT_TIMEOUT);
        }

        /* Initialize the swap area */
        mkswap_argv[1] = fstab->recs[i].blk_device;
        err = android_fork_execvp_ext(ARRAY_SIZE(mkswap_argv), mkswap_argv,
                                      &status, true, LOG_KLOG, false, NULL);
        if (err) {
            ERROR("mkswap failed for %s\n", fstab->recs[i].blk_device);
            ret = -1;
            continue;
        }

        /* If -1, then no priority was specified in fstab, so don't set
         * SWAP_FLAG_PREFER or encode the priority */
        if (fstab->recs[i].swap_prio >= 0) {
            flags = (fstab->recs[i].swap_prio << SWAP_FLAG_PRIO_SHIFT) &
                    SWAP_FLAG_PRIO_MASK;
            flags |= SWAP_FLAG_PREFER;
        } else {
            flags = 0;
        }
        err = swapon(fstab->recs[i].blk_device, flags);
        if (err) {
            ERROR("swapon failed for %s\n", fstab->recs[i].blk_device);
            ret = -1;
        }
    }

    return ret;
}

/*
 * key_loc must be at least PROPERTY_VALUE_MAX bytes long
 *
 * real_blk_device must be at least PROPERTY_VALUE_MAX bytes long
 */
int fs_mgr_get_crypt_info(struct fstab *fstab, char *key_loc, char *real_blk_device, int size)
{
    int i = 0;

    if (!fstab) {
        return -1;
    }
    /* Initialize return values to null strings */
    if (key_loc) {
        *key_loc = '\0';
    }
    if (real_blk_device) {
        *real_blk_device = '\0';
    }

    /* Look for the encryptable partition to find the data */
    for (i = 0; i < fstab->num_entries; i++) {
        /* Don't deal with vold managed enryptable partitions here */
        if (fstab->recs[i].fs_mgr_flags & MF_VOLDMANAGED) {
            continue;
        }
        if (!(fstab->recs[i].fs_mgr_flags & (MF_CRYPT | MF_FORCECRYPT))) {
            continue;
        }

        /* We found a match */
        if (key_loc) {
            strlcpy(key_loc, fstab->recs[i].key_loc, size);
        }
        if (real_blk_device) {
            strlcpy(real_blk_device, fstab->recs[i].blk_device, size);
        }
        break;
    }

    return 0;
}

int execute_cmd(char *cmd_argv[], int argc) {
      int status;
      int ret = 0;

      ret = android_fork_execvp_ext(argc, cmd_argv, &status, true, LOG_KLOG, false, NULL);
      if (ret != 0) {
          /* No need to check for error in fork, we can't really handle it now */
          ERROR("Failed trying to run %s\n", cmd_argv[0]);
          return -1;
      }
      else {
          NOTICE("Execute '%s', status(%d), WEXITSTATUS(%d) \n", cmd_argv[0], status, WEXITSTATUS(status));
          return WEXITSTATUS(ret);
      }
}

#ifdef MTK_FSTAB_FLAGS
static void resize_fs(char *blk_device, char *key_loc)
{
    int status;
    int ret;

    char *resize_ext4_argv[] = {
            RESIZE_EXT4,
            blk_device,
            key_loc
    };
    if(key_loc == NULL) {
        resize_ext4_argv[2] = strdup("dummy");
    }
    INFO("Running %s on %s\n", RESIZE_EXT4, blk_device);

    ret = android_fork_execvp_ext(ARRAY_SIZE(resize_ext4_argv), resize_ext4_argv,
            &status, true, LOG_NONE,
            false, NULL);
    if (ret < 0) {
        /* No need to check for error in fork, we can't really handle it now */
        ERROR("Failed trying to run %s\n", RESIZE_EXT4);
    }
exit:
    ERROR("Resize ext4 return %d\n", ret);
}
#endif

#if defined(MTK_UBIFS_SUPPORT) || defined(MTK_FTL_SUPPORT)
//#if 0
#define MAX_MTD_PARTITIONS 40

static struct {
    char name[16];
    int number;
} mtd_part_map[MAX_MTD_PARTITIONS];

static int mtd_part_count = -1;

static void find_mtd_partitions(void)
{
    int fd;
    char buf[1024];
    char *pmtdbufp;
    ssize_t pmtdsize;
    int r;

    fd = open("/proc/mtd", O_RDONLY);
    if (fd < 0)
        return;

    buf[sizeof(buf) - 1] = '\0';
    pmtdsize = read(fd, buf, sizeof(buf) - 1);
    pmtdbufp = buf;
    while (pmtdsize > 0) {
        int mtdnum, mtdsize, mtderasesize;
        char mtdname[16];
        mtdname[0] = '\0';
        mtdnum = -1;
        r = sscanf(pmtdbufp, "mtd%d: %x %x %15s",
                   &mtdnum, &mtdsize, &mtderasesize, mtdname);
        if ((r == 4) && (mtdname[0] == '"')) {
            char *x = strchr(mtdname + 1, '"');
            if (x) {
                *x = 0;
            }
            INFO("mtd partition %d, %s\n", mtdnum, mtdname + 1);
            if (mtd_part_count < MAX_MTD_PARTITIONS) {
                strcpy(mtd_part_map[mtd_part_count].name, mtdname + 1);
                mtd_part_map[mtd_part_count].number = mtdnum;
                mtd_part_count++;
            } else {
                ERROR("too many mtd partitions\n");
            }
        }
        while (pmtdsize > 0 && *pmtdbufp != '\n') {
            pmtdbufp++;
            pmtdsize--;
        }
        if (pmtdsize > 0) {
            pmtdbufp++;
            pmtdsize--;
        }
    }
    close(fd);
}

static int mtd_name_to_number(const char *name)
{
    int n;
    if (mtd_part_count < 0) {
        mtd_part_count = 0;
        find_mtd_partitions();
    }
    for (n = 0; n < mtd_part_count; n++) {
        if (!strcmp(name, mtd_part_map[n].name)) {
            return mtd_part_map[n].number;
        }
    }
    return -1;
}

#define UBI_CTRL_DEV "/dev/ubi_ctrl"
#define UBI_SYS_PATH "/sys/class/ubi"
static int ubi_dev_read_int(int dev, const char *file, int def)
{
    int fd, val = def;
    char path[128], buf[64];

    sprintf(path, UBI_SYS_PATH "/ubi%d/%s", dev, file);
    wait_for_file(path, 5);
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        return val;
    }

    if (read(fd, buf, 64) > 0) {
        val = atoi(buf);
    }

    close(fd);
    return val;
}

// Should include kernel header include/mtd/ubi-user.h
#include <linux/types.h>
#include <asm/ioctl.h>
#define UBI_CTRL_IOC_MAGIC 'o'
#define UBI_IOC_MAGIC 'o'
#define UBI_VOL_NUM_AUTO (-1)
#define UBI_DEV_NUM_AUTO (-1)
#define UBI_IOCATT _IOW(UBI_CTRL_IOC_MAGIC, 64, struct ubi_attach_req)
#define UBI_IOCDET _IOW(UBI_CTRL_IOC_MAGIC, 65, __s32)
#define UBI_IOCMKVOL _IOW(UBI_IOC_MAGIC, 0, struct ubi_mkvol_req)
#define UBI_MAX_VOLUME_NAME 127
#define UBI_VID_OFFSET_AUTO (0)
struct ubi_attach_req {
    __s32 ubi_num;
    __s32 mtd_num;
    __s32 vid_hdr_offset;
    __s8 padding[12];
};

struct ubi_mkvol_req {
    __s32 vol_id;
    __s32 alignment;
    __s64 bytes;
    __s8 vol_type;
    __s8 padding1;
    __s16 name_len;
    __s8 padding2[4];
    char name[UBI_MAX_VOLUME_NAME + 1];
} __packed;

enum {
    UBI_DYNAMIC_VOLUME = 3,
    UBI_STATIC_VOLUME  = 4,
};

// Should include kernel header include/mtd/ubi-user.h

static int ubi_attach_mtd(const char *name)
{
    int ret;
    int mtd_num, ubi_num, vid_off;
    int ubi_ctrl, ubi_dev;
    int vols, avail_lebs, leb_size;
    char path[128];
    struct ubi_attach_req attach_req;
    struct ubi_mkvol_req mkvol_req;
    mtd_num = mtd_name_to_number(name);
    if (mtd_num == -1) {
        return -1;
    }

    for (ubi_num = 0; ubi_num < 4; ubi_num++)
    {
      sprintf(path, "/sys/class/ubi/ubi%d/mtd_num", ubi_num);
      ubi_dev = open(path, O_RDONLY);
      if (ubi_dev != -1)
      {
        ret = read(ubi_dev, path, sizeof(path));
        close(ubi_dev);
        if (ret > 0 && mtd_num == atoi(path))
          return ubi_num;
      }
    }

    ret = wait_for_file(UBI_CTRL_DEV, 50);
    ubi_ctrl = open(UBI_CTRL_DEV, O_RDONLY);
    if (ubi_ctrl == -1) {
        ERROR("open %s fail fail\n", UBI_CTRL_DEV);
        return -1;
    }

    memset(&attach_req, 0, sizeof(struct ubi_attach_req));
    attach_req.ubi_num = UBI_DEV_NUM_AUTO;
    attach_req.mtd_num = mtd_num;
    attach_req.vid_hdr_offset = UBI_VID_OFFSET_AUTO;

    ret = ioctl(ubi_ctrl, UBI_IOCATT, &attach_req);
    if (ret == -1) {
        ERROR("attach mtd fail mtd num %d\n", mtd_num);
        close(ubi_ctrl);
        return -1;
    }

    ubi_num = attach_req.ubi_num;
   vid_off = attach_req.vid_hdr_offset;
    vols = ubi_dev_read_int(ubi_num, "volumes_count", -1);
    if (vols == 0) {
        long long data_vol_size = 0;
        sprintf(path, "/dev/ubi%d", ubi_num);
        ret = wait_for_file(path, 50);
        ubi_dev = open(path, O_RDONLY);
        if (ubi_dev == -1) {
            close(ubi_ctrl);
            return ubi_num;
        }
        avail_lebs = ubi_dev_read_int(ubi_num, "avail_eraseblocks", 0);
        leb_size = ubi_dev_read_int(ubi_num, "eraseblock_size", 0);
        data_vol_size = (long long)avail_lebs * leb_size;
#if defined(MTK_MLC_NAND_SUPPORT)
#if defined(MTK_IPOH_SUPPORT)
        if (!strcmp(name, "userdata")) {
           data_vol_size -= BOARD_UBIFS_IPOH_VOLUME_SIZE;
        }
#endif
#endif
        memset(&mkvol_req, 0, sizeof(struct ubi_mkvol_req));
        mkvol_req.vol_id = UBI_VOL_NUM_AUTO;
        mkvol_req.alignment = 1;
        mkvol_req.bytes = data_vol_size;
        mkvol_req.vol_type = UBI_DYNAMIC_VOLUME;
        ret = snprintf(mkvol_req.name, UBI_MAX_VOLUME_NAME + 1, "%s", name);
        mkvol_req.name_len = ret;
        ioctl(ubi_dev, UBI_IOCMKVOL, &mkvol_req);
#if defined(MTK_MLC_NAND_SUPPORT)
#if defined(MTK_IPOH_SUPPORT)
    if (!strcmp(name, "userdata")) {
       memset(&mkvol_req, 0, sizeof(struct ubi_mkvol_req));
       mkvol_req.vol_id = UBI_VOL_NUM_AUTO;
       mkvol_req.alignment = 1;
       mkvol_req.bytes = (long long)BOARD_UBIFS_IPOH_VOLUME_SIZE;
       mkvol_req.vol_type = UBI_DYNAMIC_VOLUME;
       ret = snprintf(mkvol_req.name, UBI_MAX_VOLUME_NAME + 1, "%s", "ipoh");
       mkvol_req.name_len = ret;
       ioctl(ubi_dev, UBI_IOCMKVOL, &mkvol_req);
   }
#endif
#endif
        close(ubi_dev);
    }

    close(ubi_ctrl);
    return ubi_num;
}

static int ubi_detach_dev(int dev)
{
    int ret, ubi_ctrl;

    ubi_ctrl = open(UBI_CTRL_DEV, O_RDONLY);
    if (ubi_ctrl == -1) {
        return -1;
    }

    ret = ioctl(ubi_ctrl, UBI_IOCDET, &dev);
    close(ubi_ctrl);
    return ret;
}
#endif


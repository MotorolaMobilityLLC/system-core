/*
 * Copyright (C) 2011 Motorola
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*****************************************************************************
 * Recover Userdata
 * Purpose:  Bridges a gap between GED Honeycomb devices which have a
 *           bootloader that formats ext4 partitions, and those that do not.
 *
 *           This program tries to determine if there is a valid filesystem
 *           at the supplied block device.  If not, then it formats the block
 *           device as ext4.
 *
 * Also see:
 * http://source.android.com/tech/encryption/android_crypto_implementation.html
 *
 *****************************************************************************/

#include <stdio.h>    // printf()
#include <stdlib.h>
#include <unistd.h>   // exec()
#include <sys/types.h>// open()
#include <sys/stat.h> // open()
#include <fcntl.h>    // open()
#include <errno.h>    // errno
#include <cutils/partition_utils.h> // partition_wiped()
#include <sys/mount.h>// BLKGETSIZE
#include "make_ext4fs.h" // make_ext4fs
/* Avoid redefinition warnings */
#undef __le32
#undef __le16
#include <cryptfs.h>  // Crypfs footer information

#define UDLOGE printf
#define UDLOGD printf
#define UDLOGV printf

#ifndef MS_SILENT
#define MS_SILENT MS_VERBOSE /* MS_VERBOSE is obsolete but still used in Android mount */
#endif

#define INVALID_BLOCK_SIZE -1

/* is_valid_fs: Check for a validly formatted or encrypted partition
 * Return 1 for plausibly valid filesystem, 0 otherwise.
 */
int is_valid_fs(char *fs_type, char *fs_real_blkdev, char *fs_mnt_point)
{
    int status;
    off64_t off;
    int fd;
    unsigned int nr_sec;
    struct crypt_mnt_ftr crypt_ftr;

    /* Check the likely case first - unencrypted ext4. */
    status = mount(fs_real_blkdev, fs_mnt_point, fs_type, MS_SILENT, 0);
    if (status == 0) {
        /* Valid FS! */
        umount(fs_mnt_point);
        return 1;
    }

    /* 2nd likely case, encrypted filesystem */
    UDLOGD("Problem mounting the raw device, could be encrypted.\n");
    /* Need to calculate the offset of the crypto footer and read it. */
    if ((fd = open(fs_real_blkdev, O_RDWR)) < 0) {
        UDLOGE("Cannot open block device.  %s\n", strerror(errno));
        return 0;
    }
    if ((ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
        UDLOGE("Cannot get block device size.  %s\n", strerror(errno));
        close(fd);
        return 0;
    }
    off = ((off64_t)nr_sec * 512) - CRYPT_FOOTER_OFFSET;
    if (lseek64(fd, off, SEEK_SET) == -1) {
        UDLOGE("Cannot seek to real block device footer.  %s\n", strerror(errno));
        close(fd);
        return 0;
    }
    if ((read(fd, &crypt_ftr, sizeof(struct crypt_mnt_ftr)))
        != sizeof(struct crypt_mnt_ftr)) {
        UDLOGE("Cannot read real block device footer. %s\n", strerror(errno));
        close(fd);
        return 0;
    }
    close(fd);
    if (crypt_ftr.magic == CRYPT_MNT_MAGIC && crypt_ftr.crypto_type_name[0] != '\0') {
        UDLOGD("Success: Found footer magic and partition is encrypted with \"%s\"\n", crypt_ftr.crypto_type_name);
        if (partition_wiped(fs_real_blkdev)) {
            UDLOGD("Found magic but the device is wiped.\n");
            return 0;
        } else {
            UDLOGD("Let vold finish decryption - likely valid encrypted FS\n");
            if (crypt_ftr.failed_decrypt_count)
            {
                UDLOGE("Notice: failed decrypt count is %d\n", crypt_ftr.failed_decrypt_count);
                /* Continue, maybe password errors. */
            }
            if (crypt_ftr.flags & CRYPT_ENCRYPTION_IN_PROGRESS) {
                UDLOGE("Notice: Encryption in progress?  The filesystem will be corrupted.\n");
                return 0;
            }
            return 1;
        }
    }

    /* Least likely case: We just finished a master clear or make_ext4fs didn't finish. */
    UDLOGD("No valid crypto footer and the device isn't mounting.\n");
    return 0;
}


/* format_fs: Creates a file system.
 * Returns 0 on success, -1 on error
 */
extern struct fs_info info;
int format_fs(char *fs_type, char *fs_real_blkdev, char *fs_mnt_point, long int fs_blksize)
{
    int status;
    off64_t off;
    int fd;
    unsigned int nr_sec;
    struct crypt_mnt_ftr crypt_ftr;

    if (!strcmp(fs_type, "f2fs")) {
        char * args[5];
        char footer_size[10];
        snprintf(footer_size, sizeof(footer_size), "%d", CRYPT_FOOTER_OFFSET);
        args[0] = (char *)"/vendor/bin/make_f2fs";
        args[1] = (char *)"-r";
        args[2] = footer_size;
        args[3] = fs_real_blkdev;
        args[4] = (char *)0;
	if (!fork()) {
		/* This doesn't return */
		execv("/vendor/bin/make_f2fs", args);
		return -1;
	}
	wait(&status);
        return 0;
    }
    /* else, it's EXT4 */

    memset (&crypt_ftr, 0, sizeof(crypt_ftr));

    /* Need to calculate the size to format. (Partition size - CRYPT_FOOTER_OFFSET) */
    if ((fd = open(fs_real_blkdev, O_RDWR)) < 0) {
        UDLOGE("Cannot open block device.  %s\n", strerror(errno));
        return -1;
    }
    if ((ioctl(fd, BLKGETSIZE, &nr_sec)) == -1) {
        UDLOGE("Cannot get block device size.  %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    off = ((off64_t)nr_sec * 512) - CRYPT_FOOTER_OFFSET;

    UDLOGD("Wipe the old crypto info\n");
    if (lseek64(fd, off, SEEK_SET) == -1) {
        UDLOGE("Cannot seek to real block device footer.  %s\n", strerror(errno));
        close(fd);
        return -1;
    }
    write(fd, &crypt_ftr, sizeof(struct crypt_mnt_ftr));
    close(fd);

    /* Format the partition using the calculated length */
    reset_ext4fs_info();
    info.len = off;
    if (fs_blksize != INVALID_BLOCK_SIZE)
        info.block_size = fs_blksize;
    fd = open(fs_real_blkdev, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        UDLOGE("Cannot open block device for make_ext4fs.  %s\n",
               strerror(errno));
        return -1;
    }
    status = make_ext4fs_internal(fd, NULL, fs_mnt_point, 0, 0, 0, 0, 0, 0, 0);
    UDLOGV("make_ext4fs returned %d.\n", status);
    close(fd);
    return 0;
}

int main(int argc, char* argv[])
{
    char *fs_type;
    char *fs_real_blkdev;
    char *fs_mnt_point;
    long int fs_blksize = INVALID_BLOCK_SIZE;
    int status = 0;
    if (argc < 4) {
        printf("USAGE: %s <type> <blkdev> <mntpoint> [blksize]\n", argv[0]);
        return -1;
    }

    fs_type = argv[1];
    fs_real_blkdev = argv[2];
    fs_mnt_point = argv[3];
#ifdef BOARD_USERIMAGE_BLOCK_SIZE
    fs_blksize = BOARD_USERIMAGE_BLOCK_SIZE;
#endif
    if (argc > 4)
        fs_blksize = strtol(argv[4], NULL, 10);

    /* Ext2/3/4 only supports these block sizes, so make sure it is sane. */
    if (fs_blksize != INVALID_BLOCK_SIZE && (fs_blksize != 1024 &&
                                             fs_blksize != 2048 &&
                                             fs_blksize != 4096))
    {
        UDLOGE("Block size '%s' not supported; using default\n", argv[4]);
        fs_blksize = INVALID_BLOCK_SIZE;
    }

    if (is_valid_fs(fs_type, fs_real_blkdev, fs_mnt_point)) {
        UDLOGD("Found a valid or encrypted FS\n");
    } else {
        UDLOGE("Formatting %s for %s\n", fs_real_blkdev, fs_mnt_point);
        status = format_fs(fs_type, fs_real_blkdev, fs_mnt_point, fs_blksize);
    }
    return status;
}

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
 * Purpose:  Bridges a gap between GED devices which have a
 *           bootloader that formats ext4 partitions, and those that do not.
 *
 *           The current implementation simply formats the filesystem.
 *
 *****************************************************************************/

#include <stdio.h>    // snprintf()
#include <unistd.h>   // exec()
#include <sys/types.h>// open()
#include <sys/stat.h> // open()
#include <fcntl.h>    // open()
#include <sys/wait.h> // WEXITSTATUS etc.
#include <errno.h>    // errno
#include <cutils/partition_utils.h> // partition_wiped()
#include <sys/mount.h>// BLKGETSIZE
#include "ext4_utils.h"
#include "make_ext4fs.h" // make_ext4fs
#include "fs_mgr_priv.h" // ERROR
/* Avoid redefinition warnings */
#undef __le32
#undef __le16
#include <cryptfs.h>

#define UDLOGE ERROR
#define UDLOGD INFO
#define UDLOGV INFO

#ifndef MS_SILENT
#define MS_SILENT MS_VERBOSE /* MS_VERBOSE is obsolete but still used in Android mount */
#endif

#define INVALID_BLOCK_SIZE -1

/* format_fs: Creates a file system.
 * Returns 0 on success, -1 on error
 */
extern struct fs_info info;
int format_fs(char *fs_type, char *fs_real_blkdev, char *fs_mnt_point, long int fs_blksize)
{
    int status = 0;
    int rc = 0;
    off64_t off;
    int fd, pid;
    unsigned int nr_sec;
    struct crypt_mnt_ftr crypt_ftr;

    if (!strcmp(fs_type, "f2fs")) {
        char * args[5];
        char footer_size[10];
        snprintf(footer_size, sizeof(footer_size), "%d", CRYPT_FOOTER_OFFSET);
        args[0] = (char *)"/system/bin/mkfs.f2fs_arm";
        args[1] = (char *)"-r";
        args[2] = footer_size;
        args[3] = fs_real_blkdev;
        args[4] = (char *)0;
	if (!(pid = fork())) {
		/* This doesn't return */
		execv("/system/bin/mkfs.f2fs_arm", args);
		exit(1);
	}
	for(;;) {
		pid_t p = waitpid(pid, &status, 0);
		if (p != pid) {
			UDLOGE("Error waiting for child process - %d\n", p);
			rc = -1;
			break;
		}
		if (WIFEXITED(status)) {
			rc = WEXITSTATUS(status);
			UDLOGD("mkfs done, status %d", rc);
			if (rc) {
				rc = -1;
			}
			break;
		}
		UDLOGE("still waiting for mkfs.f2fs...\n");
	}
        return rc;
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

/* Recover userdata returns 0 on success, -1 on error. */

int recover_userdata(char *fs_type, char *fs_real_blkdev, char *fs_mnt_point)
{
    long int fs_blksize = INVALID_BLOCK_SIZE;
    int status = 0;

#ifdef BOARD_USERIMAGE_BLOCK_SIZE
    fs_blksize = BOARD_USERIMAGE_BLOCK_SIZE;
#endif

    /* Ext2/3/4 only supports these block sizes, so make sure it is sane. */
    if (fs_blksize != INVALID_BLOCK_SIZE && (fs_blksize != 1024 &&
                                             fs_blksize != 2048 &&
                                             fs_blksize != 4096))
    {
        UDLOGE("Block size '%ld' not supported; using default\n", fs_blksize);
        fs_blksize = INVALID_BLOCK_SIZE;
    }

    UDLOGE("Formatting %s for %s\n", fs_real_blkdev, fs_mnt_point);
    status = format_fs(fs_type, fs_real_blkdev, fs_mnt_point, fs_blksize);

    return status;
}

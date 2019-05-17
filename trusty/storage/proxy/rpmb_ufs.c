/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/major.h>
#include <linux/mmc/ioctl.h>

#include "ipc.h"
#include "log.h"
#include "rpmb.h"
#include "storage.h"

#define MMC_RELIABLE_WRITE_FLAG (1 << 31)

#define MMC_WRITE_FLAG_R 0
#define MMC_WRITE_FLAG_W 1
#define MMC_WRITE_FLAG_RELW (MMC_WRITE_FLAG_W | MMC_RELIABLE_WRITE_FLAG)

#define MMC_BLOCK_SIZE 512

#define UFS_IOCTL_RPMB         0x5391
#define RPMB_PROGRAM_KEY       0x1    /* Program RPMB Authentication Key */
#define RPMB_GET_WRITE_COUNTER 0x2    /* Read RPMB write counter */
#define RPMB_WRITE_DATA        0x3    /* Write data to RPMB partition */
#define RPMB_READ_DATA         0x4    /* Read data from RPMB partition */
#define RPMB_RESULT_READ       0x5    /* Read result request  (Internal) */

static uint8_t read_buf[4096];

#ifdef RPMB_DEBUG

static void print_buf(const char *prefix, const uint8_t *buf, size_t size)
{
    size_t i;

    printf("%s @%p [%zu]", prefix, buf, size);
    for (i = 0; i < size; i++) {
        if (i && i % 32 == 0)
            printf("\n%*s", (int) strlen(prefix), "");
        printf(" %02x", buf[i]);
    }
    printf("\n");
    fflush(stdout);
}

#endif

/* for boot type usage */
int get_boot_type(void)
{
    int fd;
    size_t s;
    char boot_type[4] = {'0'};

    fd = open("/sys/class/BOOT/BOOT/boot/boot_type", O_RDONLY);
    if (fd < 0) {
        ALOGE("fail to open: %s\n", "/sys/class/BOOT/BOOT/boot/boot_type");
        return -1;
    }

    s = read(fd, (void *)&boot_type, sizeof(boot_type) - 1);
    close(fd);

    if (s <= 0) {
        ALOGE("could not read boot type sys file\n");
        return -1;
    }

    boot_type[s] = '\0';

    return atoi((char *)&boot_type);
}

int rpmb_send_ufs(struct storage_msg *msg, const void *r,
        size_t req_len, int rpmb_fd)
{
    int rc;
    struct rpmb_cmd {
        uint32_t flags;
        uint32_t nframes;
        uint8_t *data_ptr;
    } cmd_buf[3], *cmd;
    uint16_t req_type;
    const struct storage_rpmb_send_req *req = r;

    if (req_len < sizeof(*req)) {
        ALOGW("malformed rpmb request: invalid length (%zu < %zu)\n",
              req_len, sizeof(*req));
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    size_t expected_len =
            sizeof(*req) + req->reliable_write_size + req->write_size;
    if (req_len != expected_len) {
        ALOGW("malformed rpmb request: invalid length (%zu != %zu)\n",
              req_len, expected_len);
        msg->result = STORAGE_ERR_NOT_VALID;
        goto err_response;
    }

    memset(&cmd_buf[0], 0, sizeof(cmd_buf));
    uint8_t *write_buf = (uint8_t *) req->payload;
    cmd = &cmd_buf[0];
    if (req->reliable_write_size) {
        if ((req->reliable_write_size % MMC_BLOCK_SIZE) != 0) {
            ALOGW("invalid reliable write size %u\n", req->reliable_write_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        cmd->flags = MMC_WRITE_FLAG_RELW;
        cmd->nframes = req->reliable_write_size / MMC_BLOCK_SIZE;
        cmd->data_ptr = (uint8_t *) write_buf;

#ifdef RPMB_DEBUG
        ALOGI("reliable write flags: 0x%x\n", cmd->flags);
        print_buf("request: ", write_buf, req->reliable_write_size);
#endif
        write_buf += req->reliable_write_size;
        cmd++;
    }

    if (req->write_size) {
        if ((req->write_size % MMC_BLOCK_SIZE) != 0) {
            ALOGW("invalid write size %u\n", req->write_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        cmd->flags = MMC_WRITE_FLAG_W;
        cmd->nframes = req->write_size / MMC_BLOCK_SIZE;
        cmd->data_ptr = (uint8_t *) write_buf;

#ifdef RPMB_DEBUG
        ALOGI("write flags: 0x%x\n", cmd->flags);
        print_buf("request: ", write_buf, req->write_size);
#endif

        req_type = (*(write_buf+510) << 8) + (*(write_buf+511));
        if (req_type == RPMB_READ_DATA) {
            *(write_buf+506) = (req->read_size / MMC_BLOCK_SIZE) & 0xFF00;
            *(write_buf+507) = (req->read_size / MMC_BLOCK_SIZE) & 0xFF;
        }

        write_buf += req->write_size;
        cmd++;
    }

    if (req->read_size) {
        if (req->read_size % MMC_BLOCK_SIZE != 0 ||
            req->read_size > sizeof(read_buf)) {
            ALOGE("%s: invalid read size %u\n", __func__, req->read_size);
            msg->result = STORAGE_ERR_NOT_VALID;
            goto err_response;
        }

        cmd->flags = MMC_WRITE_FLAG_R;
        cmd->nframes = req->read_size / MMC_BLOCK_SIZE;
        cmd->data_ptr = (uint8_t *) read_buf;

#ifdef RPMB_DEBUG
        ALOGI("read flags: 0x%x\n", cmd->flags);
#endif
    }

    rc = ioctl(rpmb_fd, UFS_IOCTL_RPMB, &cmd_buf[0]);
    if (rc < 0) {
        ALOGE("%s: ufs ioctl failed: %d, %s\n", __func__, rc, strerror(errno));
        msg->result = STORAGE_ERR_GENERIC;
        goto err_response;
    }

#ifdef RPMB_DEBUG
    if (req->read_size)
        print_buf("response: ", read_buf, req->read_size);
#endif

    if (msg->flags & STORAGE_MSG_FLAG_POST_COMMIT) {
        /*
         * Nothing todo for post msg commit request as MMC_IOC_MULTI_CMD
         * is fully synchronous in this implementation.
         */
    }

    msg->result = STORAGE_NO_ERROR;
    return ipc_respond(msg, read_buf, req->read_size);

err_response:
    return ipc_respond(msg, NULL, 0);
}



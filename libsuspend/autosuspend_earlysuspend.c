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

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOG_TAG "libsuspend"
#include <cutils/log.h>

#include "autosuspend_ops.h"

#define EARLYSUSPEND_SYS_POWER_STATE "/sys/power/state"
#define EARLYSUSPEND_WAIT_FOR_FB_SLEEP "/sys/power/wait_for_fb_sleep"
#define EARLYSUSPEND_WAIT_FOR_FB_WAKE "/sys/power/wait_for_fb_wake"


static int sPowerStatefd;
static const char *pwr_state_mem = "mem";
static const char *pwr_state_on = "on";
static pthread_t earlysuspend_thread;

int wait_for_fb_wake(void)
{
    int err = 0;
    char buf;
    int fd = open(EARLYSUSPEND_WAIT_FOR_FB_WAKE, O_RDONLY, 0);
    // if the file doesn't exist, the error will be caught in read() below
    do {
        err = read(fd, &buf, 1);
    } while (err < 0 && errno == EINTR);
    ALOGE_IF(err < 0,
            "*** ANDROID_WAIT_FOR_FB_WAKE failed (%s)", strerror(errno));
    close(fd);
    return err < 0 ? err : 0;
}

static int wait_for_fb_sleep(void)
{
    int err = 0;
    char buf;
    int fd = open(EARLYSUSPEND_WAIT_FOR_FB_SLEEP, O_RDONLY, 0);
    // if the file doesn't exist, the error will be caught in read() below
    do {
        err = read(fd, &buf, 1);
    } while (err < 0 && errno == EINTR);
    ALOGE_IF(err < 0,
            "*** ANDROID_WAIT_FOR_FB_SLEEP failed (%s)", strerror(errno));
    close(fd);
    return err < 0 ? err : 0;
}

static void *earlysuspend_thread_func(void *arg)
{
    char buf[80];
    char wakeup_count[20];
    int wakeup_count_len;
    int ret;

    while (1) {
        if (wait_for_fb_sleep()) {
            ALOGE("Failed reading wait_for_fb_sleep, exiting earlysuspend thread\n");
            return NULL;
        }
        if (wait_for_fb_wake()) {
            ALOGE("Failed reading wait_for_fb_wake, exiting earlysuspend thread\n");
            return NULL;
        }
    }
}
static int autosuspend_earlysuspend_enable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_earlysuspend_enable\n");

    ret = write(sPowerStatefd, pwr_state_mem, strlen(pwr_state_mem));
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        goto err;
    }

    ALOGV("autosuspend_earlysuspend_enable done\n");

    return 0;

err:
    return ret;
}

static int autosuspend_earlysuspend_disable(void)
{
    char buf[80];
    int ret;

    ALOGV("autosuspend_earlysuspend_disable\n");

    ret = write(sPowerStatefd, pwr_state_on, strlen(pwr_state_on));
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error writing to %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        goto err;
    }

    ALOGV("autosuspend_earlysuspend_disable done\n");

    return 0;

err:
    return ret;
}

struct autosuspend_ops autosuspend_earlysuspend_ops = {
        .enable = autosuspend_earlysuspend_enable,
        .disable = autosuspend_earlysuspend_disable,
};

void start_earlysuspend_thread(void)
{
    char buf[80];
    int ret;

    ret = access(EARLYSUSPEND_WAIT_FOR_FB_SLEEP, F_OK);
    if (ret < 0) {
        return;
    }

    ret = access(EARLYSUSPEND_WAIT_FOR_FB_WAKE, F_OK);
    if (ret < 0) {
        return;
    }

    ALOGI("Starting early suspend unblocker thread\n");
    ret = pthread_create(&earlysuspend_thread, NULL, earlysuspend_thread_func, NULL);
    if (ret) {
        strerror_r(ret, buf, sizeof(buf));
        ALOGE("Error creating thread: %s\n", buf);
    }
}

struct autosuspend_ops *autosuspend_earlysuspend_init(void)
{
    char buf[80];
    int ret;

    sPowerStatefd = open(EARLYSUSPEND_SYS_POWER_STATE, O_RDWR);

    if (sPowerStatefd < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGW("Error opening %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        return NULL;
    }

    ret = write(sPowerStatefd, "on", 2);
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGW("Error writing 'on' to %s: %s\n", EARLYSUSPEND_SYS_POWER_STATE, buf);
        goto err_write;
    }

    ALOGI("Selected early suspend\n");

    start_earlysuspend_thread();

    return &autosuspend_earlysuspend_ops;

err_write:
    close(sPowerStatefd);
    return NULL;
}

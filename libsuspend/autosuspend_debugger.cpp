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

#define LOG_TAG "libsuspend"
//#define LOG_NDEBUG 0

#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>

#include "autosuspend_ops.h"

#define DEBUGGER_SLEEP_TIME 15000000

static int wakeup_sources_fd = -1;

using android::base::ReadFdToString;
using android::base::Trim;
using android::base::WriteStringToFd;

static pthread_t debugger_thread;
static sem_t debugger_lockout;
static constexpr char debugfs_wakeup_sources[] = "/sys/kernel/debug/wakeup_sources";
static bool autosuspend_debugger_setting_is_init = false;

static void* debugger_thread_func(void* arg __attribute__((unused))) {
    char buf[512];

    while (true) {
        LOG(VERBOSE) << "wait";
        int ret = sem_wait(&debugger_lockout);
        if (ret < 0) {
            PLOG(ERROR) << "error waiting on debugger_lockout semaphore";
            continue;
        }

        LOG(VERBOSE) << "read wakeup_sources";
        FILE * pFile;
        pFile = fopen (debugfs_wakeup_sources , "r");

        while (fgets(buf, sizeof(buf), pFile) != NULL) {
            int active_since_index = 5;
            int current_index = 0;

            int active_count = 0;
            int event_count = 0;
            int wakeup_count = 0;
            int expire_count = 0;
            int active_since = 0;

            char *token = strtok(buf,"\t");
            char *wakeup_source_name = token;

            int i;
            for (i = strlen(wakeup_source_name) - 1; i >= 0 ; i--) {
                if (wakeup_source_name[i] != ' ') {
                    wakeup_source_name[i + 1] = '\0';
                    break;
                }
            }

            while (token != NULL) {
                switch(current_index) {
                    case 1:
                        active_count = atoi(token);
                        break;
                    case 2:
                        event_count = atoi(token);
                        break;
                    case 3:
                        wakeup_count = atoi(token);
                        break;
                    case 4:
                        expire_count = atoi(token);
                        break;
                    case 5:
                        active_since = atoi(token);
                        break;
                    default:
                        break;
                }
                if (current_index == active_since_index && active_since > 0) {
                    LOG(INFO) << "ws name: " << wakeup_source_name <<
                        ", act_since: " << active_since <<
                        ", act_cnt: " << active_count <<
                        ", ev_cnt: " << event_count <<
                        ", wakeup_cnt: " << wakeup_count;
                }
                current_index++;
                token = strtok(NULL, "\t");
            }
        }

        fclose (pFile);

        LOG(VERBOSE) << "release sem";
        ret = sem_post(&debugger_lockout);
        if (ret < 0) {
            PLOG(ERROR) << "error releasing debugger_lockout semaphore";
        }

        usleep(DEBUGGER_SLEEP_TIME);
    }
    return NULL;
}

static int init_wakeup_fd(void) {
    if (wakeup_sources_fd >= 0) {
        return 0;
    }

    int fd = TEMP_FAILURE_RETRY(open(debugfs_wakeup_sources, O_CLOEXEC | O_RDONLY));
    if (fd < 0) {
        PLOG(ERROR) << "error opening " << debugfs_wakeup_sources;
        return -1;
    }

    wakeup_sources_fd = fd;
    LOG(INFO) << "init_wakeup_fd success";
    return 0;
}

static int autosuspend_debugger_setting_init(void) {
    if (autosuspend_debugger_setting_is_init) {
        return 0;
    }

    int ret = init_wakeup_fd();
    if (ret < 0) {
        return -1;
    }

    ret = sem_init(&debugger_lockout, 0, 0);
    if (ret < 0) {
        PLOG(ERROR) << "error creating debugger_lockout semaphore";
        goto err_sem_init;
    }

    ret = pthread_create(&debugger_thread, NULL, debugger_thread_func, NULL);
    if (ret) {
        LOG(ERROR) << "error creating thread: " << strerror(ret);
        goto err_pthread_create;
    }

    LOG(INFO) << "autosuspend_debugger_setting_init success";
    autosuspend_debugger_setting_is_init = true;
    return 0;

err_pthread_create:
    sem_destroy(&debugger_lockout);
err_sem_init:
    close(wakeup_sources_fd);
    return -1;
}

static int autosuspend_debugger_enable(void) {
    LOG(INFO) << "autosuspend_debugger_enable";

    int ret = autosuspend_debugger_setting_init();
    if (ret < 0) {
        LOG(ERROR) << "autosuspend_debugger_setting_init failed";
        return ret;
    }

    ret = sem_post(&debugger_lockout);
    if (ret < 0) {
        PLOG(ERROR) << "error changing debugger_lockout semaphore";
    }

    LOG(INFO) << "autosuspend_debugger_enable done";

    return ret;
}

static int autosuspend_debugger_disable(void) {
    LOG(INFO) << "autosuspend_debugger_disable";

    if (!autosuspend_debugger_setting_is_init) {
        return 0;  // always successful if no thread is running yet
    }

    int ret = sem_wait(&debugger_lockout);

    if (ret < 0) {
        PLOG(ERROR) << "error changing debugger_lockout semaphore";
    }

    LOG(INFO) << "autosuspend_debugger_disable done";

    return ret;
}

struct autosuspend_ops autosuspend_debugger_ops = {
    .enable = autosuspend_debugger_enable,
    .disable = autosuspend_debugger_disable,
};

struct autosuspend_ops* autosuspend_debugger_init(void) {
    return &autosuspend_debugger_ops;
}
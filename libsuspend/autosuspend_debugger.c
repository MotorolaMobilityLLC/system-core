#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "autosuspend_ops.h"

#define LOG_TAG "libsuspend"
#include <cutils/log.h>

#define SYS_KERNEL_WAKEUP_SOURCES "/sys/kernel/debug/wakeup_sources"

static FILE *wakeup_sources_fd = NULL;
static pthread_t debugger_thread;
static sem_t debugger_lockout;

static void *debugger_thread_func(void *arg __attribute__((unused)))
{
    int ret;
    char buf[512];

    while (1) {
        ALOGV("%s: wait\n", __func__);
        ret = sem_wait(&debugger_lockout);
        if (ret < 0) {
            strerror_r(errno, buf, sizeof(buf));
            ALOGE("Error waiting on semaphore: %s\n", buf);
            continue;
        }

        ALOGV("%s: read wakeup_sources\n", __func__);
        fseek(wakeup_sources_fd, 0, SEEK_SET);
        while (fgets(buf, sizeof(buf), wakeup_sources_fd) != NULL) {
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
                    ALOGI("ws name: %s, act_since: %d, act_cnt: %d, ev_cnt: %d, wakeup_cnt: %d\n",
                        wakeup_source_name, active_since, active_count, event_count, wakeup_count);
                }
                current_index++;
                token = strtok(NULL, "\t");
            }
        }

        ALOGV("%s: release sem\n", __func__);
        ret = sem_post(&debugger_lockout);
        if (ret < 0) {
            strerror_r(errno, buf, sizeof(buf));
            ALOGE("Error releasing semaphore: %s\n", buf);
        }

        usleep(15000000); // 15s
    }
    return NULL;
}

static int autosuspend_debugger_enable(void)
{
    char buf[80];
    int ret;

    ALOGI("autosuspend_debugger_enable\n");

    ret = sem_post(&debugger_lockout);

    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error changing semaphore: %s\n", buf);
    }

    ALOGI("autosuspend_debugger_enable done\n");

    return ret;
}

static int autosuspend_debugger_disable(void)
{
    char buf[80];
    int ret;

    ALOGI("autosuspend_debugger_disable\n");

    ret = sem_wait(&debugger_lockout);

    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error changing semaphore: %s\n", buf);
    }

    ALOGI("autosuspend_debugger_disable done\n");

    return ret;
}

struct autosuspend_ops autosuspend_debugger_ops = {
        .enable = autosuspend_debugger_enable,
        .disable = autosuspend_debugger_disable,
};

struct autosuspend_ops *autosuspend_debugger_init(void)
{
    int ret;
    char buf[80];

    wakeup_sources_fd = fopen(SYS_KERNEL_WAKEUP_SOURCES, "r");
    if (wakeup_sources_fd == NULL) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error opening %s: %s\n", SYS_KERNEL_WAKEUP_SOURCES, buf);
        goto err_open_wakeup_sources;
    }
    ret = sem_init(&debugger_lockout, 0, 0);
    if (ret < 0) {
        strerror_r(errno, buf, sizeof(buf));
        ALOGE("Error creating semaphore: %s\n", buf);
        goto err_debugger_sem_init;
    }
    ret = pthread_create(&debugger_thread, NULL, debugger_thread_func, NULL);
    if (ret) {
        strerror_r(ret, buf, sizeof(buf));
        ALOGE("Error creating thread: %s\n", buf);
        goto err_debugger_pthread_create;
    }

    ALOGI("Selected wakeup source debugger\n");
    return &autosuspend_debugger_ops;

err_debugger_pthread_create:
    sem_destroy(&debugger_lockout);
err_debugger_sem_init:
    fclose(wakeup_sources_fd);
err_open_wakeup_sources:
    return NULL;
}

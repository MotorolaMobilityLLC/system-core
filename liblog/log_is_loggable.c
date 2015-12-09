/*
** Copyright 2014, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <android/log.h>

static pthread_mutex_t lock_loggable = PTHREAD_MUTEX_INITIALIZER;

static void lock()
{
    /*
     * If we trigger a signal handler in the middle of locked activity and the
     * signal handler logs a message, we could get into a deadlock state.
     */
    pthread_mutex_lock(&lock_loggable);
}

static void unlock()
{
    pthread_mutex_unlock(&lock_loggable);
}

struct cache {
    const prop_info *pinfo;
    uint32_t serial;
    unsigned char c;
};

#define BOOLEAN_TRUE 0xFF
#define BOOLEAN_FALSE 0xFE

static void refresh_cache(struct cache *cache, const char *key)
{
    uint32_t serial;
    char buf[PROP_VALUE_MAX];

    if (!cache->pinfo) {
        cache->pinfo = __system_property_find(key);
        if (!cache->pinfo) {
            return;
        }
    }
    serial = __system_property_serial(cache->pinfo);
    if (serial == cache->serial) {
        return;
    }
    cache->serial = serial;
    __system_property_read(cache->pinfo, 0, buf);
    switch(buf[0]) {
    case 't': case 'T':
        cache->c = strcasecmp(buf + 1, "rue") ? buf[0] : BOOLEAN_TRUE;
        break;
    case 'f': case 'F':
        cache->c = strcasecmp(buf + 1, "alse") ? buf[0] : BOOLEAN_FALSE;
        break;
    default:
        cache->c = buf[0];
    }
}

static int __android_log_level(const char *tag, int default_prio)
{
    /* sizeof() is used on this array below */
    static const char log_namespace[] = "persist.log.tag.";
    static const size_t base_offset = 8; /* skip "persist." */
    /* calculate the size of our key temporary buffer */
    const size_t taglen = (tag && *tag) ? strlen(tag) : 0;
    /* sizeof(log_namespace) = strlen(log_namespace) + 1 */
    char key[sizeof(log_namespace) + taglen];
    char *kp;
    size_t i;
    char c = 0;
    /*
     * Single layer cache of four properties. Priorities are:
     *    log.tag.<tag>
     *    persist.log.tag.<tag>
     *    log.tag
     *    persist.log.tag
     * Where the missing tag matches all tags and becomes the
     * system global default. We do not support ro.log.tag* .
     */
    static char *last_tag;
    static uint32_t global_serial;
    uint32_t current_global_serial;
    static struct cache tag_cache[2] = {
        { NULL, -1, 0 },
        { NULL, -1, 0 }
    };
    static struct cache global_cache[2] = {
        { NULL, -1, 0 },
        { NULL, -1, 0 }
    };

    strcpy(key, log_namespace);

    lock();

    current_global_serial = __system_property_area_serial();

    if (taglen) {
        uint32_t current_local_serial = current_global_serial;

        if (!last_tag || (last_tag[0] != tag[0]) || strcmp(last_tag + 1, tag + 1)) {
            /* invalidate log.tag.<tag> cache */
            for(i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
                tag_cache[i].pinfo = NULL;
                tag_cache[i].serial = -1;
                tag_cache[i].c = '\0';
            }
            free(last_tag);
            last_tag = NULL;
            current_global_serial = -1;
        }
        if (!last_tag) {
            last_tag = strdup(tag);
        }
        strcpy(key + sizeof(log_namespace) - 1, tag);

        kp = key;
        for(i = 0; i < (sizeof(tag_cache) / sizeof(tag_cache[0])); ++i) {
            if (current_local_serial != global_serial) {
                refresh_cache(&tag_cache[i], kp);
            }

            if (tag_cache[i].c) {
                c = tag_cache[i].c;
                break;
            }

            kp = key + base_offset;
        }
    }

    switch (toupper(c)) { /* if invalid, resort to global */
    case 'V':
    case 'D':
    case 'I':
    case 'W':
    case 'E':
    case 'F': /* Not officially supported */
    case 'A':
    case 'S':
    case BOOLEAN_FALSE: /* Not officially supported */
        break;
    default:
        /* clear '.' after log.tag */
        key[sizeof(log_namespace) - 2] = '\0';

        kp = key;
        for(i = 0; i < (sizeof(global_cache) / sizeof(global_cache[0])); ++i) {
            if (current_global_serial != global_serial) {
                refresh_cache(&global_cache[i], kp);
            }

            if (global_cache[i].c) {
                c = global_cache[i].c;
                break;
            }

            kp = key + base_offset;
        }
        break;
    }

    global_serial = current_global_serial;

    unlock();

    switch (toupper(c)) {
    case 'V': return ANDROID_LOG_VERBOSE;
    case 'D': return ANDROID_LOG_DEBUG;
    case 'I': return ANDROID_LOG_INFO;
    case 'W': return ANDROID_LOG_WARN;
    case 'E': return ANDROID_LOG_ERROR;
    case 'F': /* FALLTHRU */ /* Not officially supported */
    case 'A': return ANDROID_LOG_FATAL;
    case BOOLEAN_FALSE: /* FALLTHRU */ /* Not Officially supported */
    case 'S': return -1; /* ANDROID_LOG_SUPPRESS */
    }
    return default_prio;
}

int __android_log_is_loggable(int prio, const char *tag, int default_prio)
{
    int logLevel = __android_log_level(tag, default_prio);
    return logLevel >= 0 && prio >= logLevel;
}

/*
 * Timestamp state generally remains constant, since a change is
 * rare, we can accept a trylock failure gracefully. Use a separate
 * lock from is_loggable to keep contention down b/25563384.
 */
static pthread_mutex_t lock_clockid = PTHREAD_MUTEX_INITIALIZER;

clockid_t android_log_clockid()
{
    static struct cache r_time_cache = { NULL, -1, 0 };
    static struct cache p_time_cache = { NULL, -1, 0 };
    char c;

    if (pthread_mutex_trylock(&lock_clockid)) {
        /* We are willing to accept some race in this context */
        if (!(c = p_time_cache.c)) {
            c = r_time_cache.c;
        }
    } else {
        static uint32_t serial;
        uint32_t current_serial = __system_property_area_serial();
        if (current_serial != serial) {
            refresh_cache(&r_time_cache, "ro.logd.timestamp");
            refresh_cache(&p_time_cache, "persist.logd.timestamp");
            serial = current_serial;
        }
        if (!(c = p_time_cache.c)) {
            c = r_time_cache.c;
        }

        pthread_mutex_unlock(&lock_clockid);
    }

    return (tolower(c) == 'm') ? CLOCK_MONOTONIC : CLOCK_REALTIME;
}

/*
 * security state generally remains constant, since a change is
 * rare, we can accept a trylock failure gracefully.
 */
static pthread_mutex_t lock_security = PTHREAD_MUTEX_INITIALIZER;

int __android_log_security()
{
    static struct cache r_do_cache = { NULL, -1, BOOLEAN_FALSE };
    static struct cache p_security_cache = { NULL, -1, BOOLEAN_FALSE };
    int retval;

    if (pthread_mutex_trylock(&lock_security)) {
        /* We are willing to accept some race in this context */
        retval = (r_do_cache.c != BOOLEAN_FALSE) && r_do_cache.c &&
                 (p_security_cache.c == BOOLEAN_TRUE);
    } else {
        static uint32_t serial;
        uint32_t current_serial = __system_property_area_serial();
        if (current_serial != serial) {
            refresh_cache(&r_do_cache, "ro.device_owner");
            refresh_cache(&p_security_cache, "persist.logd.security");
            serial = current_serial;
        }
        retval = (r_do_cache.c != BOOLEAN_FALSE) && r_do_cache.c &&
                 (p_security_cache.c == BOOLEAN_TRUE);

        pthread_mutex_unlock(&lock_security);
    }

    return retval;
}

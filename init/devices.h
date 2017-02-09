/*
 * Copyright (C) 2007 The Android Open Source Project
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

#ifndef _INIT_DEVICES_H
#define _INIT_DEVICES_H

#include <functional>
#include <sys/stat.h>

enum coldboot_action_t {
    // coldboot continues without creating the device for the uevent
    COLDBOOT_CONTINUE = 0,
    // coldboot continues after creating the device for the uevent
    COLDBOOT_CREATE,
    // coldboot stops after creating the device for uevent but doesn't
    // create the COLDBOOT_DONE file
    COLDBOOT_STOP,
    // same as COLDBOOT_STOP, but creates the COLDBOOT_DONE file
    COLDBOOT_FINISH
};

struct uevent {
    const char* action;
    const char* path;
    const char* subsystem;
    const char* firmware;
    const char* partition_name;
    const char* device_name;
    int partition_num;
    int major;
    int minor;
};

typedef std::function<coldboot_action_t(struct uevent* uevent)> coldboot_callback;
extern coldboot_action_t handle_device_fd(coldboot_callback fn = nullptr);
extern void device_init(const char* path = nullptr, coldboot_callback fn = nullptr);

enum early_device_type { EARLY_BLOCK_DEV, EARLY_CHAR_DEV };

extern int early_device_socket_open();
extern void early_device_socket_close();
extern void early_create_dev(const std::string& syspath, early_device_type dev_type);

extern int add_dev_perms(const char *name, const char *attr,
                         mode_t perm, unsigned int uid,
                         unsigned int gid, unsigned short prefix,
                         unsigned short wildcard);
int get_device_fd();

#endif	/* _INIT_DEVICES_H */

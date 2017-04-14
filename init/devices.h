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

#include <sys/stat.h>

#include <functional>
#include <string>
#include <vector>

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
    std::string action;
    std::string path;
    std::string subsystem;
    std::string firmware;
    std::string partition_name;
    std::string device_name;
    int partition_num;
    int major;
    int minor;
};

typedef std::function<coldboot_action_t(struct uevent* uevent)> coldboot_callback;
extern coldboot_action_t handle_device_fd(coldboot_callback fn = nullptr);
extern void device_init(const char* path = nullptr, coldboot_callback fn = nullptr);
extern void device_close();

extern int add_dev_perms(const char *name, const char *attr,
                         mode_t perm, unsigned int uid,
                         unsigned int gid, unsigned short prefix,
                         unsigned short wildcard);
int get_device_fd();

// Exposed for testing
void add_platform_device(const char* path);
void remove_platform_device(const char* path);
std::vector<std::string> get_character_device_symlinks(uevent* uevent);
std::vector<std::string> get_block_device_symlinks(uevent* uevent);
void sanitize_partition_name(std::string* string);

#endif /* _INIT_DEVICES_H */

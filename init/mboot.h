/*
 * Copyright (C) 2019 UNISOC Communications Inc.
 */

#ifndef _MBOOT_H
#define _MBOOT_H
#include <dirent.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include <functional>
#include <ostream>
#include <string>

namespace android {
namespace mboot {
    bool IsMboot(void);
    void do_overlayfs(void);
    void list_dir(const char *d);
    void console(void);
    void spath(void);
    void mdb(const char *cmd="init", const char *env_name=nullptr, const char *env_value=nullptr);
} // mboot
} // android
#endif

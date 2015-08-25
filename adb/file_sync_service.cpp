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

#define TRACE_TAG TRACE_SYNC

#include "sysdeps.h"
#include "file_sync_service.h"

#include <dirent.h>
#include <errno.h>
#include <selinux/android.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include "adb.h"
#include "adb_io.h"
#include "private/android_filesystem_config.h"

#include <base/stringprintf.h>
#include <base/strings.h>

static bool should_use_fs_config(const std::string& path) {
    // TODO: use fs_config to configure permissions on /data.
    return android::base::StartsWith(path, "/system/") ||
           android::base::StartsWith(path, "/vendor/") ||
           android::base::StartsWith(path, "/oem/");
}

static bool secure_mkdirs(const std::string& path) {
    uid_t uid = -1;
    gid_t gid = -1;
    unsigned int mode = 0775;
    uint64_t cap = 0;

    if (path[0] != '/') return false;

    std::vector<std::string> path_components = android::base::Split(path, "/");
    path_components.pop_back(); // For "/system/bin/sh", only create "/system/bin".

    std::string partial_path;
    for (auto& path_component : path_components) {
        if (partial_path.back() != OS_PATH_SEPARATOR) partial_path += OS_PATH_SEPARATOR;
        partial_path += path_component;

        if (should_use_fs_config(partial_path)) {
            fs_config(partial_path.c_str(), 1, nullptr, &uid, &gid, &mode, &cap);
        }
        if (adb_mkdir(partial_path.c_str(), mode) == -1) {
            if (errno != EEXIST) {
                return false;
            }
        } else {
            if (chown(partial_path.c_str(), uid, gid) == -1) {
                return false;
            }
            selinux_android_restorecon(partial_path.c_str(), 0);
        }
    }
    return true;
}

static bool do_stat(int s, const char* path) {
    syncmsg msg;
    msg.stat.id = ID_STAT;

    struct stat st;
    memset(&st, 0, sizeof(st));
    // TODO: add a way to report that the stat failed!
    lstat(path, &st);
    msg.stat.mode = st.st_mode;
    msg.stat.size = st.st_size;
    msg.stat.time = st.st_mtime;

    return WriteFdExactly(s, &msg.stat, sizeof(msg.stat));
}

static bool do_list(int s, const char* path) {
    dirent* de;

    syncmsg msg;
    msg.dent.id = ID_DENT;

    std::unique_ptr<DIR, int(*)(DIR*)> d(opendir(path), closedir);
    if (!d) goto done;

    while ((de = readdir(d.get()))) {
        std::string filename(android::base::StringPrintf("%s/%s", path, de->d_name));

        struct stat st;
        if (lstat(filename.c_str(), &st) == 0) {
            size_t d_name_length = strlen(de->d_name);
            msg.dent.mode = st.st_mode;
            msg.dent.size = st.st_size;
            msg.dent.time = st.st_mtime;
            msg.dent.namelen = d_name_length;

            if (!WriteFdExactly(s, &msg.dent, sizeof(msg.dent)) ||
                    !WriteFdExactly(s, de->d_name, d_name_length)) {
                return false;
            }
        }
    }

done:
    msg.dent.id = ID_DONE;
    msg.dent.mode = 0;
    msg.dent.size = 0;
    msg.dent.time = 0;
    msg.dent.namelen = 0;
    return WriteFdExactly(s, &msg.dent, sizeof(msg.dent));
}

static bool SendSyncFail(int fd, const std::string& reason) {
    D("sync: failure: %s\n", reason.c_str());

    syncmsg msg;
    msg.data.id = ID_FAIL;
    msg.data.size = reason.size();
    return WriteFdExactly(fd, &msg.data, sizeof(msg.data)) && WriteFdExactly(fd, reason);
}

static bool SendSyncFailErrno(int fd, const std::string& reason) {
    return SendSyncFail(fd, android::base::StringPrintf("%s: %s", reason.c_str(), strerror(errno)));
}

static bool handle_send_file(int s, const char* path, uid_t uid,
                             gid_t gid, mode_t mode, std::vector<char>& buffer, bool do_unlink) {
    syncmsg msg;
    unsigned int timestamp = 0;

    int fd = adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    if (fd < 0 && errno == ENOENT) {
        if (!secure_mkdirs(path)) {
            SendSyncFailErrno(s, "secure_mkdirs failed");
            goto fail;
        }
        fd = adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode);
    }
    if (fd < 0 && errno == EEXIST) {
        fd = adb_open_mode(path, O_WRONLY | O_CLOEXEC, mode);
    }
    if (fd < 0) {
        SendSyncFailErrno(s, "couldn't create file");
        goto fail;
    } else {
        if (fchown(fd, uid, gid) == -1) {
            SendSyncFailErrno(s, "fchown failed");
            goto fail;
        }

         // fchown clears the setuid bit - restore it if present.
         // Ignore the result of calling fchmod. It's not supported
         // by all filesystems. b/12441485
        fchmod(fd, mode);
    }

    while (true) {
        unsigned int len;

        if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) goto fail;

        if (msg.data.id != ID_DATA) {
            if (msg.data.id == ID_DONE) {
                timestamp = msg.data.size;
                break;
            }
            SendSyncFail(s, "invalid data message");
            goto fail;
        }
        len = msg.data.size;
        if (len > buffer.size()) { // TODO: resize buffer?
            SendSyncFail(s, "oversize data message");
            goto fail;
        }

        if (!ReadFdExactly(s, &buffer[0], len)) goto fail;

        if (!WriteFdExactly(fd, &buffer[0], len)) {
            SendSyncFailErrno(s, "write failed");
            goto fail;
        }
    }

    adb_close(fd);

    selinux_android_restorecon(path, 0);

    utimbuf u;
    u.actime = timestamp;
    u.modtime = timestamp;
    utime(path, &u);

    msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    return WriteFdExactly(s, &msg.status, sizeof(msg.status));

fail:
    if (fd >= 0) adb_close(fd);
    if (do_unlink) adb_unlink(path);
    return false;
}

#if defined(_WIN32)
extern bool handle_send_link(int s, const std::string& path, std::vector<char>& buffer) __attribute__((error("no symlinks on Windows")));
#else
static bool handle_send_link(int s, const std::string& path, std::vector<char>& buffer) {
    syncmsg msg;
    unsigned int len;
    int ret;

    if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) return false;

    if (msg.data.id != ID_DATA) {
        SendSyncFail(s, "invalid data message: expected ID_DATA");
        return false;
    }

    len = msg.data.size;
    if (len > buffer.size()) { // TODO: resize buffer?
        SendSyncFail(s, "oversize data message");
        return false;
    }
    if (!ReadFdExactly(s, &buffer[0], len)) return false;

    ret = symlink(&buffer[0], path.c_str());
    if (ret && errno == ENOENT) {
        if (!secure_mkdirs(path)) {
            SendSyncFailErrno(s, "secure_mkdirs failed");
            return false;
        }
        ret = symlink(&buffer[0], path.c_str());
    }
    if (ret) {
        SendSyncFailErrno(s, "symlink failed");
        return false;
    }

    if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) return false;

    if (msg.data.id == ID_DONE) {
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if (!WriteFdExactly(s, &msg.status, sizeof(msg.status))) return false;
    } else {
        SendFail(s, "invalid data message: expected ID_DONE");
        return false;
    }

    return true;
}
#endif

static bool do_send(int s, const std::string& spec, std::vector<char>& buffer) {
    // 'spec' is of the form "/some/path,0755". Break it up.
    size_t comma = spec.find_last_of(',');
    if (comma == std::string::npos) {
        SendFail(s, "missing , in ID_SEND");
        return false;
    }

    std::string path = spec.substr(0, comma);

    errno = 0;
    mode_t mode = strtoul(spec.substr(comma + 1).c_str(), nullptr, 0);
    if (errno != 0) {
        SendFail(s, "bad mode");
        return false;
    }

    // Don't delete files before copying if they are not "regular" or symlinks.
    struct stat st;
    bool do_unlink = (lstat(path.c_str(), &st) == -1) || S_ISREG(st.st_mode) || S_ISLNK(st.st_mode);
    if (do_unlink) {
        adb_unlink(path.c_str());
    }

    if (S_ISLNK(mode)) {
        return handle_send_link(s, path.c_str(), buffer);
    }

    // Copy user permission bits to "group" and "other" permissions.
    mode &= 0777;
    mode |= ((mode >> 3) & 0070);
    mode |= ((mode >> 3) & 0007);

    uid_t uid = -1;
    gid_t gid = -1;
    uint64_t cap = 0;
    if (should_use_fs_config(path)) {
        unsigned int broken_api_hack = mode;
        fs_config(path.c_str(), 0, nullptr, &uid, &gid, &broken_api_hack, &cap);
        mode = broken_api_hack;
    }
    return handle_send_file(s, path.c_str(), uid, gid, mode, buffer, do_unlink);
}

static bool do_recv(int s, const char* path, std::vector<char>& buffer) {
    int fd = adb_open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        SendSyncFailErrno(s, "open failed");
        return false;
    }

    syncmsg msg;
    msg.data.id = ID_DATA;
    while (true) {
        int r = adb_read(fd, &buffer[0], buffer.size());
        if (r <= 0) {
            if (r == 0) break;
            if (errno == EINTR) continue;
            SendSyncFailErrno(s, "read failed");
            adb_close(fd);
            return false;
        }
        msg.data.size = r;
        if (!WriteFdExactly(s, &msg.data, sizeof(msg.data)) || !WriteFdExactly(s, &buffer[0], r)) {
            adb_close(fd);
            return false;
        }
    }

    adb_close(fd);

    msg.data.id = ID_DONE;
    msg.data.size = 0;
    return WriteFdExactly(s, &msg.data, sizeof(msg.data));
}

static bool handle_sync_command(int fd, std::vector<char>& buffer) {
    D("sync: waiting for request\n");

    SyncRequest request;
    if (!ReadFdExactly(fd, &request, sizeof(request))) {
        SendSyncFail(fd, "command read failure");
        return false;
    }
    size_t path_length = request.path_length;
    if (path_length > 1024) {
        SendSyncFail(fd, "path too long");
        return false;
    }
    char name[1025];
    if (!ReadFdExactly(fd, name, path_length)) {
        SendSyncFail(fd, "filename read failure");
        return false;
    }
    name[path_length] = 0;

    const char* id = reinterpret_cast<const char*>(&request.id);
    D("sync: '%.4s' '%s'\n", id, name);

    switch (request.id) {
      case ID_STAT:
        if (!do_stat(fd, name)) return false;
        break;
      case ID_LIST:
        if (!do_list(fd, name)) return false;
        break;
      case ID_SEND:
        if (!do_send(fd, name, buffer)) return false;
        break;
      case ID_RECV:
        if (!do_recv(fd, name, buffer)) return false;
        break;
      case ID_QUIT:
        return false;
      default:
        SendSyncFail(fd, android::base::StringPrintf("unknown command '%.4s' (%08x)",
                                                     id, request.id));
        return false;
    }

    return true;
}

void file_sync_service(int fd, void* cookie) {
    std::vector<char> buffer(SYNC_DATA_MAX);

    while (handle_sync_command(fd, buffer)) {
    }

    D("sync: done\n");
    adb_close(fd);
}

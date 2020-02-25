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

#define TRACE_TAG SYNC

#include "daemon/file_sync_service.h"

#include "sysdeps.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#if defined(__ANDROID__)
#include <selinux/android.h>
#include <sys/xattr.h>
#endif

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "adb_utils.h"
#include "file_sync_protocol.h"
#include "security_log_tags.h"
#include "sysdeps/errno.h"

using android::base::Dirname;
using android::base::StringPrintf;

static bool should_use_fs_config(const std::string& path) {
#if defined(__ANDROID__)
    // TODO: use fs_config to configure permissions on /data too.
    return !android::base::StartsWith(path, "/data/");
#else
    UNUSED(path);
    return false;
#endif
}

static bool update_capabilities(const char* path, uint64_t capabilities) {
#if defined(__ANDROID__)
    if (capabilities == 0) {
        // Ensure we clean up in case the capabilities weren't 0 in the past.
        removexattr(path, XATTR_NAME_CAPS);
        return true;
    }

    vfs_cap_data cap_data = {};
    cap_data.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE;
    cap_data.data[0].permitted = (capabilities & 0xffffffff);
    cap_data.data[0].inheritable = 0;
    cap_data.data[1].permitted = (capabilities >> 32);
    cap_data.data[1].inheritable = 0;
    return setxattr(path, XATTR_NAME_CAPS, &cap_data, sizeof(cap_data), 0) != -1;
#else
    UNUSED(path, capabilities);
    return true;
#endif
}

static bool secure_mkdirs(const std::string& path) {
    if (path[0] != '/') return false;

    std::vector<std::string> path_components = android::base::Split(path, "/");
    std::string partial_path;
    for (const auto& path_component : path_components) {
        uid_t uid = -1;
        gid_t gid = -1;
        unsigned int mode = 0775;
        uint64_t capabilities = 0;

        if (path_component.empty()) {
            continue;
        }

        if (partial_path.empty() || partial_path.back() != OS_PATH_SEPARATOR) {
            partial_path += OS_PATH_SEPARATOR;
        }
        partial_path += path_component;

        if (should_use_fs_config(partial_path)) {
            fs_config(partial_path.c_str(), 1, nullptr, &uid, &gid, &mode, &capabilities);
        }
        if (adb_mkdir(partial_path.c_str(), mode) == -1) {
            if (errno != EEXIST) {
                return false;
            }
        } else {
            if (chown(partial_path.c_str(), uid, gid) == -1) return false;

#if defined(__ANDROID__)
            // Not all filesystems support setting SELinux labels. http://b/23530370.
            selinux_android_restorecon(partial_path.c_str(), 0);
#endif

            if (!update_capabilities(partial_path.c_str(), capabilities)) return false;
        }
    }
    return true;
}

static bool do_lstat_v1(int s, const char* path) {
    syncmsg msg = {};
    msg.stat_v1.id = ID_LSTAT_V1;

    struct stat st = {};
    lstat(path, &st);
    msg.stat_v1.mode = st.st_mode;
    msg.stat_v1.size = st.st_size;
    msg.stat_v1.mtime = st.st_mtime;
    return WriteFdExactly(s, &msg.stat_v1, sizeof(msg.stat_v1));
}

static bool do_stat_v2(int s, uint32_t id, const char* path) {
    syncmsg msg = {};
    msg.stat_v2.id = id;

    decltype(&stat) stat_fn;
    if (id == ID_STAT_V2) {
        stat_fn = stat;
    } else {
        stat_fn = lstat;
    }

    struct stat st = {};
    int rc = stat_fn(path, &st);
    if (rc == -1) {
        msg.stat_v2.error = errno_to_wire(errno);
    } else {
        msg.stat_v2.dev = st.st_dev;
        msg.stat_v2.ino = st.st_ino;
        msg.stat_v2.mode = st.st_mode;
        msg.stat_v2.nlink = st.st_nlink;
        msg.stat_v2.uid = st.st_uid;
        msg.stat_v2.gid = st.st_gid;
        msg.stat_v2.size = st.st_size;
        msg.stat_v2.atime = st.st_atime;
        msg.stat_v2.mtime = st.st_mtime;
        msg.stat_v2.ctime = st.st_ctime;
    }

    return WriteFdExactly(s, &msg.stat_v2, sizeof(msg.stat_v2));
}

template <bool v2>
static bool do_list(int s, const char* path) {
    dirent* de;

    using MessageType =
            std::conditional_t<v2, decltype(syncmsg::dent_v2), decltype(syncmsg::dent_v1)>;
    MessageType msg;
    uint32_t msg_id;
    if constexpr (v2) {
        msg_id = ID_DENT_V2;
    } else {
        msg_id = ID_DENT_V1;
    }

    std::unique_ptr<DIR, int(*)(DIR*)> d(opendir(path), closedir);
    if (!d) goto done;

    while ((de = readdir(d.get()))) {
        memset(&msg, 0, sizeof(msg));
        msg.id = msg_id;

        std::string filename(StringPrintf("%s/%s", path, de->d_name));

        struct stat st;
        if (lstat(filename.c_str(), &st) == 0) {
            msg.mode = st.st_mode;
            msg.size = st.st_size;
            msg.mtime = st.st_mtime;

            if constexpr (v2) {
                msg.dev = st.st_dev;
                msg.ino = st.st_ino;
                msg.nlink = st.st_nlink;
                msg.uid = st.st_uid;
                msg.gid = st.st_gid;
                msg.atime = st.st_atime;
                msg.ctime = st.st_ctime;
            }
        } else {
            if constexpr (v2) {
                msg.error = errno;
            } else {
                continue;
            }
        }

        size_t d_name_length = strlen(de->d_name);
        msg.namelen = d_name_length;

        if (!WriteFdExactly(s, &msg, sizeof(msg)) ||
            !WriteFdExactly(s, de->d_name, d_name_length)) {
            return false;
        }
    }

done:
    memset(&msg, 0, sizeof(msg));
    msg.id = ID_DONE;
    return WriteFdExactly(s, &msg, sizeof(msg));
}

static bool do_list_v1(int s, const char* path) {
    return do_list<false>(s, path);
}

static bool do_list_v2(int s, const char* path) {
    return do_list<true>(s, path);
}

// Make sure that SendFail from adb_io.cpp isn't accidentally used in this file.
#pragma GCC poison SendFail

static bool SendSyncFail(int fd, const std::string& reason) {
    D("sync: failure: %s", reason.c_str());

    syncmsg msg;
    msg.data.id = ID_FAIL;
    msg.data.size = reason.size();
    return WriteFdExactly(fd, &msg.data, sizeof(msg.data)) && WriteFdExactly(fd, reason);
}

static bool SendSyncFailErrno(int fd, const std::string& reason) {
    return SendSyncFail(fd, StringPrintf("%s: %s", reason.c_str(), strerror(errno)));
}

static bool handle_send_file(int s, const char* path, uint32_t* timestamp, uid_t uid, gid_t gid,
                             uint64_t capabilities, mode_t mode, std::vector<char>& buffer,
                             bool do_unlink) {
    int rc;
    syncmsg msg;

    __android_log_security_bswrite(SEC_TAG_ADB_SEND_FILE, path);

    unique_fd fd(adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode));

    if (fd < 0 && errno == ENOENT) {
        if (!secure_mkdirs(Dirname(path))) {
            SendSyncFailErrno(s, "secure_mkdirs failed");
            goto fail;
        }
        fd.reset(adb_open_mode(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode));
    }
    if (fd < 0 && errno == EEXIST) {
        fd.reset(adb_open_mode(path, O_WRONLY | O_CLOEXEC, mode));
    }
    if (fd < 0) {
        SendSyncFailErrno(s, "couldn't create file");
        goto fail;
    } else {
        if (fchown(fd.get(), uid, gid) == -1) {
            SendSyncFailErrno(s, "fchown failed");
            goto fail;
        }

#if defined(__ANDROID__)
        // Not all filesystems support setting SELinux labels. http://b/23530370.
        selinux_android_restorecon(path, 0);
#endif

        // fchown clears the setuid bit - restore it if present.
        // Ignore the result of calling fchmod. It's not supported
        // by all filesystems, so we don't check for success. b/12441485
        fchmod(fd.get(), mode);
    }

    rc = posix_fadvise(fd.get(), 0, 0,
                       POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE | POSIX_FADV_WILLNEED);
    if (rc != 0) {
        D("[ Failed to fadvise: %s ]", strerror(rc));
    }

    while (true) {
        if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) goto fail;

        if (msg.data.id != ID_DATA) {
            if (msg.data.id == ID_DONE) {
                *timestamp = msg.data.size;
                break;
            }
            SendSyncFail(s, "invalid data message");
            goto abort;
        }

        if (msg.data.size > buffer.size()) {  // TODO: resize buffer?
            SendSyncFail(s, "oversize data message");
            goto abort;
        }

        if (!ReadFdExactly(s, &buffer[0], msg.data.size)) goto abort;

        if (!WriteFdExactly(fd.get(), &buffer[0], msg.data.size)) {
            SendSyncFailErrno(s, "write failed");
            goto fail;
        }
    }

    if (!update_capabilities(path, capabilities)) {
        SendSyncFailErrno(s, "update_capabilities failed");
        goto fail;
    }

    msg.status.id = ID_OKAY;
    msg.status.msglen = 0;
    return WriteFdExactly(s, &msg.status, sizeof(msg.status));

fail:
    // If there's a problem on the device, we'll send an ID_FAIL message and
    // close the socket. Unfortunately the kernel will sometimes throw that
    // data away if the other end keeps writing without reading (which is
    // the case with old versions of adb). To maintain compatibility, keep
    // reading and throwing away ID_DATA packets until the other side notices
    // that we've reported an error.
    while (true) {
        if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) break;

        if (msg.data.id == ID_DONE) {
            break;
        } else if (msg.data.id != ID_DATA) {
            char id[5];
            memcpy(id, &msg.data.id, sizeof(msg.data.id));
            id[4] = '\0';
            D("handle_send_fail received unexpected id '%s' during failure", id);
            break;
        }

        if (msg.data.size > buffer.size()) {
            D("handle_send_fail received oversized packet of length '%u' during failure",
              msg.data.size);
            break;
        }

        if (!ReadFdExactly(s, &buffer[0], msg.data.size)) break;
    }

abort:
    if (do_unlink) adb_unlink(path);
    return false;
}

#if defined(_WIN32)
extern bool handle_send_link(int s, const std::string& path,
                             uint32_t* timestamp, std::vector<char>& buffer)
        __attribute__((error("no symlinks on Windows")));
#else
static bool handle_send_link(int s, const std::string& path, uint32_t* timestamp,
                             std::vector<char>& buffer) {
    syncmsg msg;

    if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) return false;

    if (msg.data.id != ID_DATA) {
        SendSyncFail(s, "invalid data message: expected ID_DATA");
        return false;
    }

    unsigned int len = msg.data.size;
    if (len > buffer.size()) { // TODO: resize buffer?
        SendSyncFail(s, "oversize data message");
        return false;
    }
    if (!ReadFdExactly(s, &buffer[0], len)) return false;

    std::string buf_link;
    if (!android::base::Readlink(path, &buf_link) || (buf_link != &buffer[0])) {
        adb_unlink(path.c_str());
        auto ret = symlink(&buffer[0], path.c_str());
        if (ret && errno == ENOENT) {
            if (!secure_mkdirs(Dirname(path))) {
                SendSyncFailErrno(s, "secure_mkdirs failed");
                return false;
            }
            ret = symlink(&buffer[0], path.c_str());
        }
        if (ret) {
            SendSyncFailErrno(s, "symlink failed");
            return false;
        }
    }

    if (!ReadFdExactly(s, &msg.data, sizeof(msg.data))) return false;

    if (msg.data.id == ID_DONE) {
        *timestamp = msg.data.size;
        msg.status.id = ID_OKAY;
        msg.status.msglen = 0;
        if (!WriteFdExactly(s, &msg.status, sizeof(msg.status))) return false;
    } else {
        SendSyncFail(s, "invalid data message: expected ID_DONE");
        return false;
    }

    return true;
}
#endif

static bool do_send(int s, const std::string& spec, std::vector<char>& buffer) {
    // 'spec' is of the form "/some/path,0755". Break it up.
    size_t comma = spec.find_last_of(',');
    if (comma == std::string::npos) {
        SendSyncFail(s, "missing , in ID_SEND");
        return false;
    }

    std::string path = spec.substr(0, comma);

    errno = 0;
    mode_t mode = strtoul(spec.substr(comma + 1).c_str(), nullptr, 0);
    if (errno != 0) {
        SendSyncFail(s, "bad mode");
        return false;
    }

    // Don't delete files before copying if they are not "regular" or symlinks.
    struct stat st;
    bool do_unlink = (lstat(path.c_str(), &st) == -1) || S_ISREG(st.st_mode) ||
                     (S_ISLNK(st.st_mode) && !S_ISLNK(mode));
    if (do_unlink) {
        adb_unlink(path.c_str());
    }

    bool result;
    uint32_t timestamp;
    if (S_ISLNK(mode)) {
        result = handle_send_link(s, path, &timestamp, buffer);
    } else {
        // Copy user permission bits to "group" and "other" permissions.
        mode &= 0777;
        mode |= ((mode >> 3) & 0070);
        mode |= ((mode >> 3) & 0007);

        uid_t uid = -1;
        gid_t gid = -1;
        uint64_t capabilities = 0;
        if (should_use_fs_config(path)) {
            unsigned int broken_api_hack = mode;
            fs_config(path.c_str(), 0, nullptr, &uid, &gid, &broken_api_hack, &capabilities);
            mode = broken_api_hack;
        }

        result = handle_send_file(s, path.c_str(), &timestamp, uid, gid, capabilities, mode, buffer,
                                  do_unlink);
    }

    if (!result) {
      return false;
    }

    struct timeval tv[2];
    tv[0].tv_sec = timestamp;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = timestamp;
    tv[1].tv_usec = 0;
    lutimes(path.c_str(), tv);
    return true;
}

static bool do_recv(int s, const char* path, std::vector<char>& buffer) {
    __android_log_security_bswrite(SEC_TAG_ADB_RECV_FILE, path);

    unique_fd fd(adb_open(path, O_RDONLY | O_CLOEXEC));
    if (fd < 0) {
        SendSyncFailErrno(s, "open failed");
        return false;
    }

    int rc = posix_fadvise(fd.get(), 0, 0, POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE);
    if (rc != 0) {
        D("[ Failed to fadvise: %s ]", strerror(rc));
    }

    syncmsg msg;
    msg.data.id = ID_DATA;
    while (true) {
        int r = adb_read(fd.get(), &buffer[0], buffer.size() - sizeof(msg.data));
        if (r <= 0) {
            if (r == 0) break;
            SendSyncFailErrno(s, "read failed");
            return false;
        }
        msg.data.size = r;
        if (!WriteFdExactly(s, &msg.data, sizeof(msg.data)) || !WriteFdExactly(s, &buffer[0], r)) {
            return false;
        }
    }

    msg.data.id = ID_DONE;
    msg.data.size = 0;
    return WriteFdExactly(s, &msg.data, sizeof(msg.data));
}

static const char* sync_id_to_name(uint32_t id) {
  switch (id) {
    case ID_LSTAT_V1:
      return "lstat_v1";
    case ID_LSTAT_V2:
      return "lstat_v2";
    case ID_STAT_V2:
      return "stat_v2";
    case ID_LIST_V1:
      return "list_v1";
    case ID_LIST_V2:
      return "list_v2";
    case ID_SEND:
      return "send";
    case ID_RECV:
      return "recv";
    case ID_QUIT:
        return "quit";
    default:
        return "???";
  }
}

static bool handle_sync_command(int fd, std::vector<char>& buffer) {
    D("sync: waiting for request");

    ATRACE_CALL();
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

    std::string id_name = sync_id_to_name(request.id);
    std::string trace_name = StringPrintf("%s(%s)", id_name.c_str(), name);
    ATRACE_NAME(trace_name.c_str());

    D("sync: %s('%s')", id_name.c_str(), name);
    switch (request.id) {
        case ID_LSTAT_V1:
            if (!do_lstat_v1(fd, name)) return false;
            break;
        case ID_LSTAT_V2:
        case ID_STAT_V2:
            if (!do_stat_v2(fd, request.id, name)) return false;
            break;
        case ID_LIST_V1:
            if (!do_list_v1(fd, name)) return false;
            break;
        case ID_LIST_V2:
            if (!do_list_v2(fd, name)) return false;
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
            SendSyncFail(fd, StringPrintf("unknown command %08x", request.id));
            return false;
    }

    return true;
}

void file_sync_service(unique_fd fd) {
    std::vector<char> buffer(SYNC_DATA_MAX);

    while (handle_sync_command(fd.get(), buffer)) {
    }

    D("sync: done");
}

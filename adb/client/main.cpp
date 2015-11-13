/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

// We only build the affinity WAR code for Linux.
#if defined(__linux__)
#include <sched.h>
#endif

#include "base/file.h"
#include "base/logging.h"
#include "base/stringprintf.h"

#include "adb.h"
#include "adb_auth.h"
#include "adb_listeners.h"
#include "transport.h"

#if defined(_WIN32)
static const char kNullFileName[] = "NUL";

static BOOL WINAPI ctrlc_handler(DWORD type) {
    // TODO: Consider trying to kill a starting up adb server (if we're in
    // launch_server) by calling GenerateConsoleCtrlEvent().
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}

static std::string GetLogFilePath() {
    const char log_name[] = "adb.log";
    WCHAR temp_path[MAX_PATH];

    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364992%28v=vs.85%29.aspx
    DWORD nchars = GetTempPathW(arraysize(temp_path), temp_path);
    if ((nchars >= arraysize(temp_path)) || (nchars == 0)) {
        // If string truncation or some other error.
        fatal("cannot retrieve temporary file path: %s\n",
              SystemErrorCodeToString(GetLastError()).c_str());
    }

    std::string temp_path_utf8;
    if (!android::base::WideToUTF8(temp_path, &temp_path_utf8)) {
        fatal_errno("cannot convert temporary file path from UTF-16 to UTF-8");
    }

    return temp_path_utf8 + log_name;
}
#else
static const char kNullFileName[] = "/dev/null";

static std::string GetLogFilePath() {
    return std::string("/tmp/adb.log");
}
#endif

static void close_stdin() {
    int fd = unix_open(kNullFileName, O_RDONLY);
    if (fd == -1) {
        fatal("cannot open '%s': %s", kNullFileName, strerror(errno));
    }
    if (dup2(fd, STDIN_FILENO) == -1) {
        fatal("cannot redirect stdin: %s", strerror(errno));
    }
    unix_close(fd);
}

static void setup_daemon_logging(void) {
    const std::string log_file_path(GetLogFilePath());
    int fd = unix_open(log_file_path.c_str(), O_WRONLY | O_CREAT | O_APPEND,
                       0640);
    if (fd == -1) {
        fatal("cannot open '%s': %s", log_file_path.c_str(), strerror(errno));
    }
    if (dup2(fd, STDOUT_FILENO) == -1) {
        fatal("cannot redirect stdout: %s", strerror(errno));
    }
    if (dup2(fd, STDERR_FILENO) == -1) {
        fatal("cannot redirect stderr: %s", strerror(errno));
    }
    unix_close(fd);

    fprintf(stderr, "--- adb starting (pid %d) ---\n", getpid());
    LOG(INFO) << adb_version();
}

int adb_main(int is_daemon, int server_port, int ack_reply_fd) {
#if defined(_WIN32)
    // adb start-server starts us up with stdout and stderr hooked up to
    // anonymous pipes to. When the C Runtime sees this, it makes stderr and
    // stdout buffered, but to improve the chance that error output is seen,
    // unbuffer stdout and stderr just like if we were run at the console.
    // This also keeps stderr unbuffered when it is redirected to adb.log.
    if (is_daemon) {
        if (setvbuf(stdout, NULL, _IONBF, 0) == -1) {
            fatal("cannot make stdout unbuffered: %s", strerror(errno));
        }
        if (setvbuf(stderr, NULL, _IONBF, 0) == -1) {
            fatal("cannot make stderr unbuffered: %s", strerror(errno));
        }
    }

    SetConsoleCtrlHandler(ctrlc_handler, TRUE);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();

    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    adb_auth_init();

    std::string error;
    std::string local_name = android::base::StringPrintf("tcp:%d", server_port);
    if (install_listener(local_name, "*smartsocket*", nullptr, 0, &error)) {
        fatal("could not install *smartsocket* listener: %s", error.c_str());
    }

    // Inform our parent that we are up and running.
    if (is_daemon) {
        close_stdin();
        setup_daemon_logging();

        // Any error output written to stderr now goes to adb.log. We could
        // keep around a copy of the stderr fd and use that to write any errors
        // encountered by the following code, but that is probably overkill.
#if defined(_WIN32)
        const HANDLE ack_reply_handle = cast_int_to_handle(ack_reply_fd);
        const CHAR ack[] = "OK\n";
        const DWORD bytes_to_write = arraysize(ack) - 1;
        DWORD written = 0;
        if (!WriteFile(ack_reply_handle, ack, bytes_to_write, &written, NULL)) {
            fatal("adb: cannot write ACK to handle 0x%p: %s", ack_reply_handle,
                  SystemErrorCodeToString(GetLastError()).c_str());
        }
        if (written != bytes_to_write) {
            fatal("adb: cannot write %lu bytes of ACK: only wrote %lu bytes",
                  bytes_to_write, written);
        }
        CloseHandle(ack_reply_handle);
#else
        // TODO(danalbert): Can't use SendOkay because we're sending "OK\n", not
        // "OKAY".
        if (!android::base::WriteStringToFd("OK\n", ack_reply_fd)) {
            fatal_errno("error writing ACK to fd %d", ack_reply_fd);
        }
        unix_close(ack_reply_fd);
#endif
    }

    D("Event loop starting");
    fdevent_loop();

    return 0;
}

int main(int argc, char** argv) {
    adb_sysdeps_init();
    adb_trace_init(argv);
    return adb_commandline(argc - 1, const_cast<const char**>(argv + 1));
}

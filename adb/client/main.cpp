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

#define TRACE_TAG TRACE_ADB

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

#if defined(WORKAROUND_BUG6558362) && defined(__linux__)
static const bool kWorkaroundBug6558362 = true;
#else
static const bool kWorkaroundBug6558362 = false;
#endif

static void adb_workaround_affinity(void) {
#if defined(__linux__)
    const char affinity_env[] = "ADB_CPU_AFFINITY_BUG6558362";
    const char* cpunum_str = getenv(affinity_env);
    if (cpunum_str == nullptr || *cpunum_str == '\0') {
        return;
    }

    char* strtol_res;
    int cpu_num = strtol(cpunum_str, &strtol_res, 0);
    if (*strtol_res != '\0') {
        fatal("bad number (%s) in env var %s. Expecting 0..n.\n", cpunum_str,
              affinity_env);
    }

    cpu_set_t cpu_set;
    sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
    D("orig cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);

    CPU_ZERO(&cpu_set);
    CPU_SET(cpu_num, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set), &cpu_set);

    sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
    D("new cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);
#else
    // No workaround was ever implemented for the other platforms.
#endif
}

#if defined(_WIN32)
static const char kNullFileName[] = "NUL";

static BOOL WINAPI ctrlc_handler(DWORD type) {
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

    return narrow(temp_path) + log_name;
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

#ifdef _WIN32
    // On Windows, stderr is buffered by default, so switch to non-buffered
    // to match Linux.
    setvbuf(stderr, NULL, _IONBF, 0);
#endif
    fprintf(stderr, "--- adb starting (pid %d) ---\n", getpid());
}

int adb_main(int is_daemon, int server_port, int ack_reply_fd) {
    HOST = 1;

#if defined(_WIN32)
    SetConsoleCtrlHandler(ctrlc_handler, TRUE);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();

    if (kWorkaroundBug6558362 && is_daemon) {
        adb_workaround_affinity();
    }

    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    adb_auth_init();

    std::string error;
    std::string local_name = android::base::StringPrintf("tcp:%d", server_port);
    if (install_listener(local_name, "*smartsocket*", nullptr, 0, &error)) {
        LOG(FATAL) << "Could not install *smartsocket* listener: " << error;
    }

    // Inform our parent that we are up and running.
    if (is_daemon) {
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
        android::base::WriteStringToFd("OK\n", ack_reply_fd);
        unix_close(ack_reply_fd);
#endif
        close_stdin();
        setup_daemon_logging();
    }

    D("Event loop starting\n");
    fdevent_loop();

    return 0;
}

#ifdef _WIN32
static bool _argv_is_utf8 = false;
#endif

int main(int argc, char** argv) {
#ifdef _WIN32
    if (!_argv_is_utf8) {
        fatal("_argv_is_utf8 is not set, suggesting that wmain was not "
              "called. Did you forget to link with -municode?");
    }
#endif

    adb_sysdeps_init();
    adb_trace_init(argv);
    return adb_commandline(argc - 1, const_cast<const char**>(argv + 1));
}

#ifdef _WIN32

extern "C"
int wmain(int argc, wchar_t **argv) {
    // Set diagnostic flag to try to detect if the build system was not
    // configured to call wmain.
    _argv_is_utf8 = true;

    // Convert args from UTF-16 to UTF-8 and pass that to main().
    NarrowArgs narrow_args(argc, argv);
    return main(argc, narrow_args.data());
}

#endif

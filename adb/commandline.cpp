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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/stringprintf.h>
#include <base/strings.h>

#if !defined(_WIN32)
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#endif

#include "adb.h"
#include "adb_auth.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "file_sync_service.h"
#include "services.h"
#include "shell_service.h"
#include "transport.h"

static int install_app(TransportType t, const char* serial, int argc, const char** argv);
static int install_multiple_app(TransportType t, const char* serial, int argc, const char** argv);
static int uninstall_app(TransportType t, const char* serial, int argc, const char** argv);
static int install_app_legacy(TransportType t, const char* serial, int argc, const char** argv);
static int uninstall_app_legacy(TransportType t, const char* serial, int argc, const char** argv);

static std::string gProductOutPath;
extern int gListenAll;

static std::string product_file(const char *extra) {
    if (gProductOutPath.empty()) {
        fprintf(stderr, "adb: Product directory not specified; "
                "use -p or define ANDROID_PRODUCT_OUT\n");
        exit(1);
    }

    return android::base::StringPrintf("%s%s%s",
                                       gProductOutPath.c_str(), OS_PATH_SEPARATOR_STR, extra);
}

static void help() {
    fprintf(stderr, "%s\n", adb_version().c_str());
    fprintf(stderr,
        " -a                            - directs adb to listen on all interfaces for a connection\n"
        " -d                            - directs command to the only connected USB device\n"
        "                                 returns an error if more than one USB device is present.\n"
        " -e                            - directs command to the only running emulator.\n"
        "                                 returns an error if more than one emulator is running.\n"
        " -s <specific device>          - directs command to the device or emulator with the given\n"
        "                                 serial number or qualifier. Overrides ANDROID_SERIAL\n"
        "                                 environment variable.\n"
        " -p <product name or path>     - simple product name like 'sooner', or\n"
        "                                 a relative/absolute path to a product\n"
        "                                 out directory like 'out/target/product/sooner'.\n"
        "                                 If -p is not specified, the ANDROID_PRODUCT_OUT\n"
        "                                 environment variable is used, which must\n"
        "                                 be an absolute path.\n"
        " -H                            - Name of adb server host (default: localhost)\n"
        " -P                            - Port of adb server (default: 5037)\n"
        " devices [-l]                  - list all connected devices\n"
        "                                 ('-l' will also list device qualifiers)\n"
        " connect <host>[:<port>]       - connect to a device via TCP/IP\n"
        "                                 Port 5555 is used by default if no port number is specified.\n"
        " disconnect [<host>[:<port>]]  - disconnect from a TCP/IP device.\n"
        "                                 Port 5555 is used by default if no port number is specified.\n"
        "                                 Using this command with no additional arguments\n"
        "                                 will disconnect from all connected TCP/IP devices.\n"
        "\n"
        "device commands:\n"
        "  adb push <local>... <remote>\n"
        "                               - copy files/dirs to device\n"
        "  adb pull [-a] <remote>... <local>\n"
        "                               - copy files/dirs from device\n"
        "                                 (-a preserves file timestamp and mode)\n"
        "  adb sync [ <directory> ]     - copy host->device only if changed\n"
        "                                 (-l means list but don't copy)\n"
        "  adb shell [-Ttx]             - run remote shell interactively\n"
        "  adb shell [-Ttx] <command>   - run remote shell command\n"
        "                                 (-T disables PTY allocation)\n"
        "                                 (-t forces PTY allocation)\n"
        "                                 (-x disables remote exit codes and stdout/stderr separation)\n"
        "  adb emu <command>            - run emulator console command\n"
        "  adb logcat [ <filter-spec> ] - View device log\n"
        "  adb forward --list           - list all forward socket connections.\n"
        "                                 the format is a list of lines with the following format:\n"
        "                                    <serial> \" \" <local> \" \" <remote> \"\\n\"\n"
        "  adb forward <local> <remote> - forward socket connections\n"
        "                                 forward specs are one of: \n"
        "                                   tcp:<port>\n"
        "                                   localabstract:<unix domain socket name>\n"
        "                                   localreserved:<unix domain socket name>\n"
        "                                   localfilesystem:<unix domain socket name>\n"
        "                                   dev:<character device name>\n"
        "                                   jdwp:<process pid> (remote only)\n"
        "  adb forward --no-rebind <local> <remote>\n"
        "                               - same as 'adb forward <local> <remote>' but fails\n"
        "                                 if <local> is already forwarded\n"
        "  adb forward --remove <local> - remove a specific forward socket connection\n"
        "  adb forward --remove-all     - remove all forward socket connections\n"
        "  adb reverse --list           - list all reverse socket connections from device\n"
        "  adb reverse <remote> <local> - reverse socket connections\n"
        "                                 reverse specs are one of:\n"
        "                                   tcp:<port>\n"
        "                                   localabstract:<unix domain socket name>\n"
        "                                   localreserved:<unix domain socket name>\n"
        "                                   localfilesystem:<unix domain socket name>\n"
        "  adb reverse --no-rebind <remote> <local>\n"
        "                               - same as 'adb reverse <remote> <local>' but fails\n"
        "                                 if <remote> is already reversed.\n"
        "  adb reverse --remove <remote>\n"
        "                               - remove a specific reversed socket connection\n"
        "  adb reverse --remove-all     - remove all reversed socket connections from device\n"
        "  adb jdwp                     - list PIDs of processes hosting a JDWP transport\n"
        "  adb install [-lrtsdg] <file>\n"
        "                               - push this package file to the device and install it\n"
        "                                 (-l: forward lock application)\n"
        "                                 (-r: replace existing application)\n"
        "                                 (-t: allow test packages)\n"
        "                                 (-s: install application on sdcard)\n"
        "                                 (-d: allow version code downgrade)\n"
        "                                 (-g: grant all runtime permissions)\n"
        "  adb install-multiple [-lrtsdpg] <file...>\n"
        "                               - push this package file to the device and install it\n"
        "                                 (-l: forward lock application)\n"
        "                                 (-r: replace existing application)\n"
        "                                 (-t: allow test packages)\n"
        "                                 (-s: install application on sdcard)\n"
        "                                 (-d: allow version code downgrade)\n"
        "                                 (-p: partial application install)\n"
        "                                 (-g: grant all runtime permissions)\n"
        "  adb uninstall [-k] <package> - remove this app package from the device\n"
        "                                 ('-k' means keep the data and cache directories)\n"
        "  adb bugreport                - return all information from the device\n"
        "                                 that should be included in a bug report.\n"
        "\n"
        "  adb backup [-f <file>] [-apk|-noapk] [-obb|-noobb] [-shared|-noshared] [-all] [-system|-nosystem] [<packages...>]\n"
        "                               - write an archive of the device's data to <file>.\n"
        "                                 If no -f option is supplied then the data is written\n"
        "                                 to \"backup.ab\" in the current directory.\n"
        "                                 (-apk|-noapk enable/disable backup of the .apks themselves\n"
        "                                    in the archive; the default is noapk.)\n"
        "                                 (-obb|-noobb enable/disable backup of any installed apk expansion\n"
        "                                    (aka .obb) files associated with each application; the default\n"
        "                                    is noobb.)\n"
        "                                 (-shared|-noshared enable/disable backup of the device's\n"
        "                                    shared storage / SD card contents; the default is noshared.)\n"
        "                                 (-all means to back up all installed applications)\n"
        "                                 (-system|-nosystem toggles whether -all automatically includes\n"
        "                                    system applications; the default is to include system apps)\n"
        "                                 (<packages...> is the list of applications to be backed up.  If\n"
        "                                    the -all or -shared flags are passed, then the package\n"
        "                                    list is optional.  Applications explicitly given on the\n"
        "                                    command line will be included even if -nosystem would\n"
        "                                    ordinarily cause them to be omitted.)\n"
        "\n"
        "  adb restore <file>           - restore device contents from the <file> backup archive\n"
        "\n"
        "  adb disable-verity           - disable dm-verity checking on USERDEBUG builds\n"
        "  adb enable-verity            - re-enable dm-verity checking on USERDEBUG builds\n"
        "  adb keygen <file>            - generate adb public/private key. The private key is stored in <file>,\n"
        "                                 and the public key is stored in <file>.pub. Any existing files\n"
        "                                 are overwritten.\n"
        "  adb help                     - show this help message\n"
        "  adb version                  - show version num\n"
        "\n"
        "scripting:\n"
        "  adb wait-for-device          - block until device is online\n"
        "  adb start-server             - ensure that there is a server running\n"
        "  adb kill-server              - kill the server if it is running\n"
        "  adb get-state                - prints: offline | bootloader | device\n"
        "  adb get-serialno             - prints: <serial-number>\n"
        "  adb get-devpath              - prints: <device-path>\n"
        "  adb remount                  - remounts the /system, /vendor (if present) and /oem (if present) partitions on the device read-write\n"
        "  adb reboot [bootloader|recovery]\n"
        "                               - reboots the device, optionally into the bootloader or recovery program.\n"
        "  adb reboot sideload          - reboots the device into the sideload mode in recovery program (adb root required).\n"
        "  adb reboot sideload-auto-reboot\n"
        "                               - reboots into the sideload mode, then reboots automatically after the sideload regardless of the result.\n"
        "  adb sideload <file>          - sideloads the given package\n"
        "  adb root                     - restarts the adbd daemon with root permissions\n"
        "  adb unroot                   - restarts the adbd daemon without root permissions\n"
        "  adb usb                      - restarts the adbd daemon listening on USB\n"
        "  adb tcpip <port>             - restarts the adbd daemon listening on TCP on the specified port\n"
        "\n"
        "networking:\n"
        "  adb ppp <tty> [parameters]   - Run PPP over USB.\n"
        " Note: you should not automatically start a PPP connection.\n"
        " <tty> refers to the tty for PPP stream. Eg. dev:/dev/omap_csmi_tty1\n"
        " [parameters] - Eg. defaultroute debug dump local notty usepeerdns\n"
        "\n"
        "adb sync notes: adb sync [ <directory> ]\n"
        "  <localdir> can be interpreted in several ways:\n"
        "\n"
        "  - If <directory> is not specified, /system, /vendor (if present), /oem (if present) and /data partitions will be updated.\n"
        "\n"
        "  - If it is \"system\", \"vendor\", \"oem\" or \"data\", only the corresponding partition\n"
        "    is updated.\n"
        "\n"
        "environment variables:\n"
        "  ADB_TRACE                    - Print debug information. A comma separated list of the following values\n"
        "                                 1 or all, adb, sockets, packets, rwx, usb, sync, sysdeps, transport, jdwp\n"
        "  ANDROID_SERIAL               - The serial number to connect to. -s takes priority over this if given.\n"
        "  ANDROID_LOG_TAGS             - When used with the logcat option, only these debug tags are printed.\n"
        );
}

static int usage() {
    help();
    return 1;
}

#if defined(_WIN32)

// Implemented in sysdeps_win32.cpp.
void stdin_raw_init();
void stdin_raw_restore();

#else
static termios g_saved_terminal_state;

static void stdin_raw_init() {
    if (tcgetattr(STDIN_FILENO, &g_saved_terminal_state)) return;

    termios tio;
    if (tcgetattr(STDIN_FILENO, &tio)) return;

    cfmakeraw(&tio);

    // No timeout but request at least one character per read.
    tio.c_cc[VTIME] = 0;
    tio.c_cc[VMIN] = 1;

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio);
}

static void stdin_raw_restore() {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_saved_terminal_state);
}
#endif

// Reads from |fd| and prints received data. If |use_shell_protocol| is true
// this expects that incoming data will use the shell protocol, in which case
// stdout/stderr are routed independently and the remote exit code will be
// returned.
static int read_and_dump(int fd, bool use_shell_protocol=false) {
    int exit_code = 0;
    std::unique_ptr<ShellProtocol> protocol;
    int length = 0;
    FILE* outfile = stdout;

    char raw_buffer[BUFSIZ];
    char* buffer_ptr = raw_buffer;
    if (use_shell_protocol) {
        protocol.reset(new ShellProtocol(fd));
        if (!protocol) {
            LOG(ERROR) << "failed to allocate memory for ShellProtocol object";
            return 1;
        }
        buffer_ptr = protocol->data();
    }

    while (fd >= 0) {
        if (use_shell_protocol) {
            if (!protocol->Read()) {
                break;
            }
            switch (protocol->id()) {
                case ShellProtocol::kIdStdout:
                    outfile = stdout;
                    break;
                case ShellProtocol::kIdStderr:
                    outfile = stderr;
                    break;
                case ShellProtocol::kIdExit:
                    exit_code = protocol->data()[0];
                    continue;
                default:
                    continue;
            }
            length = protocol->data_length();
        } else {
            D("read_and_dump(): pre adb_read(fd=%d)", fd);
            length = adb_read(fd, raw_buffer, sizeof(raw_buffer));
            D("read_and_dump(): post adb_read(fd=%d): length=%d", fd, length);
            if (length <= 0) {
                break;
            }
        }

        fwrite(buffer_ptr, 1, length, outfile);
        fflush(outfile);
    }

    return exit_code;
}

static void read_status_line(int fd, char* buf, size_t count)
{
    count--;
    while (count > 0) {
        int len = adb_read(fd, buf, count);
        if (len <= 0) {
            break;
        }

        buf += len;
        count -= len;
    }
    *buf = '\0';
}

static void copy_to_file(int inFd, int outFd) {
    const size_t BUFSIZE = 32 * 1024;
    char* buf = (char*) malloc(BUFSIZE);
    if (buf == nullptr) fatal("couldn't allocate buffer for copy_to_file");
    int len;
    long total = 0;
#ifdef _WIN32
    int old_stdin_mode = -1;
    int old_stdout_mode = -1;
#endif

    D("copy_to_file(%d -> %d)", inFd, outFd);

    if (inFd == STDIN_FILENO) {
        stdin_raw_init();
#ifdef _WIN32
        old_stdin_mode = _setmode(STDIN_FILENO, _O_BINARY);
        if (old_stdin_mode == -1) {
            fatal_errno("could not set stdin to binary");
        }
#endif
    }

#ifdef _WIN32
    if (outFd == STDOUT_FILENO) {
        old_stdout_mode = _setmode(STDOUT_FILENO, _O_BINARY);
        if (old_stdout_mode == -1) {
            fatal_errno("could not set stdout to binary");
        }
    }
#endif

    while (true) {
        if (inFd == STDIN_FILENO) {
            len = unix_read(inFd, buf, BUFSIZE);
        } else {
            len = adb_read(inFd, buf, BUFSIZE);
        }
        if (len == 0) {
            D("copy_to_file() : read 0 bytes; exiting");
            break;
        }
        if (len < 0) {
            D("copy_to_file(): read failed: %s", strerror(errno));
            break;
        }
        if (outFd == STDOUT_FILENO) {
            fwrite(buf, 1, len, stdout);
            fflush(stdout);
        } else {
            adb_write(outFd, buf, len);
        }
        total += len;
    }

    if (inFd == STDIN_FILENO) {
        stdin_raw_restore();
#ifdef _WIN32
        if (_setmode(STDIN_FILENO, old_stdin_mode) == -1) {
            fatal_errno("could not restore stdin mode");
        }
#endif
    }

#ifdef _WIN32
    if (outFd == STDOUT_FILENO) {
        if (_setmode(STDOUT_FILENO, old_stdout_mode) == -1) {
            fatal_errno("could not restore stdout mode");
        }
    }
#endif

    D("copy_to_file() finished after %lu bytes", total);
    free(buf);
}

static std::string format_host_command(const char* command,
                                       TransportType type, const char* serial) {
    if (serial) {
        return android::base::StringPrintf("host-serial:%s:%s", serial, command);
    }

    const char* prefix = "host";
    if (type == kTransportUsb) {
        prefix = "host-usb";
    } else if (type == kTransportLocal) {
        prefix = "host-local";
    }
    return android::base::StringPrintf("%s:%s", prefix, command);
}

// Returns the FeatureSet for the indicated transport.
static FeatureSet GetFeatureSet(TransportType transport_type, const char* serial) {
    std::string result, error;
    if (adb_query(format_host_command("features", transport_type, serial), &result, &error)) {
        return StringToFeatureSet(result);
    }
    return FeatureSet();
}

static void send_window_size_change(int fd, std::unique_ptr<ShellProtocol>& shell) {
#if !defined(_WIN32)
    // Old devices can't handle window size changes.
    if (shell == nullptr) return;

    winsize ws;
    if (ioctl(fd, TIOCGWINSZ, &ws) == -1) return;

    // Send the new window size as human-readable ASCII for debugging convenience.
    size_t l = snprintf(shell->data(), shell->data_capacity(), "%dx%d,%dx%d",
                        ws.ws_row, ws.ws_col, ws.ws_xpixel, ws.ws_ypixel);
    shell->Write(ShellProtocol::kIdWindowSizeChange, l + 1);
#endif
}

// Used to pass multiple values to the stdin read thread.
struct StdinReadArgs {
    int stdin_fd, write_fd;
    bool raw_stdin;
    std::unique_ptr<ShellProtocol> protocol;
};

// Loops to read from stdin and push the data to the given FD.
// The argument should be a pointer to a StdinReadArgs object. This function
// will take ownership of the object and delete it when finished.
static void* stdin_read_thread_loop(void* x) {
    std::unique_ptr<StdinReadArgs> args(reinterpret_cast<StdinReadArgs*>(x));
    int state = 0;

#if !defined(_WIN32)
    // Mask SIGTTIN in case we're in a backgrounded process.
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTTIN);
    pthread_sigmask(SIG_BLOCK, &sigset, nullptr);
#endif

#if !defined(_WIN32)
    // Unblock SIGWINCH for this thread, so our read(2) below will be
    // interrupted if the window size changes.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWINCH);
    pthread_sigmask(SIG_UNBLOCK, &mask, nullptr);
#endif

    // Set up the initial window size.
    send_window_size_change(args->stdin_fd, args->protocol);

    char raw_buffer[1024];
    char* buffer_ptr = raw_buffer;
    size_t buffer_size = sizeof(raw_buffer);
    if (args->protocol != nullptr) {
        buffer_ptr = args->protocol->data();
        buffer_size = args->protocol->data_capacity();
    }

    while (true) {
        // Use unix_read() rather than adb_read() for stdin.
        D("stdin_read_thread_loop(): pre unix_read(fdi=%d,...)", args->stdin_fd);
#if !defined(_WIN32)
#undef read
        int r = read(args->stdin_fd, buffer_ptr, buffer_size);
        if (r == -1 && errno == EINTR) {
            send_window_size_change(args->stdin_fd, args->protocol);
            continue;
        }
#define read ___xxx_read
#else
        int r = unix_read(args->stdin_fd, buffer_ptr, buffer_size);
#endif
        D("stdin_read_thread_loop(): post unix_read(fdi=%d,...)", args->stdin_fd);
        if (r <= 0) {
            // Only devices using the shell protocol know to close subprocess
            // stdin. For older devices we want to just leave the connection
            // open, otherwise an unpredictable amount of return data could
            // be lost due to the FD closing before all data has been received.
            if (args->protocol) {
                args->protocol->Write(ShellProtocol::kIdCloseStdin, 0);
            }
            break;
        }
        // If we made stdin raw, check input for the "~." escape sequence. In
        // this situation signals like Ctrl+C are sent remotely rather than
        // interpreted locally so this provides an emergency out if the remote
        // process starts ignoring the signal. SSH also does this, see the
        // "escape characters" section on the ssh man page for more info.
        if (args->raw_stdin) {
            for (int n = 0; n < r; n++) {
                switch (buffer_ptr[n]) {
                case '\n':
                    state = 1;
                    break;
                case '\r':
                    state = 1;
                    break;
                case '~':
                    if (state == 1) {
                        state++;
                    } else {
                        state = 0;
                    }
                    break;
                case '.':
                    if (state == 2) {
                        fprintf(stderr,"\r\n* disconnect *\r\n");
                        stdin_raw_restore();
                        exit(0);
                    }
                default:
                    state = 0;
                }
            }
        }
        if (args->protocol) {
            if (!args->protocol->Write(ShellProtocol::kIdStdin, r)) {
                break;
            }
        } else {
            if (!WriteFdExactly(args->write_fd, buffer_ptr, r)) {
                break;
            }
        }
    }

    return nullptr;
}

// Returns a shell service string with the indicated arguments and command.
static std::string ShellServiceString(bool use_shell_protocol,
                                      const std::string& type_arg,
                                      const std::string& command) {
    std::vector<std::string> args;
    if (use_shell_protocol) {
        args.push_back(kShellServiceArgShellProtocol);
    }
    if (!type_arg.empty()) {
        args.push_back(type_arg);
    }

    // Shell service string can look like: shell[,arg1,arg2,...]:[command].
    return android::base::StringPrintf("shell%s%s:%s",
                                       args.empty() ? "" : ",",
                                       android::base::Join(args, ',').c_str(),
                                       command.c_str());
}

// Connects to a shell on the device and read/writes data.
//
// Note: currently this function doesn't properly clean up resources; the
// FD connected to the adb server is never closed and the stdin read thread
// may never exit.
//
// On success returns the remote exit code if |use_shell_protocol| is true,
// 0 otherwise. On failure returns 1.
static int RemoteShell(bool use_shell_protocol, const std::string& type_arg,
                       const std::string& command) {
    std::string service_string = ShellServiceString(use_shell_protocol,
                                                    type_arg, command);

    // Make local stdin raw if the device allocates a PTY, which happens if:
    //   1. We are explicitly asking for a PTY shell, or
    //   2. We don't specify shell type and are starting an interactive session.
    bool raw_stdin = (type_arg == kShellServiceArgPty ||
                      (type_arg.empty() && command.empty()));

    std::string error;
    int fd = adb_connect(service_string, &error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error.c_str());
        return 1;
    }

    StdinReadArgs* args = new StdinReadArgs;
    if (!args) {
        LOG(ERROR) << "couldn't allocate StdinReadArgs object";
        return 1;
    }
    args->stdin_fd = STDIN_FILENO;
    args->write_fd = fd;
    args->raw_stdin = raw_stdin;
    if (use_shell_protocol) {
        args->protocol.reset(new ShellProtocol(args->write_fd));
    }

    if (raw_stdin) stdin_raw_init();

#if !defined(_WIN32)
    // Ensure our process is notified if the local window size changes.
    // We use sigaction(2) to ensure that the SA_RESTART flag is not set,
    // because the whole reason we're sending signals is to unblock the read(2)!
    // That also means we don't need to do anything in the signal handler:
    // the side effect of delivering the signal is all we need.
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = [](int) {};
    sa.sa_flags = 0;
    sigaction(SIGWINCH, &sa, nullptr);

    // Now block SIGWINCH in this thread (the main thread) and all threads spawned
    // from it. The stdin read thread will unblock this signal to ensure that it's
    // the thread that receives the signal.
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGWINCH);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);
#endif

    // TODO: combine read_and_dump with stdin_read_thread to make life simpler?
    int exit_code = 1;
    if (!adb_thread_create(stdin_read_thread_loop, args)) {
        PLOG(ERROR) << "error starting stdin read thread";
        delete args;
    } else {
        exit_code = read_and_dump(fd, use_shell_protocol);
    }

    // TODO: properly exit stdin_read_thread_loop and close |fd|.

    // TODO: we should probably install signal handlers for this.
    // TODO: can we use atexit? even on Windows?
    if (raw_stdin) stdin_raw_restore();

    return exit_code;
}

static int adb_shell(int argc, const char** argv,
                     TransportType transport_type, const char* serial) {
    FeatureSet features = GetFeatureSet(transport_type, serial);

    bool use_shell_protocol = CanUseFeature(features, kFeatureShell2);
    if (!use_shell_protocol) {
        D("shell protocol not supported, using raw data transfer");
    } else {
        D("using shell protocol");
    }

    // Parse shell-specific command-line options.
    // argv[0] is always "shell".
    --argc;
    ++argv;
    int t_arg_count = 0;
    while (argc) {
        if (!strcmp(argv[0], "-T") || !strcmp(argv[0], "-t")) {
            if (!CanUseFeature(features, kFeatureShell2)) {
                fprintf(stderr, "error: target doesn't support PTY args -Tt\n");
                return 1;
            }
            // Like ssh, -t arguments are cumulative so that multiple -t's
            // are needed to force a PTY.
            if (argv[0][1] == 't') {
                ++t_arg_count;
            } else {
                t_arg_count = -1;
            }
            --argc;
            ++argv;
        } else if (!strcmp(argv[0], "-x")) {
            use_shell_protocol = false;
            --argc;
            ++argv;
        } else {
            break;
        }
    }

    std::string shell_type_arg;
    if (CanUseFeature(features, kFeatureShell2)) {
        if (t_arg_count < 0) {
            shell_type_arg = kShellServiceArgRaw;
        } else if (t_arg_count == 0) {
            // If stdin isn't a TTY, default to a raw shell; this lets
            // things like `adb shell < my_script.sh` work as expected.
            // Otherwise leave |shell_type_arg| blank which uses PTY for
            // interactive shells and raw for non-interactive.
            if (!unix_isatty(STDIN_FILENO)) {
                shell_type_arg = kShellServiceArgRaw;
            }
        } else if (t_arg_count == 1) {
            // A single -t arg isn't enough to override implicit -T.
            if (!unix_isatty(STDIN_FILENO)) {
                fprintf(stderr,
                        "Remote PTY will not be allocated because stdin is not a terminal.\n"
                        "Use multiple -t options to force remote PTY allocation.\n");
                shell_type_arg = kShellServiceArgRaw;
            } else {
                shell_type_arg = kShellServiceArgPty;
            }
        } else {
            shell_type_arg = kShellServiceArgPty;
        }
    }

    std::string command;
    if (argc) {
        // We don't escape here, just like ssh(1). http://b/20564385.
        command = android::base::Join(std::vector<const char*>(argv, argv + argc), ' ');
    }

    return RemoteShell(use_shell_protocol, shell_type_arg, command);
}

static int adb_download_buffer(const char *service, const char *fn, const void* data, unsigned sz,
                               bool show_progress)
{
    std::string error;
    int fd = adb_connect(android::base::StringPrintf("%s:%d", service, sz), &error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error.c_str());
        return -1;
    }

    int opt = CHUNK_SIZE;
    opt = adb_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *) &opt, sizeof(opt));

    unsigned total = sz;
    const uint8_t* ptr = reinterpret_cast<const uint8_t*>(data);

    if (show_progress) {
        const char* x = strrchr(service, ':');
        if (x) service = x + 1;
    }

    while (sz > 0) {
        unsigned xfer = (sz > CHUNK_SIZE) ? CHUNK_SIZE : sz;
        if (!WriteFdExactly(fd, ptr, xfer)) {
            std::string error;
            adb_status(fd, &error);
            fprintf(stderr,"* failed to write data '%s' *\n", error.c_str());
            adb_close(fd);
            return -1;
        }
        sz -= xfer;
        ptr += xfer;
        if (show_progress) {
            printf("sending: '%s' %4d%%    \r", fn, (int)(100LL - ((100LL * sz) / (total))));
            fflush(stdout);
        }
    }
    if (show_progress) {
        printf("\n");
    }

    if (!adb_status(fd, &error)) {
        fprintf(stderr,"* error response '%s' *\n", error.c_str());
        adb_close(fd);
        return -1;
    }

    adb_close(fd);
    return 0;
}

#define SIDELOAD_HOST_BLOCK_SIZE (CHUNK_SIZE)

/*
 * The sideload-host protocol serves the data in a file (given on the
 * command line) to the client, using a simple protocol:
 *
 * - The connect message includes the total number of bytes in the
 *   file and a block size chosen by us.
 *
 * - The other side sends the desired block number as eight decimal
 *   digits (eg "00000023" for block 23).  Blocks are numbered from
 *   zero.
 *
 * - We send back the data of the requested block.  The last block is
 *   likely to be partial; when the last block is requested we only
 *   send the part of the block that exists, it's not padded up to the
 *   block size.
 *
 * - When the other side sends "DONEDONE" instead of a block number,
 *   we hang up.
 */
static int adb_sideload_host(const char* fn) {
    unsigned sz;
    size_t xfer = 0;
    int status;
    int last_percent = -1;
    int opt = SIDELOAD_HOST_BLOCK_SIZE;

    printf("loading: '%s'", fn);
    fflush(stdout);
    uint8_t* data = reinterpret_cast<uint8_t*>(load_file(fn, &sz));
    if (data == 0) {
        printf("\n");
        fprintf(stderr, "* cannot read '%s' *\n", fn);
        return -1;
    }

    std::string service =
            android::base::StringPrintf("sideload-host:%d:%d", sz, SIDELOAD_HOST_BLOCK_SIZE);
    std::string error;
    int fd = adb_connect(service, &error);
    if (fd < 0) {
        // Try falling back to the older sideload method.  Maybe this
        // is an older device that doesn't support sideload-host.
        printf("\n");
        status = adb_download_buffer("sideload", fn, data, sz, true);
        goto done;
    }

    opt = adb_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const void *) &opt, sizeof(opt));

    while (true) {
        char buf[9];
        if (!ReadFdExactly(fd, buf, 8)) {
            fprintf(stderr, "* failed to read command: %s\n", strerror(errno));
            status = -1;
            goto done;
        }
        buf[8] = '\0';

        if (strcmp("DONEDONE", buf) == 0) {
            status = 0;
            break;
        }

        int block = strtol(buf, NULL, 10);

        size_t offset = block * SIDELOAD_HOST_BLOCK_SIZE;
        if (offset >= sz) {
            fprintf(stderr, "* attempt to read block %d past end\n", block);
            status = -1;
            goto done;
        }
        uint8_t* start = data + offset;
        size_t offset_end = offset + SIDELOAD_HOST_BLOCK_SIZE;
        size_t to_write = SIDELOAD_HOST_BLOCK_SIZE;
        if (offset_end > sz) {
            to_write = sz - offset;
        }

        if(!WriteFdExactly(fd, start, to_write)) {
            adb_status(fd, &error);
            fprintf(stderr,"* failed to write data '%s' *\n", error.c_str());
            status = -1;
            goto done;
        }
        xfer += to_write;

        // For normal OTA packages, we expect to transfer every byte
        // twice, plus a bit of overhead (one read during
        // verification, one read of each byte for installation, plus
        // extra access to things like the zip central directory).
        // This estimate of the completion becomes 100% when we've
        // transferred ~2.13 (=100/47) times the package size.
        int percent = (int)(xfer * 47LL / (sz ? sz : 1));
        if (percent != last_percent) {
            printf("\rserving: '%s'  (~%d%%)    ", fn, percent);
            fflush(stdout);
            last_percent = percent;
        }
    }

    printf("\rTotal xfer: %.2fx%*s\n", (double)xfer / (sz ? sz : 1), (int)strlen(fn)+10, "");

  done:
    if (fd >= 0) adb_close(fd);
    free(data);
    return status;
}

/**
 * Run ppp in "notty" mode against a resource listed as the first parameter
 * eg:
 *
 * ppp dev:/dev/omap_csmi_tty0 <ppp options>
 *
 */
static int ppp(int argc, const char** argv) {
#if defined(_WIN32)
    fprintf(stderr, "error: adb %s not implemented on Win32\n", argv[0]);
    return -1;
#else
    if (argc < 2) {
        fprintf(stderr, "usage: adb %s <adb service name> [ppp opts]\n",
                argv[0]);

        return 1;
    }

    const char* adb_service_name = argv[1];
    std::string error;
    int fd = adb_connect(adb_service_name, &error);
    if (fd < 0) {
        fprintf(stderr,"Error: Could not open adb service: %s. Error: %s\n",
                adb_service_name, error.c_str());
        return 1;
    }

    pid_t pid = fork();

    if (pid < 0) {
        perror("from fork()");
        return 1;
    } else if (pid == 0) {
        int err;
        int i;
        const char **ppp_args;

        // copy args
        ppp_args = (const char **) alloca(sizeof(char *) * argc + 1);
        ppp_args[0] = "pppd";
        for (i = 2 ; i < argc ; i++) {
            //argv[2] and beyond become ppp_args[1] and beyond
            ppp_args[i - 1] = argv[i];
        }
        ppp_args[i-1] = NULL;

        // child side

        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        adb_close(STDERR_FILENO);
        adb_close(fd);

        err = execvp("pppd", (char * const *)ppp_args);

        if (err < 0) {
            perror("execing pppd");
        }
        exit(-1);
    } else {
        // parent side

        adb_close(fd);
        return 0;
    }
#endif /* !defined(_WIN32) */
}

static bool wait_for_device(const char* service, TransportType t, const char* serial) {
    // Was the caller vague about what they'd like us to wait for?
    // If so, check they weren't more specific in their choice of transport type.
    if (strcmp(service, "wait-for-device") == 0) {
        if (t == kTransportUsb) {
            service = "wait-for-usb";
        } else if (t == kTransportLocal) {
            service = "wait-for-local";
        } else {
            service = "wait-for-any";
        }
    }

    std::string cmd = format_host_command(service, t, serial);
    return adb_command(cmd);
}

// Connects to the device "shell" service with |command| and prints the
// resulting output.
static int send_shell_command(TransportType transport_type, const char* serial,
                              const std::string& command,
                              bool disable_shell_protocol) {
    // Only use shell protocol if it's supported and the caller doesn't want
    // to explicitly disable it.
    bool use_shell_protocol = false;
    if (!disable_shell_protocol) {
        FeatureSet features = GetFeatureSet(transport_type, serial);
        use_shell_protocol = CanUseFeature(features, kFeatureShell2);
    }

    std::string service_string = ShellServiceString(use_shell_protocol, "",
                                                    command);

    int fd;
    while (true) {
        std::string error;
        fd = adb_connect(service_string, &error);
        if (fd >= 0) {
            break;
        }
        fprintf(stderr,"- waiting for device -\n");
        adb_sleep_ms(1000);
        wait_for_device("wait-for-device", transport_type, serial);
    }

    int exit_code = read_and_dump(fd, use_shell_protocol);

    if (adb_close(fd) < 0) {
        PLOG(ERROR) << "failure closing FD " << fd;
    }

    return exit_code;
}

static int logcat(TransportType transport, const char* serial, int argc, const char** argv) {
    char* log_tags = getenv("ANDROID_LOG_TAGS");
    std::string quoted = escape_arg(log_tags == nullptr ? "" : log_tags);

    std::string cmd = "export ANDROID_LOG_TAGS=\"" + quoted + "\"; exec logcat";

    if (!strcmp(argv[0], "longcat")) {
        cmd += " -v long";
    }

    --argc;
    ++argv;
    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    // No need for shell protocol with logcat, always disable for simplicity.
    return send_shell_command(transport, serial, cmd, true);
}

static int backup(int argc, const char** argv) {
    const char* filename = "backup.ab";

    /* find, extract, and use any -f argument */
    for (int i = 1; i < argc; i++) {
        if (!strcmp("-f", argv[i])) {
            if (i == argc-1) {
                fprintf(stderr, "adb: -f passed with no filename\n");
                return usage();
            }
            filename = argv[i+1];
            for (int j = i+2; j <= argc; ) {
                argv[i++] = argv[j++];
            }
            argc -= 2;
            argv[argc] = NULL;
        }
    }

    /* bare "adb backup" or "adb backup -f filename" are not valid invocations */
    if (argc < 2) return usage();

    adb_unlink(filename);
    int outFd = adb_creat(filename, 0640);
    if (outFd < 0) {
        fprintf(stderr, "adb: unable to open file %s\n", filename);
        return -1;
    }

    std::string cmd = "backup:";
    --argc;
    ++argv;
    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    D("backup. filename=%s cmd=%s", filename, cmd.c_str());
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for backup: %s\n", error.c_str());
        adb_close(outFd);
        return -1;
    }

    printf("Now unlock your device and confirm the backup operation.\n");
    copy_to_file(fd, outFd);

    adb_close(fd);
    adb_close(outFd);
    return 0;
}

static int restore(int argc, const char** argv) {
    if (argc != 2) return usage();

    const char* filename = argv[1];
    int tarFd = adb_open(filename, O_RDONLY);
    if (tarFd < 0) {
        fprintf(stderr, "adb: unable to open file %s: %s\n", filename, strerror(errno));
        return -1;
    }

    std::string error;
    int fd = adb_connect("restore:", &error);
    if (fd < 0) {
        fprintf(stderr, "adb: unable to connect for restore: %s\n", error.c_str());
        adb_close(tarFd);
        return -1;
    }

    printf("Now unlock your device and confirm the restore operation.\n");
    copy_to_file(tarFd, fd);

    adb_close(fd);
    adb_close(tarFd);
    return 0;
}

/* <hint> may be:
 * - A simple product name
 *   e.g., "sooner"
 * - A relative path from the CWD to the ANDROID_PRODUCT_OUT dir
 *   e.g., "out/target/product/sooner"
 * - An absolute path to the PRODUCT_OUT dir
 *   e.g., "/src/device/out/target/product/sooner"
 *
 * Given <hint>, try to construct an absolute path to the
 * ANDROID_PRODUCT_OUT dir.
 */
static std::string find_product_out_path(const std::string& hint) {
    if (hint.empty()) {
        return "";
    }

    // If it's already absolute, don't bother doing any work.
    if (adb_is_absolute_host_path(hint.c_str())) {
        return hint;
    }

    // If there are any slashes in it, assume it's a relative path;
    // make it absolute.
    if (hint.find_first_of(OS_PATH_SEPARATORS) != std::string::npos) {
        std::string cwd;
        if (!getcwd(&cwd)) {
            fprintf(stderr, "adb: getcwd failed: %s\n", strerror(errno));
            return "";
        }
        return android::base::StringPrintf("%s%c%s", cwd.c_str(), OS_PATH_SEPARATOR, hint.c_str());
    }

    // It's a string without any slashes.  Try to do something with it.
    //
    // Try to find the root of the build tree, and build a PRODUCT_OUT
    // path from there.
    char* top = getenv("ANDROID_BUILD_TOP");
    if (top == nullptr) {
        fprintf(stderr, "adb: ANDROID_BUILD_TOP not set!\n");
        return "";
    }

    std::string path = top;
    path += OS_PATH_SEPARATOR_STR;
    path += "out";
    path += OS_PATH_SEPARATOR_STR;
    path += "target";
    path += OS_PATH_SEPARATOR_STR;
    path += "product";
    path += OS_PATH_SEPARATOR_STR;
    path += hint;
    if (!directory_exists(path)) {
        fprintf(stderr, "adb: Couldn't find a product dir based on -p %s; "
                        "\"%s\" doesn't exist\n", hint.c_str(), path.c_str());
        return "";
    }
    return path;
}

static void parse_push_pull_args(const char** arg, int narg,
                                 std::vector<const char*>* srcs,
                                 const char** dst, bool* copy_attrs) {
    *copy_attrs = false;

    srcs->clear();
    bool ignore_flags = false;
    while (narg > 0) {
        if (ignore_flags || *arg[0] != '-') {
            srcs->push_back(*arg);
        } else {
            if (!strcmp(*arg, "-p")) {
                // Silently ignore for backwards compatibility.
            } else if (!strcmp(*arg, "-a")) {
                *copy_attrs = true;
            } else if (!strcmp(*arg, "--")) {
                ignore_flags = true;
            } else {
                fprintf(stderr, "adb: unrecognized option '%s'\n", *arg);
                exit(1);
            }
        }
        ++arg;
        --narg;
    }

    if (srcs->size() > 1) {
        *dst = srcs->back();
        srcs->pop_back();
    }
}

static int adb_connect_command(const std::string& command) {
    std::string error;
    int fd = adb_connect(command, &error);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return 1;
    }
    read_and_dump(fd);
    adb_close(fd);
    return 0;
}

static int adb_query_command(const std::string& command) {
    std::string result;
    std::string error;
    if (!adb_query(command, &result, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return 1;
    }
    printf("%s\n", result.c_str());
    return 0;
}

// Disallow stdin, stdout, and stderr.
static bool _is_valid_ack_reply_fd(const int ack_reply_fd) {
#ifdef _WIN32
    const HANDLE ack_reply_handle = cast_int_to_handle(ack_reply_fd);
    return (GetStdHandle(STD_INPUT_HANDLE) != ack_reply_handle) &&
           (GetStdHandle(STD_OUTPUT_HANDLE) != ack_reply_handle) &&
           (GetStdHandle(STD_ERROR_HANDLE) != ack_reply_handle);
#else
    return ack_reply_fd > 2;
#endif
}

int adb_commandline(int argc, const char **argv) {
    int no_daemon = 0;
    int is_daemon = 0;
    int is_server = 0;
    int r;
    TransportType transport_type = kTransportAny;
    int ack_reply_fd = -1;

    // If defined, this should be an absolute path to
    // the directory containing all of the various system images
    // for a particular product.  If not defined, and the adb
    // command requires this information, then the user must
    // specify the path using "-p".
    char* ANDROID_PRODUCT_OUT = getenv("ANDROID_PRODUCT_OUT");
    if (ANDROID_PRODUCT_OUT != nullptr) {
        gProductOutPath = ANDROID_PRODUCT_OUT;
    }
    // TODO: also try TARGET_PRODUCT/TARGET_DEVICE as a hint

    /* Validate and assign the server port */
    const char* server_port_str = getenv("ANDROID_ADB_SERVER_PORT");
    int server_port = DEFAULT_ADB_PORT;
    if (server_port_str && strlen(server_port_str) > 0) {
        server_port = strtol(server_port_str, nullptr, 0);
        if (server_port <= 0 || server_port > 65535) {
            fprintf(stderr,
                    "adb: Env var ANDROID_ADB_SERVER_PORT must be a positive number less than 65536. Got \"%s\"\n",
                    server_port_str);
            return usage();
        }
    }

    // We need to check for -d and -e before we look at $ANDROID_SERIAL.
    const char* serial = nullptr;

    while (argc > 0) {
        if (!strcmp(argv[0],"server")) {
            is_server = 1;
        } else if (!strcmp(argv[0],"nodaemon")) {
            no_daemon = 1;
        } else if (!strcmp(argv[0], "fork-server")) {
            /* this is a special flag used only when the ADB client launches the ADB Server */
            is_daemon = 1;
        } else if (!strcmp(argv[0], "--reply-fd")) {
            if (argc < 2) return usage();
            const char* reply_fd_str = argv[1];
            argc--;
            argv++;
            ack_reply_fd = strtol(reply_fd_str, nullptr, 10);
            if (!_is_valid_ack_reply_fd(ack_reply_fd)) {
                fprintf(stderr, "adb: invalid reply fd \"%s\"\n", reply_fd_str);
                return usage();
            }
        } else if (!strncmp(argv[0], "-p", 2)) {
            const char* product = nullptr;
            if (argv[0][2] == '\0') {
                if (argc < 2) return usage();
                product = argv[1];
                argc--;
                argv++;
            } else {
                product = argv[0] + 2;
            }
            gProductOutPath = find_product_out_path(product);
            if (gProductOutPath.empty()) {
                fprintf(stderr, "adb: could not resolve \"-p %s\"\n", product);
                return usage();
            }
        } else if (argv[0][0]=='-' && argv[0][1]=='s') {
            if (isdigit(argv[0][2])) {
                serial = argv[0] + 2;
            } else {
                if (argc < 2 || argv[0][2] != '\0') return usage();
                serial = argv[1];
                argc--;
                argv++;
            }
        } else if (!strcmp(argv[0],"-d")) {
            transport_type = kTransportUsb;
        } else if (!strcmp(argv[0],"-e")) {
            transport_type = kTransportLocal;
        } else if (!strcmp(argv[0],"-a")) {
            gListenAll = 1;
        } else if (!strncmp(argv[0], "-H", 2)) {
            const char *hostname = NULL;
            if (argv[0][2] == '\0') {
                if (argc < 2) return usage();
                hostname = argv[1];
                argc--;
                argv++;
            } else {
                hostname = argv[0] + 2;
            }
            adb_set_tcp_name(hostname);

        } else if (!strncmp(argv[0], "-P", 2)) {
            if (argv[0][2] == '\0') {
                if (argc < 2) return usage();
                server_port_str = argv[1];
                argc--;
                argv++;
            } else {
                server_port_str = argv[0] + 2;
            }
            if (strlen(server_port_str) > 0) {
                server_port = (int) strtol(server_port_str, NULL, 0);
                if (server_port <= 0 || server_port > 65535) {
                    fprintf(stderr,
                            "adb: port number must be a positive number less than 65536. Got \"%s\"\n",
                            server_port_str);
                    return usage();
                }
            } else {
                fprintf(stderr,
                "adb: port number must be a positive number less than 65536. Got empty string.\n");
                return usage();
            }
        } else {
                /* out of recognized modifiers and flags */
            break;
        }
        argc--;
        argv++;
    }

    // If none of -d, -e, or -s were specified, try $ANDROID_SERIAL.
    if (transport_type == kTransportAny && serial == nullptr) {
        serial = getenv("ANDROID_SERIAL");
    }

    adb_set_transport(transport_type, serial);
    adb_set_tcp_specifics(server_port);

    if (is_server) {
        if (no_daemon || is_daemon) {
            if (is_daemon && (ack_reply_fd == -1)) {
                fprintf(stderr, "reply fd for adb server to client communication not specified.\n");
                return usage();
            }
            r = adb_main(is_daemon, server_port, ack_reply_fd);
        } else {
            r = launch_server(server_port);
        }
        if (r) {
            fprintf(stderr,"* could not start server *\n");
        }
        return r;
    }

    if (argc == 0) {
        return usage();
    }

    /* handle wait-for-* prefix */
    if (!strncmp(argv[0], "wait-for-", strlen("wait-for-"))) {
        const char* service = argv[0];

        if (!wait_for_device(service, transport_type, serial)) {
            return 1;
        }

        // Allow a command to be run after wait-for-device,
        // e.g. 'adb wait-for-device shell'.
        if (argc == 1) {
            return 0;
        }

        /* Fall through */
        argc--;
        argv++;
    }

    /* adb_connect() commands */
    if (!strcmp(argv[0], "devices")) {
        const char *listopt;
        if (argc < 2) {
            listopt = "";
        } else if (argc == 2 && !strcmp(argv[1], "-l")) {
            listopt = argv[1];
        } else {
            fprintf(stderr, "Usage: adb devices [-l]\n");
            return 1;
        }

        std::string query = android::base::StringPrintf("host:%s%s", argv[0], listopt);
        printf("List of devices attached\n");
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "connect")) {
        if (argc != 2) {
            fprintf(stderr, "Usage: adb connect <host>[:<port>]\n");
            return 1;
        }

        std::string query = android::base::StringPrintf("host:connect:%s", argv[1]);
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "disconnect")) {
        if (argc > 2) {
            fprintf(stderr, "Usage: adb disconnect [<host>[:<port>]]\n");
            return 1;
        }

        std::string query = android::base::StringPrintf("host:disconnect:%s",
                                                        (argc == 2) ? argv[1] : "");
        return adb_query_command(query);
    }
    else if (!strcmp(argv[0], "emu")) {
        return adb_send_emulator_command(argc, argv, serial);
    }
    else if (!strcmp(argv[0], "shell")) {
        return adb_shell(argc, argv, transport_type, serial);
    }
    else if (!strcmp(argv[0], "exec-in") || !strcmp(argv[0], "exec-out")) {
        int exec_in = !strcmp(argv[0], "exec-in");

        std::string cmd = "exec:";
        cmd += argv[1];
        argc -= 2;
        argv += 2;
        while (argc-- > 0) {
            cmd += " " + escape_arg(*argv++);
        }

        std::string error;
        int fd = adb_connect(cmd, &error);
        if (fd < 0) {
            fprintf(stderr, "error: %s\n", error.c_str());
            return -1;
        }

        if (exec_in) {
            copy_to_file(STDIN_FILENO, fd);
        } else {
            copy_to_file(fd, STDOUT_FILENO);
        }

        adb_close(fd);
        return 0;
    }
    else if (!strcmp(argv[0], "kill-server")) {
        std::string error;
        int fd = _adb_connect("host:kill", &error);
        if (fd == -2) {
            // Failed to make network connection to server. Don't output the
            // network error since that is expected.
            fprintf(stderr,"* server not running *\n");
            // Successful exit code because the server is already "killed".
            return 0;
        } else if (fd == -1) {
            // Some other error.
            fprintf(stderr, "error: %s\n", error.c_str());
            return 1;
        } else {
            // Successfully connected, kill command sent, okay status came back.
            // Server should exit() in a moment, if not already.
            ReadOrderlyShutdown(fd);
            adb_close(fd);
            return 0;
        }
    }
    else if (!strcmp(argv[0], "sideload")) {
        if (argc != 2) return usage();
        if (adb_sideload_host(argv[1])) {
            return 1;
        } else {
            return 0;
        }
    }
    else if (!strcmp(argv[0], "tcpip") && argc > 1) {
        return adb_connect_command(android::base::StringPrintf("tcpip:%s", argv[1]));
    }
    else if (!strcmp(argv[0], "remount") ||
             !strcmp(argv[0], "reboot") ||
             !strcmp(argv[0], "reboot-bootloader") ||
             !strcmp(argv[0], "usb") ||
             !strcmp(argv[0], "root") ||
             !strcmp(argv[0], "unroot") ||
             !strcmp(argv[0], "disable-verity") ||
             !strcmp(argv[0], "enable-verity")) {
        std::string command;
        if (!strcmp(argv[0], "reboot-bootloader")) {
            command = "reboot:bootloader";
        } else if (argc > 1) {
            command = android::base::StringPrintf("%s:%s", argv[0], argv[1]);
        } else {
            command = android::base::StringPrintf("%s:", argv[0]);
        }
        return adb_connect_command(command);
    }
    else if (!strcmp(argv[0], "bugreport")) {
        if (argc != 1) return usage();
        // No need for shell protocol with bugreport, always disable for
        // simplicity.
        return send_shell_command(transport_type, serial, "bugreport", true);
    }
    else if (!strcmp(argv[0], "forward") || !strcmp(argv[0], "reverse")) {
        bool reverse = !strcmp(argv[0], "reverse");
        ++argv;
        --argc;
        if (argc < 1) return usage();

        // Determine the <host-prefix> for this command.
        std::string host_prefix;
        if (reverse) {
            host_prefix = "reverse";
        } else {
            if (serial) {
                host_prefix = android::base::StringPrintf("host-serial:%s", serial);
            } else if (transport_type == kTransportUsb) {
                host_prefix = "host-usb";
            } else if (transport_type == kTransportLocal) {
                host_prefix = "host-local";
            } else {
                host_prefix = "host";
            }
        }

        std::string cmd;
        if (strcmp(argv[0], "--list") == 0) {
            if (argc != 1) return usage();
            return adb_query_command(host_prefix + ":list-forward");
        } else if (strcmp(argv[0], "--remove-all") == 0) {
            if (argc != 1) return usage();
            cmd = host_prefix + ":killforward-all";
        } else if (strcmp(argv[0], "--remove") == 0) {
            // forward --remove <local>
            if (argc != 2) return usage();
            cmd = host_prefix + ":killforward:" + argv[1];
        } else if (strcmp(argv[0], "--no-rebind") == 0) {
            // forward --no-rebind <local> <remote>
            if (argc != 3) return usage();
            cmd = host_prefix + ":forward:norebind:" + argv[1] + ";" + argv[2];
        } else {
            // forward <local> <remote>
            if (argc != 2) return usage();
            cmd = host_prefix + ":forward:" + argv[0] + ";" + argv[1];
        }

        return adb_command(cmd) ? 0 : 1;
    }
    /* do_sync_*() commands */
    else if (!strcmp(argv[0], "ls")) {
        if (argc != 2) return usage();
        return do_sync_ls(argv[1]) ? 0 : 1;
    }
    else if (!strcmp(argv[0], "push")) {
        bool copy_attrs = false;
        std::vector<const char*> srcs;
        const char* dst = nullptr;

        parse_push_pull_args(&argv[1], argc - 1, &srcs, &dst, &copy_attrs);
        if (srcs.empty() || !dst) return usage();
        return do_sync_push(srcs, dst) ? 0 : 1;
    }
    else if (!strcmp(argv[0], "pull")) {
        bool copy_attrs = false;
        std::vector<const char*> srcs;
        const char* dst = ".";

        parse_push_pull_args(&argv[1], argc - 1, &srcs, &dst, &copy_attrs);
        if (srcs.empty()) return usage();
        return do_sync_pull(srcs, dst, copy_attrs) ? 0 : 1;
    }
    else if (!strcmp(argv[0], "install")) {
        if (argc < 2) return usage();
        FeatureSet features = GetFeatureSet(transport_type, serial);
        if (CanUseFeature(features, kFeatureCmd)) {
            return install_app(transport_type, serial, argc, argv);
        }
        return install_app_legacy(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0], "install-multiple")) {
        if (argc < 2) return usage();
        return install_multiple_app(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0], "uninstall")) {
        if (argc < 2) return usage();
        FeatureSet features = GetFeatureSet(transport_type, serial);
        if (CanUseFeature(features, kFeatureCmd)) {
            return uninstall_app(transport_type, serial, argc, argv);
        }
        return uninstall_app_legacy(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0], "sync")) {
        std::string src;
        bool list_only = false;
        if (argc < 2) {
            // No local path was specified.
            src = "";
        } else if (argc >= 2 && strcmp(argv[1], "-l") == 0) {
            list_only = true;
            if (argc == 3) {
                src = argv[2];
            } else {
                src = "";
            }
        } else if (argc == 2) {
            // A local path or "android"/"data" arg was specified.
            src = argv[1];
        } else {
            return usage();
        }

        if (src != "" &&
            src != "system" && src != "data" && src != "vendor" && src != "oem") {
            return usage();
        }

        std::string system_src_path = product_file("system");
        std::string data_src_path = product_file("data");
        std::string vendor_src_path = product_file("vendor");
        std::string oem_src_path = product_file("oem");

        bool okay = true;
        if (okay && (src.empty() || src == "system")) {
            okay = do_sync_sync(system_src_path, "/system", list_only);
        }
        if (okay && (src.empty() || src == "vendor") && directory_exists(vendor_src_path)) {
            okay = do_sync_sync(vendor_src_path, "/vendor", list_only);
        }
        if (okay && (src.empty() || src == "oem") && directory_exists(oem_src_path)) {
            okay = do_sync_sync(oem_src_path, "/oem", list_only);
        }
        if (okay && (src.empty() || src == "data")) {
            okay = do_sync_sync(data_src_path, "/data", list_only);
        }
        return okay ? 0 : 1;
    }
    /* passthrough commands */
    else if (!strcmp(argv[0],"get-state") ||
        !strcmp(argv[0],"get-serialno") ||
        !strcmp(argv[0],"get-devpath"))
    {
        return adb_query_command(format_host_command(argv[0], transport_type, serial));
    }
    /* other commands */
    else if (!strcmp(argv[0],"logcat") || !strcmp(argv[0],"lolcat") || !strcmp(argv[0],"longcat")) {
        return logcat(transport_type, serial, argc, argv);
    }
    else if (!strcmp(argv[0],"ppp")) {
        return ppp(argc, argv);
    }
    else if (!strcmp(argv[0], "start-server")) {
        std::string error;
        const int result = adb_connect("host:start-server", &error);
        if (result < 0) {
            fprintf(stderr, "error: %s\n", error.c_str());
        }
        return result;
    }
    else if (!strcmp(argv[0], "backup")) {
        return backup(argc, argv);
    }
    else if (!strcmp(argv[0], "restore")) {
        return restore(argc, argv);
    }
    else if (!strcmp(argv[0], "keygen")) {
        if (argc < 2) return usage();
        // Always print key generation information for keygen command.
        adb_trace_enable(AUTH);
        return adb_auth_keygen(argv[1]);
    }
    else if (!strcmp(argv[0], "jdwp")) {
        return adb_connect_command("jdwp");
    }
    /* "adb /?" is a common idiom under Windows */
    else if (!strcmp(argv[0], "help") || !strcmp(argv[0], "/?")) {
        help();
        return 0;
    }
    else if (!strcmp(argv[0], "version")) {
        fprintf(stdout, "%s", adb_version().c_str());
        return 0;
    }
    else if (!strcmp(argv[0], "features")) {
        // Only list the features common to both the adb client and the device.
        FeatureSet features = GetFeatureSet(transport_type, serial);
        for (const std::string& name : features) {
            if (CanUseFeature(features, name)) {
                printf("%s\n", name.c_str());
            }
        }
        return 0;
    }

    usage();
    return 1;
}

static int uninstall_app(TransportType transport, const char* serial, int argc, const char** argv) {
    // 'adb uninstall' takes the same arguments as 'cmd package uninstall' on device
    std::string cmd = "cmd package";
    while (argc-- > 0) {
        // deny the '-k' option until the remaining data/cache can be removed with adb/UI
        if (strcmp(*argv, "-k") == 0) {
            printf(
                "The -k option uninstalls the application while retaining the data/cache.\n"
                "At the moment, there is no way to remove the remaining data.\n"
                "You will have to reinstall the application with the same signature, and fully uninstall it.\n"
                "If you truly wish to continue, execute 'adb shell cmd package uninstall -k'.\n");
            return EXIT_FAILURE;
        }
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(transport, serial, cmd, false);
}

static int install_app(TransportType transport, const char* serial, int argc, const char** argv) {
    // The last argument must be the APK file
    const char* file = argv[argc - 1];
    const char* dot = strrchr(file, '.');
    bool found_apk = false;
    struct stat sb;
    if (dot && !strcasecmp(dot, ".apk")) {
        if (stat(file, &sb) == -1 || !S_ISREG(sb.st_mode)) {
            fprintf(stderr, "Invalid APK file: %s\n", file);
            return EXIT_FAILURE;
        }
        found_apk = true;
    }

    if (!found_apk) {
        fprintf(stderr, "Missing APK file\n");
        return EXIT_FAILURE;
    }

    int localFd = adb_open(file, O_RDONLY);
    if (localFd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", file, strerror(errno));
        return 1;
    }

    std::string error;
    std::string cmd = "exec:cmd package";

    // don't copy the APK name, but, copy the rest of the arguments as-is
    while (argc-- > 1) {
        cmd += " " + escape_arg(std::string(*argv++));
    }

    // add size parameter [required for streaming installs]
    // do last to override any user specified value
    cmd += " " + android::base::StringPrintf("-S %" PRIu64, static_cast<uint64_t>(sb.st_size));

    int remoteFd = adb_connect(cmd, &error);
    if (remoteFd < 0) {
        fprintf(stderr, "Connect error for write: %s\n", error.c_str());
        adb_close(localFd);
        return 1;
    }

    char buf[BUFSIZ];
    copy_to_file(localFd, remoteFd);
    read_status_line(remoteFd, buf, sizeof(buf));

    adb_close(localFd);
    adb_close(remoteFd);

    if (strncmp("Success", buf, 7)) {
        fprintf(stderr, "Failed to write %s\n", file);
        fputs(buf, stderr);
        return 1;
    }
    fputs(buf, stderr);
    return 0;
}

static int install_multiple_app(TransportType transport, const char* serial, int argc,
                                const char** argv)
{
    int i;
    struct stat sb;
    uint64_t total_size = 0;

    // Find all APK arguments starting at end.
    // All other arguments passed through verbatim.
    int first_apk = -1;
    for (i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];
        const char* dot = strrchr(file, '.');
        if (dot && !strcasecmp(dot, ".apk")) {
            if (stat(file, &sb) == -1 || !S_ISREG(sb.st_mode)) {
                fprintf(stderr, "Invalid APK file: %s\n", file);
                return EXIT_FAILURE;
            }

            total_size += sb.st_size;
            first_apk = i;
        } else {
            break;
        }
    }

    if (first_apk == -1) {
        fprintf(stderr, "Missing APK file\n");
        return 1;
    }

    std::string cmd = android::base::StringPrintf("exec:pm install-create -S %" PRIu64, total_size);
    for (i = 1; i < first_apk; i++) {
        cmd += " " + escape_arg(argv[i]);
    }

    // Create install session
    std::string error;
    int fd = adb_connect(cmd, &error);
    if (fd < 0) {
        fprintf(stderr, "Connect error for create: %s\n", error.c_str());
        return EXIT_FAILURE;
    }
    char buf[BUFSIZ];
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    int session_id = -1;
    if (!strncmp("Success", buf, 7)) {
        char* start = strrchr(buf, '[');
        char* end = strrchr(buf, ']');
        if (start && end) {
            *end = '\0';
            session_id = strtol(start + 1, NULL, 10);
        }
    }
    if (session_id < 0) {
        fprintf(stderr, "Failed to create session\n");
        fputs(buf, stderr);
        return EXIT_FAILURE;
    }

    // Valid session, now stream the APKs
    int success = 1;
    for (i = first_apk; i < argc; i++) {
        const char* file = argv[i];
        if (stat(file, &sb) == -1) {
            fprintf(stderr, "Failed to stat %s\n", file);
            success = 0;
            goto finalize_session;
        }

        std::string cmd = android::base::StringPrintf(
                "exec:pm install-write -S %" PRIu64 " %d %d_%s -",
                static_cast<uint64_t>(sb.st_size), session_id, i, adb_basename(file).c_str());

        int localFd = adb_open(file, O_RDONLY);
        if (localFd < 0) {
            fprintf(stderr, "Failed to open %s: %s\n", file, strerror(errno));
            success = 0;
            goto finalize_session;
        }

        std::string error;
        int remoteFd = adb_connect(cmd, &error);
        if (remoteFd < 0) {
            fprintf(stderr, "Connect error for write: %s\n", error.c_str());
            adb_close(localFd);
            success = 0;
            goto finalize_session;
        }

        copy_to_file(localFd, remoteFd);
        read_status_line(remoteFd, buf, sizeof(buf));

        adb_close(localFd);
        adb_close(remoteFd);

        if (strncmp("Success", buf, 7)) {
            fprintf(stderr, "Failed to write %s\n", file);
            fputs(buf, stderr);
            success = 0;
            goto finalize_session;
        }
    }

finalize_session:
    // Commit session if we streamed everything okay; otherwise abandon
    std::string service =
            android::base::StringPrintf("exec:pm install-%s %d",
                                        success ? "commit" : "abandon", session_id);
    fd = adb_connect(service, &error);
    if (fd < 0) {
        fprintf(stderr, "Connect error for finalize: %s\n", error.c_str());
        return EXIT_FAILURE;
    }
    read_status_line(fd, buf, sizeof(buf));
    adb_close(fd);

    if (!strncmp("Success", buf, 7)) {
        fputs(buf, stderr);
        return 0;
    } else {
        fprintf(stderr, "Failed to finalize session\n");
        fputs(buf, stderr);
        return EXIT_FAILURE;
    }
}

static int pm_command(TransportType transport, const char* serial, int argc, const char** argv) {
    std::string cmd = "pm";

    while (argc-- > 0) {
        cmd += " " + escape_arg(*argv++);
    }

    return send_shell_command(transport, serial, cmd, false);
}

static int uninstall_app_legacy(TransportType transport, const char* serial, int argc, const char** argv) {
    /* if the user choose the -k option, we refuse to do it until devices are
       out with the option to uninstall the remaining data somehow (adb/ui) */
    int i;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-k")) {
            printf(
                "The -k option uninstalls the application while retaining the data/cache.\n"
                "At the moment, there is no way to remove the remaining data.\n"
                "You will have to reinstall the application with the same signature, and fully uninstall it.\n"
                "If you truly wish to continue, execute 'adb shell pm uninstall -k'\n.");
            return EXIT_FAILURE;
        }
    }

    /* 'adb uninstall' takes the same arguments as 'pm uninstall' on device */
    return pm_command(transport, serial, argc, argv);
}

static int delete_file(TransportType transport, const char* serial, const std::string& filename) {
    std::string cmd = "rm -f " + escape_arg(filename);
    return send_shell_command(transport, serial, cmd, false);
}

static int install_app_legacy(TransportType transport, const char* serial, int argc, const char** argv) {
    static const char *const DATA_DEST = "/data/local/tmp/%s";
    static const char *const SD_DEST = "/sdcard/tmp/%s";
    const char* where = DATA_DEST;
    int i;
    struct stat sb;

    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-s")) {
            where = SD_DEST;
        }
    }

    // Find last APK argument.
    // All other arguments passed through verbatim.
    int last_apk = -1;
    for (i = argc - 1; i >= 0; i--) {
        const char* file = argv[i];
        const char* dot = strrchr(file, '.');
        if (dot && !strcasecmp(dot, ".apk")) {
            if (stat(file, &sb) == -1 || !S_ISREG(sb.st_mode)) {
                fprintf(stderr, "Invalid APK file: %s\n", file);
                return EXIT_FAILURE;
            }

            last_apk = i;
            break;
        }
    }

    if (last_apk == -1) {
        fprintf(stderr, "Missing APK file\n");
        return EXIT_FAILURE;
    }

    int result = -1;
    std::vector<const char*> apk_file = {argv[last_apk]};
    std::string apk_dest = android::base::StringPrintf(
        where, adb_basename(argv[last_apk]).c_str());
    if (!do_sync_push(apk_file, apk_dest.c_str())) goto cleanup_apk;
    argv[last_apk] = apk_dest.c_str(); /* destination name, not source location */
    result = pm_command(transport, serial, argc, argv);

cleanup_apk:
    delete_file(transport, serial, apk_dest);
    return result;
}

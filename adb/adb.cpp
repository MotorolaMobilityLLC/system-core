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

#define TRACE_TAG TRACE_ADB

#include "sysdeps.h"
#include "adb.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <string>
#include <vector>
#include <unordered_map>

#include <base/logging.h>
#include <base/macros.h>
#include <base/stringprintf.h>
#include <base/strings.h>

#include "adb_auth.h"
#include "adb_io.h"
#include "adb_listeners.h"
#include "adb_utils.h"
#include "transport.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if !ADB_HOST
#include <cutils/properties.h>
#include <sys/capability.h>
#include <sys/mount.h>
#endif

ADB_MUTEX_DEFINE(D_lock);

#if !ADB_HOST
const char* adb_device_banner = "device";
static android::base::LogdLogger gLogdLogger;
#endif

void AdbLogger(android::base::LogId id, android::base::LogSeverity severity,
               const char* tag, const char* file, unsigned int line,
               const char* message) {
    android::base::StderrLogger(id, severity, tag, file, line, message);
#if !ADB_HOST
    gLogdLogger(id, severity, tag, file, line, message);
#endif
}

std::string adb_version() {
    // Don't change the format of this --- it's parsed by ddmlib.
    return android::base::StringPrintf("Android Debug Bridge version %d.%d.%d\n"
                                       "Revision %s\n",
                                       ADB_VERSION_MAJOR, ADB_VERSION_MINOR, ADB_SERVER_VERSION,
                                       ADB_REVISION);
}

void fatal(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void fatal_errno(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: %s: ", strerror(errno));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

#if !ADB_HOST
static std::string get_log_file_name() {
    struct tm now;
    time_t t;
    tzset();
    time(&t);
    localtime_r(&t, &now);

    char timestamp[PATH_MAX];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d-%H-%M-%S", &now);

    return android::base::StringPrintf("/data/adb/adb-%s-%d", timestamp,
                                       getpid());
}

void start_device_log(void) {
    int fd = unix_open(get_log_file_name().c_str(),
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0640);
    if (fd == -1) {
        return;
    }

    // Redirect stdout and stderr to the log file.
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    fprintf(stderr, "--- adb starting (pid %d) ---\n", getpid());
    unix_close(fd);
}
#endif

int adb_trace_mask;

std::string get_trace_setting_from_env() {
    const char* setting = getenv("ADB_TRACE");
    if (setting == nullptr) {
        setting = "";
    }

    return std::string(setting);
}

#if !ADB_HOST
std::string get_trace_setting_from_prop() {
    char buf[PROPERTY_VALUE_MAX];
    property_get("persist.adb.trace_mask", buf, "");
    return std::string(buf);
}
#endif

std::string get_trace_setting() {
#if ADB_HOST
    return get_trace_setting_from_env();
#else
    return get_trace_setting_from_prop();
#endif
}

// Split the space separated list of tags from the trace setting and build the
// trace mask from it. note that '1' and 'all' are special cases to enable all
// tracing.
//
// adb's trace setting comes from the ADB_TRACE environment variable, whereas
// adbd's comes from the system property persist.adb.trace_mask.
static void setup_trace_mask() {
    const std::string trace_setting = get_trace_setting();

    std::unordered_map<std::string, int> trace_flags = {
        {"1", 0},
        {"all", 0},
        {"adb", TRACE_ADB},
        {"sockets", TRACE_SOCKETS},
        {"packets", TRACE_PACKETS},
        {"rwx", TRACE_RWX},
        {"usb", TRACE_USB},
        {"sync", TRACE_SYNC},
        {"sysdeps", TRACE_SYSDEPS},
        {"transport", TRACE_TRANSPORT},
        {"jdwp", TRACE_JDWP},
        {"services", TRACE_SERVICES},
        {"auth", TRACE_AUTH}};

    std::vector<std::string> elements = android::base::Split(trace_setting, " ");
    for (const auto& elem : elements) {
        const auto& flag = trace_flags.find(elem);
        if (flag == trace_flags.end()) {
            D("Unknown trace flag: %s\n", flag->first.c_str());
            continue;
        }

        if (flag->second == 0) {
            // 0 is used for the special values "1" and "all" that enable all
            // tracing.
            adb_trace_mask = ~0;
            return;
        } else {
            adb_trace_mask |= 1 << flag->second;
        }
    }
}

void adb_trace_init(char** argv) {
#if !ADB_HOST
    // Don't open log file if no tracing, since this will block
    // the crypto unmount of /data
    if (!get_trace_setting().empty()) {
        if (isatty(STDOUT_FILENO) == 0) {
            start_device_log();
        }
    }
#endif

    setup_trace_mask();
    android::base::InitLogging(argv, AdbLogger);

    D("%s", adb_version().c_str());
}

apacket* get_apacket(void)
{
    apacket* p = reinterpret_cast<apacket*>(malloc(sizeof(apacket)));
    if (p == nullptr) {
      fatal("failed to allocate an apacket");
    }

    memset(p, 0, sizeof(apacket) - MAX_PAYLOAD);
    return p;
}

void put_apacket(apacket *p)
{
    free(p);
}

void handle_online(atransport *t)
{
    D("adb: online\n");
    t->online = 1;
}

void handle_offline(atransport *t)
{
    D("adb: offline\n");
    //Close the associated usb
    t->online = 0;
    run_transport_disconnects(t);
}

#if DEBUG_PACKETS
#define DUMPMAX 32
void print_packet(const char *label, apacket *p)
{
    char *tag;
    char *x;
    unsigned count;

    switch(p->msg.command){
    case A_SYNC: tag = "SYNC"; break;
    case A_CNXN: tag = "CNXN" ; break;
    case A_OPEN: tag = "OPEN"; break;
    case A_OKAY: tag = "OKAY"; break;
    case A_CLSE: tag = "CLSE"; break;
    case A_WRTE: tag = "WRTE"; break;
    case A_AUTH: tag = "AUTH"; break;
    default: tag = "????"; break;
    }

    fprintf(stderr, "%s: %s %08x %08x %04x \"",
            label, tag, p->msg.arg0, p->msg.arg1, p->msg.data_length);
    count = p->msg.data_length;
    x = (char*) p->data;
    if(count > DUMPMAX) {
        count = DUMPMAX;
        tag = "\n";
    } else {
        tag = "\"\n";
    }
    while(count-- > 0){
        if((*x >= ' ') && (*x < 127)) {
            fputc(*x, stderr);
        } else {
            fputc('.', stderr);
        }
        x++;
    }
    fputs(tag, stderr);
}
#endif

static void send_ready(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_ready \n");
    apacket *p = get_apacket();
    p->msg.command = A_OKAY;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static void send_close(unsigned local, unsigned remote, atransport *t)
{
    D("Calling send_close \n");
    apacket *p = get_apacket();
    p->msg.command = A_CLSE;
    p->msg.arg0 = local;
    p->msg.arg1 = remote;
    send_packet(p, t);
}

static size_t fill_connect_data(char *buf, size_t bufsize)
{
#if ADB_HOST
    return snprintf(buf, bufsize, "host::") + 1;
#else
    static const char *cnxn_props[] = {
        "ro.product.name",
        "ro.product.model",
        "ro.product.device",
    };
    static const int num_cnxn_props = ARRAY_SIZE(cnxn_props);
    int i;
    size_t remaining = bufsize;
    size_t len;

    len = snprintf(buf, remaining, "%s::", adb_device_banner);
    remaining -= len;
    buf += len;
    for (i = 0; i < num_cnxn_props; i++) {
        char value[PROPERTY_VALUE_MAX];
        property_get(cnxn_props[i], value, "");
        len = snprintf(buf, remaining, "%s=%s;", cnxn_props[i], value);
        remaining -= len;
        buf += len;
    }

    return bufsize - remaining + 1;
#endif
}

void send_connect(atransport *t)
{
    D("Calling send_connect \n");
    apacket *cp = get_apacket();
    cp->msg.command = A_CNXN;
    cp->msg.arg0 = t->get_protocol_version();
    cp->msg.arg1 = t->get_max_payload();
    cp->msg.data_length = fill_connect_data((char *)cp->data,
                                            MAX_PAYLOAD_V1);
    send_packet(cp, t);
}

// qual_overwrite is used to overwrite a qualifier string.  dst is a
// pointer to a char pointer.  It is assumed that if *dst is non-NULL, it
// was malloc'ed and needs to freed.  *dst will be set to a dup of src.
// TODO: switch to std::string for these atransport fields instead.
static void qual_overwrite(char** dst, const std::string& src) {
    free(*dst);
    *dst = strdup(src.c_str());
}

void parse_banner(const char* banner, atransport* t) {
    D("parse_banner: %s\n", banner);

    // The format is something like:
    // "device::ro.product.name=x;ro.product.model=y;ro.product.device=z;".
    std::vector<std::string> pieces = android::base::Split(banner, ":");

    if (pieces.size() > 2) {
        const std::string& props = pieces[2];
        for (auto& prop : android::base::Split(props, ";")) {
            // The list of properties was traditionally ;-terminated rather than ;-separated.
            if (prop.empty()) continue;

            std::vector<std::string> key_value = android::base::Split(prop, "=");
            if (key_value.size() != 2) continue;

            const std::string& key = key_value[0];
            const std::string& value = key_value[1];
            if (key == "ro.product.name") {
                qual_overwrite(&t->product, value);
            } else if (key == "ro.product.model") {
                qual_overwrite(&t->model, value);
            } else if (key == "ro.product.device") {
                qual_overwrite(&t->device, value);
            }
        }
    }

    const std::string& type = pieces[0];
    if (type == "bootloader") {
        D("setting connection_state to kCsBootloader\n");
        t->connection_state = kCsBootloader;
        update_transports();
    } else if (type == "device") {
        D("setting connection_state to kCsDevice\n");
        t->connection_state = kCsDevice;
        update_transports();
    } else if (type == "recovery") {
        D("setting connection_state to kCsRecovery\n");
        t->connection_state = kCsRecovery;
        update_transports();
    } else if (type == "sideload") {
        D("setting connection_state to kCsSideload\n");
        t->connection_state = kCsSideload;
        update_transports();
    } else {
        D("setting connection_state to kCsHost\n");
        t->connection_state = kCsHost;
    }
}

void handle_packet(apacket *p, atransport *t)
{
    asocket *s;

    D("handle_packet() %c%c%c%c\n", ((char*) (&(p->msg.command)))[0],
            ((char*) (&(p->msg.command)))[1],
            ((char*) (&(p->msg.command)))[2],
            ((char*) (&(p->msg.command)))[3]);
    print_packet("recv", p);

    switch(p->msg.command){
    case A_SYNC:
        if(p->msg.arg0){
            send_packet(p, t);
#if ADB_HOST
            send_connect(t);
#endif
        } else {
            t->connection_state = kCsOffline;
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN: /* CONNECT(version, maxdata, "system-id-string") */
        if(t->connection_state != kCsOffline) {
            t->connection_state = kCsOffline;
            handle_offline(t);
        }

        t->update_version(p->msg.arg0, p->msg.arg1);
        parse_banner(reinterpret_cast<const char*>(p->data), t);

#if ADB_HOST
        handle_online(t);
#else
        if (!auth_required) {
            handle_online(t);
            send_connect(t);
        } else {
            send_auth_request(t);
        }
#endif
        break;

    case A_AUTH:
        if (p->msg.arg0 == ADB_AUTH_TOKEN) {
            t->connection_state = kCsUnauthorized;
            t->key = adb_auth_nextkey(t->key);
            if (t->key) {
                send_auth_response(p->data, p->msg.data_length, t);
            } else {
                /* No more private keys to try, send the public key */
                send_auth_publickey(t);
            }
        } else if (p->msg.arg0 == ADB_AUTH_SIGNATURE) {
            if (adb_auth_verify(t->token, p->data, p->msg.data_length)) {
                adb_auth_verified(t);
                t->failed_auth_attempts = 0;
            } else {
                if (t->failed_auth_attempts++ > 10)
                    adb_sleep_ms(1000);
                send_auth_request(t);
            }
        } else if (p->msg.arg0 == ADB_AUTH_RSAPUBLICKEY) {
            adb_auth_confirm_key(p->data, p->msg.data_length, t);
        }
        break;

    case A_OPEN: /* OPEN(local-id, 0, "destination") */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 == 0) {
            char *name = (char*) p->data;
            name[p->msg.data_length > 0 ? p->msg.data_length - 1 : 0] = 0;
            s = create_local_service_socket(name);
            if(s == 0) {
                send_close(0, p->msg.arg0, t);
            } else {
                s->peer = create_remote_socket(p->msg.arg0, t);
                s->peer->peer = s;
                send_ready(s->id, s->peer->id, t);
                s->ready(s);
            }
        }
        break;

    case A_OKAY: /* READY(local-id, remote-id, "") */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            if((s = find_local_socket(p->msg.arg1, 0))) {
                if(s->peer == 0) {
                    /* On first READY message, create the connection. */
                    s->peer = create_remote_socket(p->msg.arg0, t);
                    s->peer->peer = s;
                    s->ready(s);
                } else if (s->peer->id == p->msg.arg0) {
                    /* Other READY messages must use the same local-id */
                    s->ready(s);
                } else {
                    D("Invalid A_OKAY(%d,%d), expected A_OKAY(%d,%d) on transport %s\n",
                      p->msg.arg0, p->msg.arg1, s->peer->id, p->msg.arg1, t->serial);
                }
            }
        }
        break;

    case A_CLSE: /* CLOSE(local-id, remote-id, "") or CLOSE(0, remote-id, "") */
        if (t->online && p->msg.arg1 != 0) {
            if((s = find_local_socket(p->msg.arg1, p->msg.arg0))) {
                /* According to protocol.txt, p->msg.arg0 might be 0 to indicate
                 * a failed OPEN only. However, due to a bug in previous ADB
                 * versions, CLOSE(0, remote-id, "") was also used for normal
                 * CLOSE() operations.
                 *
                 * This is bad because it means a compromised adbd could
                 * send packets to close connections between the host and
                 * other devices. To avoid this, only allow this if the local
                 * socket has a peer on the same transport.
                 */
                if (p->msg.arg0 == 0 && s->peer && s->peer->transport != t) {
                    D("Invalid A_CLSE(0, %u) from transport %s, expected transport %s\n",
                      p->msg.arg1, t->serial, s->peer->transport->serial);
                } else {
                    s->close(s);
                }
            }
        }
        break;

    case A_WRTE: /* WRITE(local-id, remote-id, <data>) */
        if (t->online && p->msg.arg0 != 0 && p->msg.arg1 != 0) {
            if((s = find_local_socket(p->msg.arg1, p->msg.arg0))) {
                unsigned rid = p->msg.arg0;
                p->len = p->msg.data_length;

                if(s->enqueue(s, p) == 0) {
                    D("Enqueue the socket\n");
                    send_ready(s->id, rid, t);
                }
                return;
            }
        }
        break;

    default:
        printf("handle_packet: what is %08x?!\n", p->msg.command);
    }

    put_apacket(p);
}

#if ADB_HOST

int launch_server(int server_port)
{
#if defined(_WIN32)
    /* we need to start the server in the background                    */
    /* we create a PIPE that will be used to wait for the server's "OK" */
    /* message since the pipe handles must be inheritable, we use a     */
    /* security attribute                                               */
    HANDLE                nul_read, nul_write;
    HANDLE                pipe_read, pipe_write;
    HANDLE                stdout_handle, stderr_handle;
    SECURITY_ATTRIBUTES   sa;
    STARTUPINFOW          startup;
    PROCESS_INFORMATION   pinfo;
    WCHAR                 program_path[ MAX_PATH ];
    int                   ret;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    /* Redirect stdin and stderr to Windows /dev/null. If we instead pass our
     * stdin/stderr handles and they are console handles, when the adb server
     * starts up, the C Runtime will see console handles for a process that
     * isn't connected to a console and it will configure stderr to be closed.
     * At that point, freopen() could be used to reopen stderr, but it would
     * take more massaging to fixup the file descriptor number that freopen()
     * uses. It's simplest to avoid all of this complexity by just redirecting
     * stdin/stderr to `nul' and then the C Runtime acts as expected.
     */
    nul_read = CreateFileW(L"nul", GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (nul_read == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileW(nul, GENERIC_READ) failed: %s\n",
                SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    nul_write = CreateFileW(L"nul", GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (nul_write == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "CreateFileW(nul, GENERIC_WRITE) failed: %s\n",
                SystemErrorCodeToString(GetLastError()).c_str());
        CloseHandle(nul_read);
        return -1;
    }

    /* create pipe, and ensure its read handle isn't inheritable */
    ret = CreatePipe( &pipe_read, &pipe_write, &sa, 0 );
    if (!ret) {
        fprintf(stderr, "CreatePipe() failed: %s\n",
                SystemErrorCodeToString(GetLastError()).c_str());
        CloseHandle(nul_read);
        CloseHandle(nul_write);
        return -1;
    }

    SetHandleInformation( pipe_read, HANDLE_FLAG_INHERIT, 0 );

    /* Some programs want to launch an adb command and collect its output by
     * calling CreateProcess with inheritable stdout/stderr handles, then
     * using read() to get its output. When this happens, the stdout/stderr
     * handles passed to the adb client process will also be inheritable.
     * When starting the adb server here, care must be taken to reset them
     * to non-inheritable.
     * Otherwise, something bad happens: even if the adb command completes,
     * the calling process is stuck while read()-ing from the stdout/stderr
     * descriptors, because they're connected to corresponding handles in the
     * adb server process (even if the latter never uses/writes to them).
     */
    stdout_handle = GetStdHandle( STD_OUTPUT_HANDLE );
    stderr_handle = GetStdHandle( STD_ERROR_HANDLE );
    if (stdout_handle != INVALID_HANDLE_VALUE) {
        SetHandleInformation( stdout_handle, HANDLE_FLAG_INHERIT, 0 );
    }
    if (stderr_handle != INVALID_HANDLE_VALUE) {
        SetHandleInformation( stderr_handle, HANDLE_FLAG_INHERIT, 0 );
    }

    ZeroMemory( &startup, sizeof(startup) );
    startup.cb = sizeof(startup);
    startup.hStdInput  = nul_read;
    startup.hStdOutput = nul_write;
    startup.hStdError  = nul_write;
    startup.dwFlags    = STARTF_USESTDHANDLES;

    ZeroMemory( &pinfo, sizeof(pinfo) );

    /* get path of current program */
    DWORD module_result = GetModuleFileNameW(NULL, program_path,
                                             arraysize(program_path));
    if ((module_result == arraysize(program_path)) || (module_result == 0)) {
        // String truncation or some other error.
        fprintf(stderr, "GetModuleFileNameW() failed: %s\n",
                SystemErrorCodeToString(GetLastError()).c_str());
        return -1;
    }

    // Verify that the pipe_write handle value can be passed on the command line
    // as %d and that the rest of adb code can pass it around in an int.
    const int pipe_write_as_int = cast_handle_to_int(pipe_write);
    if (cast_int_to_handle(pipe_write_as_int) != pipe_write) {
        // If this fires, either handle values are larger than 32-bits or else
        // there is a bug in our casting.
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa384203%28v=vs.85%29.aspx
        fprintf(stderr, "CreatePipe handle value too large: 0x%p\n",
                pipe_write);
        return -1;
    }

    WCHAR args[64];
    snwprintf(args, arraysize(args),
              L"adb -P %d fork-server server --reply-fd %d", server_port,
              pipe_write_as_int);
    ret = CreateProcessW(
            program_path,                              /* program path  */
            args,
                                    /* the fork-server argument will set the
                                       debug = 2 in the child           */
            NULL,                   /* process handle is not inheritable */
            NULL,                    /* thread handle is not inheritable */
            TRUE,                          /* yes, inherit some handles */
            DETACHED_PROCESS, /* the new process doesn't have a console */
            NULL,                     /* use parent's environment block */
            NULL,                    /* use parent's starting directory */
            &startup,                 /* startup info, i.e. std handles */
            &pinfo );

    CloseHandle( nul_read );
    CloseHandle( nul_write );
    CloseHandle( pipe_write );

    if (!ret) {
        fprintf(stderr, "CreateProcess failed: %s\n",
                SystemErrorCodeToString(GetLastError()).c_str());
        CloseHandle( pipe_read );
        return -1;
    }

    CloseHandle( pinfo.hProcess );
    CloseHandle( pinfo.hThread );

    /* wait for the "OK\n" message */
    {
        char  temp[3];
        DWORD  count;

        ret = ReadFile( pipe_read, temp, 3, &count, NULL );
        CloseHandle( pipe_read );
        if ( !ret ) {
            fprintf(stderr, "could not read ok from ADB Server, error: %s\n",
                    SystemErrorCodeToString(GetLastError()).c_str());
            return -1;
        }
        if (count != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "ADB server didn't ACK\n" );
            return -1;
        }
    }
#else /* !defined(_WIN32) */
    char    path[PATH_MAX];
    int     fd[2];

    // set up a pipe so the child can tell us when it is ready.
    // fd[0] will be parent's end, and the child will write on fd[1]
    if (pipe(fd)) {
        fprintf(stderr, "pipe failed in launch_server, errno: %d\n", errno);
        return -1;
    }
    get_my_path(path, PATH_MAX);
    pid_t pid = fork();
    if(pid < 0) return -1;

    if (pid == 0) {
        // child side of the fork

        adb_close(fd[0]);

        char str_port[30];
        snprintf(str_port, sizeof(str_port), "%d", server_port);
        char reply_fd[30];
        snprintf(reply_fd, sizeof(reply_fd), "%d", fd[1]);
        // child process
        int result = execl(path, "adb", "-P", str_port, "fork-server", "server", "--reply-fd", reply_fd, NULL);
        // this should not return
        fprintf(stderr, "OOPS! execl returned %d, errno: %d\n", result, errno);
    } else  {
        // parent side of the fork

        char  temp[3];

        temp[0] = 'A'; temp[1] = 'B'; temp[2] = 'C';
        // wait for the "OK\n" message
        adb_close(fd[1]);
        int ret = adb_read(fd[0], temp, 3);
        int saved_errno = errno;
        adb_close(fd[0]);
        if (ret < 0) {
            fprintf(stderr, "could not read ok from ADB Server, errno = %d\n", saved_errno);
            return -1;
        }
        if (ret != 3 || temp[0] != 'O' || temp[1] != 'K' || temp[2] != '\n') {
            fprintf(stderr, "ADB server didn't ACK\n" );
            return -1;
        }

        setsid();
    }
#endif /* !defined(_WIN32) */
    return 0;
}
#endif /* ADB_HOST */

// Try to handle a network forwarding request.
// This returns 1 on success, 0 on failure, and -1 to indicate this is not
// a forwarding-related request.
int handle_forward_request(const char* service, TransportType type, const char* serial, int reply_fd)
{
    if (!strcmp(service, "list-forward")) {
        // Create the list of forward redirections.
        std::string listeners = format_listeners();
#if ADB_HOST
        SendOkay(reply_fd);
#endif
        SendProtocolString(reply_fd, listeners);
        return 1;
    }

    if (!strcmp(service, "killforward-all")) {
        remove_all_listeners();
#if ADB_HOST
        /* On the host: 1st OKAY is connect, 2nd OKAY is status */
        SendOkay(reply_fd);
#endif
        SendOkay(reply_fd);
        return 1;
    }

    if (!strncmp(service, "forward:", 8) || !strncmp(service, "killforward:", 12)) {
        // killforward:local
        // forward:(norebind:)?local;remote
        bool kill_forward = false;
        bool no_rebind = false;
        if (android::base::StartsWith(service, "killforward:")) {
            kill_forward = true;
            service += 12;
        } else {
            service += 8;   // skip past "forward:"
            if (android::base::StartsWith(service, "norebind:")) {
                no_rebind = true;
                service += 9;
            }
        }

        std::vector<std::string> pieces = android::base::Split(service, ";");

        if (kill_forward) {
            // Check killforward: parameter format: '<local>'
            if (pieces.size() != 1 || pieces[0].empty()) {
                SendFail(reply_fd, android::base::StringPrintf("bad killforward: %s", service));
                return 1;
            }
        } else {
            // Check forward: parameter format: '<local>;<remote>'
            if (pieces.size() != 2 || pieces[0].empty() || pieces[1].empty() || pieces[1][0] == '*') {
                SendFail(reply_fd, android::base::StringPrintf("bad forward: %s", service));
                return 1;
            }
        }

        std::string error_msg;
        atransport* transport = acquire_one_transport(kCsAny, type, serial, &error_msg);
        if (!transport) {
            SendFail(reply_fd, error_msg);
            return 1;
        }

        std::string error;
        InstallStatus r;
        if (kill_forward) {
            r = remove_listener(pieces[0].c_str(), transport);
        } else {
            r = install_listener(pieces[0], pieces[1].c_str(), transport,
                                 no_rebind, &error);
        }
        if (r == INSTALL_STATUS_OK) {
#if ADB_HOST
            /* On the host: 1st OKAY is connect, 2nd OKAY is status */
            SendOkay(reply_fd);
#endif
            SendOkay(reply_fd);
            return 1;
        }

        std::string message;
        switch (r) {
          case INSTALL_STATUS_OK: message = "success (!)"; break;
          case INSTALL_STATUS_INTERNAL_ERROR: message = "internal error"; break;
          case INSTALL_STATUS_CANNOT_BIND:
            message = android::base::StringPrintf("cannot bind listener: %s",
                                                  error.c_str());
            break;
          case INSTALL_STATUS_CANNOT_REBIND:
            message = android::base::StringPrintf("cannot rebind existing socket");
            break;
          case INSTALL_STATUS_LISTENER_NOT_FOUND:
            message = android::base::StringPrintf("listener '%s' not found", service);
            break;
        }
        SendFail(reply_fd, message);
        return 1;
    }
    return 0;
}

#if ADB_HOST
static int SendOkay(int fd, const std::string& s) {
    SendOkay(fd);
    SendProtocolString(fd, s);
    return 0;
}
#endif

int handle_host_request(const char* service, TransportType type,
                        const char* serial, int reply_fd, asocket* s) {
    if (strcmp(service, "kill") == 0) {
        fprintf(stderr, "adb server killed by remote request\n");
        fflush(stdout);
        SendOkay(reply_fd);

        // At least on Windows, if we exit() without shutdown(SD_SEND) or
        // closesocket(), the client's next recv() will error-out with
        // WSAECONNRESET and they'll never read the OKAY.
        adb_shutdown(reply_fd);

        exit(0);
    }

#if ADB_HOST
    // "transport:" is used for switching transport with a specified serial number
    // "transport-usb:" is used for switching transport to the only USB transport
    // "transport-local:" is used for switching transport to the only local transport
    // "transport-any:" is used for switching transport to the only transport
    if (!strncmp(service, "transport", strlen("transport"))) {
        TransportType type = kTransportAny;

        if (!strncmp(service, "transport-usb", strlen("transport-usb"))) {
            type = kTransportUsb;
        } else if (!strncmp(service, "transport-local", strlen("transport-local"))) {
            type = kTransportLocal;
        } else if (!strncmp(service, "transport-any", strlen("transport-any"))) {
            type = kTransportAny;
        } else if (!strncmp(service, "transport:", strlen("transport:"))) {
            service += strlen("transport:");
            serial = service;
        }

        std::string error_msg;
        atransport* t = acquire_one_transport(kCsAny, type, serial, &error_msg);
        if (t != nullptr) {
            s->transport = t;
            SendOkay(reply_fd);
        } else {
            SendFail(reply_fd, error_msg);
        }
        return 1;
    }

    // return a list of all connected devices
    if (!strncmp(service, "devices", 7)) {
        bool long_listing = (strcmp(service+7, "-l") == 0);
        if (long_listing || service[7] == 0) {
            D("Getting device list...\n");
            std::string device_list = list_transports(long_listing);
            D("Sending device list...\n");
            return SendOkay(reply_fd, device_list);
        }
        return 1;
    }

    // remove TCP transport
    if (!strncmp(service, "disconnect:", 11)) {
        const std::string address(service + 11);
        if (address.empty()) {
            // disconnect from all TCP devices
            unregister_all_tcp_transports();
            return SendOkay(reply_fd, "disconnected everything");
        }

        std::string serial;
        std::string host;
        int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
        std::string error;
        if (!parse_host_and_port(address, &serial, &host, &port, &error)) {
            return SendFail(reply_fd, android::base::StringPrintf("couldn't parse '%s': %s",
                                                                  address.c_str(), error.c_str()));
        }
        atransport* t = find_transport(serial.c_str());
        if (t == nullptr) {
            return SendFail(reply_fd, android::base::StringPrintf("no such device '%s'",
                                                                  serial.c_str()));
        }
        unregister_transport(t);
        return SendOkay(reply_fd, android::base::StringPrintf("disconnected %s", address.c_str()));
    }

    // returns our value for ADB_SERVER_VERSION
    if (!strcmp(service, "version")) {
        return SendOkay(reply_fd, android::base::StringPrintf("%04x", ADB_SERVER_VERSION));
    }

    // These always report "unknown" rather than the actual error, for scripts.
    if (!strcmp(service, "get-serialno")) {
        std::string ignored;
        atransport* t = acquire_one_transport(kCsAny, type, serial, &ignored);
        return SendOkay(reply_fd, (t && t->serial) ? t->serial : "unknown");
    }
    if (!strcmp(service, "get-devpath")) {
        std::string ignored;
        atransport* t = acquire_one_transport(kCsAny, type, serial, &ignored);
        return SendOkay(reply_fd, (t && t->devpath) ? t->devpath : "unknown");
    }
    if (!strcmp(service, "get-state")) {
        std::string ignored;
        atransport* t = acquire_one_transport(kCsAny, type, serial, &ignored);
        return SendOkay(reply_fd, t ? t->connection_state_name() : "unknown");
    }

    // indicates a new emulator instance has started
    if (!strncmp(service, "emulator:", 9)) {
        int  port = atoi(service+9);
        local_connect(port);
        /* we don't even need to send a reply */
        return 0;
    }
#endif // ADB_HOST

    int ret = handle_forward_request(service, type, serial, reply_fd);
    if (ret >= 0)
      return ret - 1;
    return -1;
}

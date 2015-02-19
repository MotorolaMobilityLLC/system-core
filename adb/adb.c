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

#define  TRACE_TAG   TRACE_ADB

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdint.h>

#include "sysdeps.h"
#include "adb.h"
#include "adb_auth.h"
#include "adb_listeners.h"
#include "qemu_tracing.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#if !ADB_HOST
#include <cutils/properties.h>
#include <private/android_filesystem_config.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <getopt.h>
#include <selinux/selinux.h>
#endif

#if ADB_TRACE
ADB_MUTEX_DEFINE( D_lock );
#endif

int HOST = 0;

static int auth_enabled = 0;

#if !ADB_HOST
static const char *adb_device_banner = "device";
static const char *root_seclabel = NULL;
#endif

void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

void fatal_errno(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "error: %s: ", strerror(errno));
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
    exit(-1);
}

int   adb_trace_mask;

/* read a comma/space/colum/semi-column separated list of tags
 * from the ADB_TRACE environment variable and build the trace
 * mask from it. note that '1' and 'all' are special cases to
 * enable all tracing
 */
void  adb_trace_init(void)
{
    const char*  p = getenv("ADB_TRACE");
    const char*  q;

    static const struct {
        const char*  tag;
        int           flag;
    } tags[] = {
        { "1", 0 },
        { "all", 0 },
        { "adb", TRACE_ADB },
        { "sockets", TRACE_SOCKETS },
        { "packets", TRACE_PACKETS },
        { "rwx", TRACE_RWX },
        { "usb", TRACE_USB },
        { "sync", TRACE_SYNC },
        { "sysdeps", TRACE_SYSDEPS },
        { "transport", TRACE_TRANSPORT },
        { "jdwp", TRACE_JDWP },
        { "services", TRACE_SERVICES },
        { "auth", TRACE_AUTH },
        { NULL, 0 }
    };

    if (p == NULL)
            return;

    /* use a comma/column/semi-colum/space separated list */
    while (*p) {
        int  len, tagn;

        q = strpbrk(p, " ,:;");
        if (q == NULL) {
            q = p + strlen(p);
        }
        len = q - p;

        for (tagn = 0; tags[tagn].tag != NULL; tagn++)
        {
            int  taglen = strlen(tags[tagn].tag);

            if (len == taglen && !memcmp(tags[tagn].tag, p, len) )
            {
                int  flag = tags[tagn].flag;
                if (flag == 0) {
                    adb_trace_mask = ~0;
                    return;
                }
                adb_trace_mask |= (1 << flag);
                break;
            }
        }
        p = q;
        if (*p)
            p++;
    }
}

apacket *get_apacket(void)
{
    apacket *p = malloc(sizeof(apacket));
    if(p == 0) fatal("failed to allocate an apacket");
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

#if !ADB_HOST
static void send_msg_with_header(int fd, const char* msg, size_t msglen) {
    char header[5];
    if (msglen > 0xffff)
        msglen = 0xffff;
    snprintf(header, sizeof(header), "%04x", (unsigned)msglen);
    writex(fd, header, 4);
    writex(fd, msg, msglen);
}
#endif

#if ADB_HOST
static void send_msg_with_okay(int fd, const char* msg, size_t msglen) {
    char header[9];
    if (msglen > 0xffff)
        msglen = 0xffff;
    snprintf(header, sizeof(header), "OKAY%04x", (unsigned)msglen);
    writex(fd, header, 8);
    writex(fd, msg, msglen);
}
#endif // ADB_HOST

void send_connect(atransport *t)
{
    D("Calling send_connect \n");
    apacket *cp = get_apacket();
    cp->msg.command = A_CNXN;
    cp->msg.arg0 = A_VERSION;
    cp->msg.arg1 = MAX_PAYLOAD;
    cp->msg.data_length = fill_connect_data((char *)cp->data,
                                            sizeof(cp->data));
    send_packet(cp, t);
}

#if ADB_HOST
static char *connection_state_name(atransport *t)
{
    if (t == NULL) {
        return "unknown";
    }

    switch(t->connection_state) {
    case CS_BOOTLOADER:
        return "bootloader";
    case CS_DEVICE:
        return "device";
    case CS_RECOVERY:
        return "recovery";
    case CS_SIDELOAD:
        return "sideload";
    case CS_OFFLINE:
        return "offline";
    case CS_UNAUTHORIZED:
        return "unauthorized";
    default:
        return "unknown";
    }
}
#endif // ADB_HOST

/* qual_overwrite is used to overwrite a qualifier string.  dst is a
 * pointer to a char pointer.  It is assumed that if *dst is non-NULL, it
 * was malloc'ed and needs to freed.  *dst will be set to a dup of src.
 */
static void qual_overwrite(char **dst, const char *src)
{
    if (!dst)
        return;

    free(*dst);
    *dst = NULL;

    if (!src || !*src)
        return;

    *dst = strdup(src);
}

void parse_banner(char *banner, atransport *t)
{
    static const char *prop_seps = ";";
    static const char key_val_sep = '=';
    char *cp;
    char *type;

    D("parse_banner: %s\n", banner);
    type = banner;
    cp = strchr(type, ':');
    if (cp) {
        *cp++ = 0;
        /* Nothing is done with second field. */
        cp = strchr(cp, ':');
        if (cp) {
            char *save;
            char *key;
            key = adb_strtok_r(cp + 1, prop_seps, &save);
            while (key) {
                cp = strchr(key, key_val_sep);
                if (cp) {
                    *cp++ = '\0';
                    if (!strcmp(key, "ro.product.name"))
                        qual_overwrite(&t->product, cp);
                    else if (!strcmp(key, "ro.product.model"))
                        qual_overwrite(&t->model, cp);
                    else if (!strcmp(key, "ro.product.device"))
                        qual_overwrite(&t->device, cp);
                }
                key = adb_strtok_r(NULL, prop_seps, &save);
            }
        }
    }

    if(!strcmp(type, "bootloader")){
        D("setting connection_state to CS_BOOTLOADER\n");
        t->connection_state = CS_BOOTLOADER;
        update_transports();
        return;
    }

    if(!strcmp(type, "device")) {
        D("setting connection_state to CS_DEVICE\n");
        t->connection_state = CS_DEVICE;
        update_transports();
        return;
    }

    if(!strcmp(type, "recovery")) {
        D("setting connection_state to CS_RECOVERY\n");
        t->connection_state = CS_RECOVERY;
        update_transports();
        return;
    }

    if(!strcmp(type, "sideload")) {
        D("setting connection_state to CS_SIDELOAD\n");
        t->connection_state = CS_SIDELOAD;
        update_transports();
        return;
    }

    t->connection_state = CS_HOST;
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
            if(HOST) send_connect(t);
        } else {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
            send_packet(p, t);
        }
        return;

    case A_CNXN: /* CONNECT(version, maxdata, "system-id-string") */
            /* XXX verify version, etc */
        if(t->connection_state != CS_OFFLINE) {
            t->connection_state = CS_OFFLINE;
            handle_offline(t);
        }

        parse_banner((char*) p->data, t);

        if (HOST || !auth_enabled) {
            handle_online(t);
            if(!HOST) send_connect(t);
        } else {
            send_auth_request(t);
        }
        break;

    case A_AUTH:
        if (p->msg.arg0 == ADB_AUTH_TOKEN) {
            t->connection_state = CS_UNAUTHORIZED;
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

#if defined(_WIN32)
static BOOL WINAPI ctrlc_handler(DWORD type)
{
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}
#endif

static void adb_cleanup(void)
{
    usb_cleanup();
}

void start_logging(void)
{
#if defined(_WIN32)
    char    temp[ MAX_PATH ];
    FILE*   fnul;
    FILE*   flog;

    GetTempPath( sizeof(temp) - 8, temp );
    strcat( temp, "adb.log" );

    /* Win32 specific redirections */
    fnul = fopen( "NUL", "rt" );
    if (fnul != NULL)
        stdin[0] = fnul[0];

    flog = fopen( temp, "at" );
    if (flog == NULL)
        flog = fnul;

    setvbuf( flog, NULL, _IONBF, 0 );

    stdout[0] = flog[0];
    stderr[0] = flog[0];
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
#else
    int fd;

    fd = unix_open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    adb_close(fd);

    fd = unix_open("/tmp/adb.log", O_WRONLY | O_CREAT | O_APPEND, 0640);
    if(fd < 0) {
        fd = unix_open("/dev/null", O_WRONLY);
    }
    dup2(fd, 1);
    dup2(fd, 2);
    adb_close(fd);
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
#endif
}

#if !ADB_HOST
void start_device_log(void)
{
    int fd;
    char    path[PATH_MAX];
    struct tm now;
    time_t t;
    char value[PROPERTY_VALUE_MAX];

    // read the trace mask from persistent property persist.adb.trace_mask
    // give up if the property is not set or cannot be parsed
    property_get("persist.adb.trace_mask", value, "");
    if (sscanf(value, "%x", &adb_trace_mask) != 1)
        return;

    adb_mkdir("/data/adb", 0775);
    tzset();
    time(&t);
    localtime_r(&t, &now);
    strftime(path, sizeof(path),
                "/data/adb/adb-%Y-%m-%d-%H-%M-%S.txt",
                &now);
    fd = unix_open(path, O_WRONLY | O_CREAT | O_TRUNC, 0640);
    if (fd < 0)
        return;

    // redirect stdout and stderr to the log file
    dup2(fd, 1);
    dup2(fd, 2);
    fprintf(stderr,"--- adb starting (pid %d) ---\n", getpid());
    adb_close(fd);

    fd = unix_open("/dev/null", O_RDONLY);
    dup2(fd, 0);
    adb_close(fd);
}
#endif

#if ADB_HOST

#ifdef WORKAROUND_BUG6558362
#include <sched.h>
#define AFFINITY_ENVVAR "ADB_CPU_AFFINITY_BUG6558362"
void adb_set_affinity(void)
{
   cpu_set_t cpu_set;
   const char* cpunum_str = getenv(AFFINITY_ENVVAR);
   char* strtol_res;
   int cpu_num;

   if (!cpunum_str || !*cpunum_str)
       return;
   cpu_num = strtol(cpunum_str, &strtol_res, 0);
   if (*strtol_res != '\0')
     fatal("bad number (%s) in env var %s. Expecting 0..n.\n", cpunum_str, AFFINITY_ENVVAR);

   sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
   D("orig cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);
   CPU_ZERO(&cpu_set);
   CPU_SET(cpu_num, &cpu_set);
   sched_setaffinity(0, sizeof(cpu_set), &cpu_set);
   sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
   D("new cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);
}
#endif

int launch_server(int server_port)
{
#if defined(_WIN32)
    /* we need to start the server in the background                    */
    /* we create a PIPE that will be used to wait for the server's "OK" */
    /* message since the pipe handles must be inheritable, we use a     */
    /* security attribute                                               */
    HANDLE                pipe_read, pipe_write;
    HANDLE                stdout_handle, stderr_handle;
    SECURITY_ATTRIBUTES   sa;
    STARTUPINFO           startup;
    PROCESS_INFORMATION   pinfo;
    char                  program_path[ MAX_PATH ];
    int                   ret;

    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;

    /* create pipe, and ensure its read handle isn't inheritable */
    ret = CreatePipe( &pipe_read, &pipe_write, &sa, 0 );
    if (!ret) {
        fprintf(stderr, "CreatePipe() failure, error %ld\n", GetLastError() );
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
    startup.hStdInput  = GetStdHandle( STD_INPUT_HANDLE );
    startup.hStdOutput = pipe_write;
    startup.hStdError  = GetStdHandle( STD_ERROR_HANDLE );
    startup.dwFlags    = STARTF_USESTDHANDLES;

    ZeroMemory( &pinfo, sizeof(pinfo) );

    /* get path of current program */
    GetModuleFileName( NULL, program_path, sizeof(program_path) );
    char args[64];
    snprintf(args, sizeof(args), "adb -P %d fork-server server",  server_port);
    ret = CreateProcess(
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

    CloseHandle( pipe_write );

    if (!ret) {
        fprintf(stderr, "CreateProcess failure, error %ld\n", GetLastError() );
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
            fprintf(stderr, "could not read ok from ADB Server, error = %ld\n", GetLastError() );
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
    // fd[0] will be parent's end, and fd[1] will get mapped to stderr in the child.
    if (pipe(fd)) {
        fprintf(stderr, "pipe failed in launch_server, errno: %d\n", errno);
        return -1;
    }
    get_my_path(path, PATH_MAX);
    pid_t pid = fork();
    if(pid < 0) return -1;

    if (pid == 0) {
        // child side of the fork

        // redirect stderr to the pipe
        // we use stderr instead of stdout due to stdout's buffering behavior.
        adb_close(fd[0]);
        dup2(fd[1], STDERR_FILENO);
        adb_close(fd[1]);

        char str_port[30];
        snprintf(str_port, sizeof(str_port), "%d",  server_port);
        // child process
        int result = execl(path, "adb", "-P", str_port, "fork-server", "server", NULL);
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

/* Constructs a local name of form tcp:port.
 * target_str points to the target string, it's content will be overwritten.
 * target_size is the capacity of the target string.
 * server_port is the port number to use for the local name.
 */
void build_local_name(char* target_str, size_t target_size, int server_port)
{
  snprintf(target_str, target_size, "tcp:%d", server_port);
}

#if !ADB_HOST

static void drop_capabilities_bounding_set_if_needed() {
#ifdef ALLOW_ADBD_ROOT
    char value[PROPERTY_VALUE_MAX];
    property_get("ro.debuggable", value, "");
    if (strcmp(value, "1") == 0) {
        return;
    }
#endif
    int i;
    for (i = 0; prctl(PR_CAPBSET_READ, i, 0, 0, 0) >= 0; i++) {
        if (i == CAP_SETUID || i == CAP_SETGID) {
            // CAP_SETUID CAP_SETGID needed by /system/bin/run-as
            continue;
        }
        int err = prctl(PR_CAPBSET_DROP, i, 0, 0, 0);

        // Some kernels don't have file capabilities compiled in, and
        // prctl(PR_CAPBSET_DROP) returns EINVAL. Don't automatically
        // die when we see such misconfigured kernels.
        if ((err < 0) && (errno != EINVAL)) {
            exit(1);
        }
    }
}

static bool should_drop_privileges() {
#if defined(ALLOW_ADBD_ROOT)
    char value[PROPERTY_VALUE_MAX];

    // The emulator is never secure, so don't drop privileges there.
    // TODO: this seems like a bug --- shouldn't the emulator behave like a device?
    property_get("ro.kernel.qemu", value, "");
    if (strcmp(value, "1") == 0) {
        return false;
    }

    property_get("ro.secure", value, "1");
    bool ro_secure = (strcmp(value, "1") == 0);

    // Drop privileges if ro.secure is set...
    bool drop = ro_secure;

    property_get("ro.debuggable", value, "");
    bool ro_debuggable = (strcmp(value, "1") == 0);
    property_get("service.adb.root", value, "");
    bool adb_root = (strcmp(value, "1") == 0);
    bool adb_unroot = (strcmp(value, "0") == 0);

    // ...except "adb root" lets you keep privileges in a debuggable build.
    if (ro_debuggable && adb_root) {
        drop = false;
    }

    // ...and "adb unroot" lets you explicitly drop privileges.
    if (adb_unroot) {
        drop = true;
    }

    return drop;
#else
    return true; // "adb root" not allowed, always drop privileges.
#endif /* ALLOW_ADBD_ROOT */
}
#endif /* !ADB_HOST */

int adb_main(int is_daemon, int server_port)
{
#if !ADB_HOST
    int port;
    char value[PROPERTY_VALUE_MAX];

    umask(000);
#endif

    atexit(adb_cleanup);
#if defined(_WIN32)
    SetConsoleCtrlHandler( ctrlc_handler, TRUE );
#else
    // No SIGCHLD. Let the service subproc handle its children.
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();

#if ADB_HOST
    HOST = 1;

#ifdef WORKAROUND_BUG6558362
    if(is_daemon) adb_set_affinity();
#endif
    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    adb_auth_init();

    char local_name[30];
    build_local_name(local_name, sizeof(local_name), server_port);
    if(install_listener(local_name, "*smartsocket*", NULL, 0)) {
        exit(1);
    }
#else
    property_get("ro.adb.secure", value, "0");
    auth_enabled = !strcmp(value, "1");
    if (auth_enabled)
        adb_auth_init();

    // Our external storage path may be different than apps, since
    // we aren't able to bind mount after dropping root.
    const char* adb_external_storage = getenv("ADB_EXTERNAL_STORAGE");
    if (NULL != adb_external_storage) {
        setenv("EXTERNAL_STORAGE", adb_external_storage, 1);
    } else {
        D("Warning: ADB_EXTERNAL_STORAGE is not set.  Leaving EXTERNAL_STORAGE"
          " unchanged.\n");
    }

    /* add extra groups:
    ** AID_ADB to access the USB driver
    ** AID_LOG to read system logs (adb logcat)
    ** AID_INPUT to diagnose input issues (getevent)
    ** AID_INET to diagnose network issues (ping)
    ** AID_NET_BT and AID_NET_BT_ADMIN to diagnose bluetooth (hcidump)
    ** AID_SDCARD_R to allow reading from the SD card
    ** AID_SDCARD_RW to allow writing to the SD card
    ** AID_NET_BW_STATS to read out qtaguid statistics
    */
    gid_t groups[] = { AID_ADB, AID_LOG, AID_INPUT, AID_INET, AID_NET_BT,
                       AID_NET_BT_ADMIN, AID_SDCARD_R, AID_SDCARD_RW,
                       AID_NET_BW_STATS };
    if (setgroups(sizeof(groups)/sizeof(groups[0]), groups) != 0) {
        exit(1);
    }

    /* don't listen on a port (default 5037) if running in secure mode */
    /* don't run as root if we are running in secure mode */
    if (should_drop_privileges()) {
        drop_capabilities_bounding_set_if_needed();

        /* then switch user and group to "shell" */
        if (setgid(AID_SHELL) != 0) {
            exit(1);
        }
        if (setuid(AID_SHELL) != 0) {
            exit(1);
        }

        D("Local port disabled\n");
    } else {
        char local_name[30];
        if ((root_seclabel != NULL) && (is_selinux_enabled() > 0)) {
            // b/12587913: fix setcon to allow const pointers
            if (setcon((char *)root_seclabel) < 0) {
                exit(1);
            }
        }
        build_local_name(local_name, sizeof(local_name), server_port);
        if(install_listener(local_name, "*smartsocket*", NULL, 0)) {
            exit(1);
        }
    }

    int usb = 0;
    if (access(USB_ADB_PATH, F_OK) == 0 || access(USB_FFS_ADB_EP0, F_OK) == 0) {
        // listen on USB
        usb_init();
        usb = 1;
    }

    // If one of these properties is set, also listen on that port
    // If one of the properties isn't set and we couldn't listen on usb,
    // listen on the default port.
    property_get("service.adb.tcp.port", value, "");
    if (!value[0]) {
        property_get("persist.adb.tcp.port", value, "");
    }
    if (sscanf(value, "%d", &port) == 1 && port > 0) {
        printf("using port=%d\n", port);
        // listen on TCP port specified by service.adb.tcp.port property
        local_init(port);
    } else if (!usb) {
        // listen on default port
        local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    }

    D("adb_main(): pre init_jdwp()\n");
    init_jdwp();
    D("adb_main(): post init_jdwp()\n");
#endif

    if (is_daemon)
    {
        // inform our parent that we are up and running.
#if defined(_WIN32)
        DWORD  count;
        WriteFile( GetStdHandle( STD_OUTPUT_HANDLE ), "OK\n", 3, &count, NULL );
#else
        fprintf(stderr, "OK\n");
#endif
        start_logging();
    }
    D("Event loop starting\n");

    fdevent_loop();

    usb_cleanup();

    return 0;
}

// Try to handle a network forwarding request.
// This returns 1 on success, 0 on failure, and -1 to indicate this is not
// a forwarding-related request.
int handle_forward_request(const char* service, transport_type ttype, char* serial, int reply_fd)
{
    if (!strcmp(service, "list-forward")) {
        // Create the list of forward redirections.
        int buffer_size = format_listeners(NULL, 0);
        // Add one byte for the trailing zero.
        char* buffer = malloc(buffer_size + 1);
        if (buffer == NULL) {
            sendfailmsg(reply_fd, "not enough memory");
            return 1;
        }
        (void) format_listeners(buffer, buffer_size + 1);
#if ADB_HOST
        send_msg_with_okay(reply_fd, buffer, buffer_size);
#else
        send_msg_with_header(reply_fd, buffer, buffer_size);
#endif
        free(buffer);
        return 1;
    }

    if (!strcmp(service, "killforward-all")) {
        remove_all_listeners();
#if ADB_HOST
        /* On the host: 1st OKAY is connect, 2nd OKAY is status */
        adb_write(reply_fd, "OKAY", 4);
#endif
        adb_write(reply_fd, "OKAY", 4);
        return 1;
    }

    if (!strncmp(service, "forward:",8) ||
        !strncmp(service, "killforward:",12)) {
        char *local, *remote, *err;
        int r;
        atransport *transport;

        int createForward = strncmp(service, "kill", 4);
        int no_rebind = 0;

        local = strchr(service, ':') + 1;

        // Handle forward:norebind:<local>... here
        if (createForward && !strncmp(local, "norebind:", 9)) {
            no_rebind = 1;
            local = strchr(local, ':') + 1;
        }

        remote = strchr(local,';');

        if (createForward) {
            // Check forward: parameter format: '<local>;<remote>'
            if(remote == 0) {
                sendfailmsg(reply_fd, "malformed forward spec");
                return 1;
            }

            *remote++ = 0;
            if((local[0] == 0) || (remote[0] == 0) || (remote[0] == '*')) {
                sendfailmsg(reply_fd, "malformed forward spec");
                return 1;
            }
        } else {
            // Check killforward: parameter format: '<local>'
            if (local[0] == 0) {
                sendfailmsg(reply_fd, "malformed forward spec");
                return 1;
            }
        }

        transport = acquire_one_transport(CS_ANY, ttype, serial, &err);
        if (!transport) {
            sendfailmsg(reply_fd, err);
            return 1;
        }

        if (createForward) {
            r = install_listener(local, remote, transport, no_rebind);
        } else {
            r = remove_listener(local, transport);
        }
        if(r == 0) {
#if ADB_HOST
            /* On the host: 1st OKAY is connect, 2nd OKAY is status */
            writex(reply_fd, "OKAY", 4);
#endif
            writex(reply_fd, "OKAY", 4);
            return 1;
        }

        if (createForward) {
            const char* message;
            switch (r) {
              case INSTALL_STATUS_CANNOT_BIND:
                message = "cannot bind to socket";
                break;
              case INSTALL_STATUS_CANNOT_REBIND:
                message = "cannot rebind existing socket";
                break;
              default:
                message = "internal error";
            }
            sendfailmsg(reply_fd, message);
        } else {
            sendfailmsg(reply_fd, "cannot remove listener");
        }
        return 1;
    }
    return 0;
}

int handle_host_request(char *service, transport_type ttype, char* serial, int reply_fd, asocket *s)
{
    if(!strcmp(service, "kill")) {
        fprintf(stderr,"adb server killed by remote request\n");
        fflush(stdout);
        adb_write(reply_fd, "OKAY", 4);
        usb_cleanup();
        exit(0);
    }

#if ADB_HOST
    atransport *transport = NULL;
    // "transport:" is used for switching transport with a specified serial number
    // "transport-usb:" is used for switching transport to the only USB transport
    // "transport-local:" is used for switching transport to the only local transport
    // "transport-any:" is used for switching transport to the only transport
    if (!strncmp(service, "transport", strlen("transport"))) {
        char* error_string = "unknown failure";
        transport_type type = kTransportAny;

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

        transport = acquire_one_transport(CS_ANY, type, serial, &error_string);

        if (transport) {
            s->transport = transport;
            adb_write(reply_fd, "OKAY", 4);
        } else {
            sendfailmsg(reply_fd, error_string);
        }
        return 1;
    }

    // return a list of all connected devices
    if (!strncmp(service, "devices", 7)) {
        char buffer[4096];
        int use_long = !strcmp(service+7, "-l");
        if (use_long || service[7] == 0) {
            memset(buffer, 0, sizeof(buffer));
            D("Getting device list \n");
            list_transports(buffer, sizeof(buffer), use_long);
            D("Wrote device list \n");
            send_msg_with_okay(reply_fd, buffer, strlen(buffer));
            return 0;
        }
    }

    // remove TCP transport
    if (!strncmp(service, "disconnect:", 11)) {
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        char* serial = service + 11;
        if (serial[0] == 0) {
            // disconnect from all TCP devices
            unregister_all_tcp_transports();
        } else {
            char hostbuf[100];
            // assume port 5555 if no port is specified
            if (!strchr(serial, ':')) {
                snprintf(hostbuf, sizeof(hostbuf) - 1, "%s:5555", serial);
                serial = hostbuf;
            }
            atransport *t = find_transport(serial);

            if (t) {
                unregister_transport(t);
            } else {
                snprintf(buffer, sizeof(buffer), "No such device %s", serial);
            }
        }

        send_msg_with_okay(reply_fd, buffer, strlen(buffer));
        return 0;
    }

    // returns our value for ADB_SERVER_VERSION
    if (!strcmp(service, "version")) {
        char version[12];
        snprintf(version, sizeof version, "%04x", ADB_SERVER_VERSION);
        send_msg_with_okay(reply_fd, version, strlen(version));
        return 0;
    }

    if(!strncmp(service,"get-serialno",strlen("get-serialno"))) {
        char *out = "unknown";
         transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
       if (transport && transport->serial) {
            out = transport->serial;
        }
        send_msg_with_okay(reply_fd, out, strlen(out));
        return 0;
    }
    if(!strncmp(service,"get-devpath",strlen("get-devpath"))) {
        char *out = "unknown";
         transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
       if (transport && transport->devpath) {
            out = transport->devpath;
        }
        send_msg_with_okay(reply_fd, out, strlen(out));
        return 0;
    }
    // indicates a new emulator instance has started
    if (!strncmp(service,"emulator:",9)) {
        int  port = atoi(service+9);
        local_connect(port);
        /* we don't even need to send a reply */
        return 0;
    }

    if(!strncmp(service,"get-state",strlen("get-state"))) {
        transport = acquire_one_transport(CS_ANY, ttype, serial, NULL);
        char *state = connection_state_name(transport);
        send_msg_with_okay(reply_fd, state, strlen(state));
        return 0;
    }
#endif // ADB_HOST

    int ret = handle_forward_request(service, ttype, serial, reply_fd);
    if (ret >= 0)
      return ret - 1;
    return -1;
}

int main(int argc, char **argv)
{
#if ADB_HOST
    adb_sysdeps_init();
    adb_trace_init();
    D("Handling commandline()\n");
    return adb_commandline(argc - 1, argv + 1);
#else
    /* If adbd runs inside the emulator this will enable adb tracing via
     * adb-debug qemud service in the emulator. */
    adb_qemu_trace_init();
    while(1) {
        int c;
        int option_index = 0;
        static struct option opts[] = {
            {"root_seclabel", required_argument, 0, 's' },
            {"device_banner", required_argument, 0, 'b' }
        };
        c = getopt_long(argc, argv, "", opts, &option_index);
        if (c == -1)
            break;
        switch (c) {
        case 's':
            root_seclabel = optarg;
            break;
        case 'b':
            adb_device_banner = optarg;
            break;
        default:
            break;
        }
    }

    start_device_log();
    D("Handling main()\n");
    return adb_main(0, DEFAULT_ADB_PORT);
#endif
}

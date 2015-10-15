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

/* this file contains system-dependent definitions used by ADB
 * they're related to threads, sockets and file descriptors
 */
#ifndef _ADB_SYSDEPS_H
#define _ADB_SYSDEPS_H

#ifdef __CYGWIN__
#  undef _WIN32
#endif

#include <errno.h>

#include <string>

/*
 * TEMP_FAILURE_RETRY is defined by some, but not all, versions of
 * <unistd.h>. (Alas, it is not as standard as we'd hoped!) So, if it's
 * not already defined, then define it here.
 */
#ifndef TEMP_FAILURE_RETRY
/* Used to retry syscalls that can return EINTR. */
#define TEMP_FAILURE_RETRY(exp) ({         \
    typeof (exp) _rc;                      \
    do {                                   \
        _rc = (exp);                       \
    } while (_rc == -1 && errno == EINTR); \
    _rc; })
#endif

// Some printf-like functions are implemented in terms of
// android::base::StringAppendV, so they should use the same attribute for
// compile-time format string checking. On Windows, if the mingw version of
// vsnprintf is used in StringAppendV, use `gnu_printf' which allows z in %zd
// and PRIu64 (and related) to be recognized by the compile-time checking.
#define ADB_FORMAT_ARCHETYPE __printf__
#ifdef __USE_MINGW_ANSI_STDIO
#if __USE_MINGW_ANSI_STDIO
#undef ADB_FORMAT_ARCHETYPE
#define ADB_FORMAT_ARCHETYPE gnu_printf
#endif
#endif

#ifdef _WIN32

#include <ctype.h>
#include <direct.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>
#include <utime.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include <memory>   // unique_ptr
#include <string>   // Prototypes for narrow() and widen() use std::(w)string.

#include "fdevent.h"

#define OS_PATH_SEPARATORS "\\/"
#define OS_PATH_SEPARATOR '\\'
#define OS_PATH_SEPARATOR_STR "\\"
#define ENV_PATH_SEPARATOR_STR ";"

typedef CRITICAL_SECTION          adb_mutex_t;

#define  ADB_MUTEX_DEFINE(x)     adb_mutex_t   x

/* declare all mutexes */
/* For win32, adb_sysdeps_init() will do the mutex runtime initialization. */
#define  ADB_MUTEX(x)   extern adb_mutex_t  x;
#include "mutex_list.h"

extern void  adb_sysdeps_init(void);

static __inline__ void adb_mutex_lock( adb_mutex_t*  lock )
{
    EnterCriticalSection( lock );
}

static __inline__ void  adb_mutex_unlock( adb_mutex_t*  lock )
{
    LeaveCriticalSection( lock );
}

typedef  void*  (*adb_thread_func_t)(void*  arg);

typedef  void (*win_thread_func_t)(void*  arg);

static __inline__ bool adb_thread_create(adb_thread_func_t func, void* arg) {
    uintptr_t tid = _beginthread((win_thread_func_t)func, 0, arg);
    return (tid != static_cast<uintptr_t>(-1L));
}

static __inline__ int adb_thread_setname(const std::string& name) {
    // TODO: See https://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx for how to set
    // the thread name in Windows. Unfortunately, it only works during debugging, but
    // our build process doesn't generate PDB files needed for debugging.
    return 0;
}

static __inline__  unsigned long adb_thread_id()
{
    return GetCurrentThreadId();
}

static __inline__ void  close_on_exec(int  fd)
{
    /* nothing really */
}

#define  lstat    stat   /* no symlinks on Win32 */

#define  S_ISLNK(m)   0   /* no symlinks on Win32 */

extern int  adb_unlink(const char*  path);
#undef  unlink
#define unlink  ___xxx_unlink

extern int adb_mkdir(const std::string& path, int mode);
#undef   mkdir
#define  mkdir  ___xxx_mkdir

// See the comments for the !defined(_WIN32) versions of adb_*().
extern int  adb_open(const char*  path, int  options);
extern int  adb_creat(const char*  path, int  mode);
extern int  adb_read(int  fd, void* buf, int len);
extern int  adb_write(int  fd, const void*  buf, int  len);
extern int  adb_lseek(int  fd, int  pos, int  where);
extern int  adb_shutdown(int  fd);
extern int  adb_close(int  fd);

// See the comments for the !defined(_WIN32) version of unix_close().
static __inline__ int  unix_close(int fd)
{
    return close(fd);
}
#undef   close
#define  close   ____xxx_close

// See the comments for the !defined(_WIN32) version of unix_read().
extern int  unix_read(int  fd, void*  buf, size_t  len);

#undef   read
#define  read  ___xxx_read

// See the comments for the !defined(_WIN32) version of unix_write().
static __inline__  int  unix_write(int  fd, const void*  buf, size_t  len)
{
    return write(fd, buf, len);
}
#undef   write
#define  write  ___xxx_write

// See the comments for the !defined(_WIN32) version of adb_open_mode().
static __inline__ int  adb_open_mode(const char* path, int options, int mode)
{
    return adb_open(path, options);
}

// See the comments for the !defined(_WIN32) version of unix_open().
extern int unix_open(const char* path, int options, ...);
#define  open    ___xxx_unix_open


/* normally provided by <cutils/misc.h> */
extern void*  load_file(const char*  pathname, unsigned*  psize);

/* normally provided by "fdevent.h" */

#define FDE_READ              0x0001
#define FDE_WRITE             0x0002
#define FDE_ERROR             0x0004
#define FDE_DONT_CLOSE        0x0080

typedef void (*fd_func)(int fd, unsigned events, void *userdata);

fdevent *fdevent_create(int fd, fd_func func, void *arg);
void     fdevent_destroy(fdevent *fde);
void     fdevent_install(fdevent *fde, int fd, fd_func func, void *arg);
void     fdevent_remove(fdevent *item);
void     fdevent_set(fdevent *fde, unsigned events);
void     fdevent_add(fdevent *fde, unsigned events);
void     fdevent_del(fdevent *fde, unsigned events);
void     fdevent_loop();

static __inline__ void  adb_sleep_ms( int  mseconds )
{
    Sleep( mseconds );
}

int network_loopback_client(int port, int type, std::string* error);
int network_loopback_server(int port, int type, std::string* error);
int network_inaddr_any_server(int port, int type, std::string* error);
int network_connect(const std::string& host, int port, int type, int timeout,
                    std::string* error);

extern int  adb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen);

#undef   accept
#define  accept  ___xxx_accept

extern int  adb_setsockopt(int  fd, int  level, int  optname, const void*  optval, socklen_t  optlen);

#undef   setsockopt
#define  setsockopt  ___xxx_setsockopt

static __inline__  int  adb_socket_setbufsize( int   fd, int  bufsize )
{
    int opt = bufsize;
    return adb_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (const void*)&opt, sizeof(opt));
}

static __inline__ void  disable_tcp_nagle( int  fd )
{
    int  on = 1;
    adb_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const void*)&on, sizeof(on));
}

extern int  adb_socketpair( int  sv[2] );

static __inline__ int adb_is_absolute_host_path(const char* path) {
    return isalpha(path[0]) && path[1] == ':' && path[2] == '\\';
}

// Like strerror(), but for Win32 error codes.
std::string SystemErrorCodeToString(DWORD error_code);

// We later define a macro mapping 'stat' to 'adb_stat'. This causes:
//   struct stat s;
//   stat(filename, &s);
// To turn into the following:
//   struct adb_stat s;
//   adb_stat(filename, &s);
// To get this to work, we need to make 'struct adb_stat' the same as
// 'struct stat'. Note that this definition of 'struct adb_stat' uses the
// *current* macro definition of stat, so it may actually be inheriting from
// struct _stat32i64 (or some other remapping).
struct adb_stat : public stat {};

static_assert(sizeof(struct adb_stat) == sizeof(struct stat),
    "structures should be the same");

extern int adb_stat(const char* f, struct adb_stat* s);

// stat is already a macro, undefine it so we can redefine it.
#undef stat
#define stat adb_stat

// UTF-8 versions of POSIX APIs.
extern DIR* adb_opendir(const char* dirname);
extern struct dirent* adb_readdir(DIR* dir);
extern int adb_closedir(DIR* dir);

extern int adb_utime(const char *, struct utimbuf *);
extern int adb_chmod(const char *, int);

extern int adb_vfprintf(FILE *stream, const char *format, va_list ap)
    __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 2, 0)));
extern int adb_fprintf(FILE *stream, const char *format, ...)
    __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 2, 3)));
extern int adb_printf(const char *format, ...)
    __attribute__((__format__(ADB_FORMAT_ARCHETYPE, 1, 2)));

extern int adb_fputs(const char* buf, FILE* stream);
extern int adb_fputc(int ch, FILE* stream);
extern size_t adb_fwrite(const void* ptr, size_t size, size_t nmemb,
                         FILE* stream);

extern FILE* adb_fopen(const char* f, const char* m);

extern char* adb_getenv(const char* name);

extern char* adb_getcwd(char* buf, int size);

// Remap calls to POSIX APIs to our UTF-8 versions.
#define opendir adb_opendir
#define readdir adb_readdir
#define closedir adb_closedir
#define rewinddir rewinddir_utf8_not_yet_implemented
#define telldir telldir_utf8_not_yet_implemented
#define seekdir seekdir_utf8_not_yet_implemented

#define utime adb_utime
#define chmod adb_chmod

#define vfprintf adb_vfprintf
#define fprintf adb_fprintf
#define printf adb_printf
#define fputs adb_fputs
#define fputc adb_fputc
#define fwrite adb_fwrite

#define fopen adb_fopen

#define getenv adb_getenv
#define putenv putenv_utf8_not_yet_implemented
#define setenv setenv_utf8_not_yet_implemented
#define unsetenv unsetenv_utf8_not_yet_implemented

#define getcwd adb_getcwd

// Convert from UTF-8 to UTF-16, typically used to convert char strings into
// wchar_t strings that can be passed to wchar_t-based OS and C Runtime APIs
// on Windows.
extern std::wstring widen(const std::string& utf8);
extern std::wstring widen(const char* utf8);

// Convert from UTF-16 to UTF-8, typically used to convert strings from OS and
// C Runtime APIs that return wchar_t, to a format for our char-based data
// structures.
extern std::string narrow(const std::wstring& utf16);
extern std::string narrow(const wchar_t* utf16);

// Helper class to convert UTF-16 argv from wmain() to UTF-8 args that can be
// passed to main().
class NarrowArgs {
public:
    NarrowArgs(int argc, wchar_t** argv);
    ~NarrowArgs();

    inline char** data() {
        return narrow_args;
    }

private:
    char** narrow_args;
};

// Windows HANDLE values only use 32-bits of the type, even on 64-bit machines,
// so they can fit in an int. To convert back, we just need to sign-extend.
// https://msdn.microsoft.com/en-us/library/windows/desktop/aa384203%28v=vs.85%29.aspx
// Note that this does not make a HANDLE value work with APIs like open(), nor
// does this make a value from open() passable to APIs taking a HANDLE. This
// just lets you take a HANDLE, pass it around as an int, and then use it again
// as a HANDLE.
inline int cast_handle_to_int(const HANDLE h) {
    // truncate
    return static_cast<int>(reinterpret_cast<INT_PTR>(h));
}

inline HANDLE cast_int_to_handle(const int fd) {
    // sign-extend
    return reinterpret_cast<HANDLE>(static_cast<INT_PTR>(fd));
}

// Deleter for unique_handle. Adapted from many sources, including:
// http://stackoverflow.com/questions/14841396/stdunique-ptr-deleters-and-the-win32-api
// https://visualstudiomagazine.com/articles/2013/09/01/get-a-handle-on-the-windows-api.aspx
class handle_deleter {
public:
    typedef HANDLE pointer;

    void operator()(HANDLE h);
};

// Like std::unique_ptr, but for Windows HANDLE objects that should be
// CloseHandle()'d. Operator bool() only checks if the handle != nullptr,
// but does not check if the handle != INVALID_HANDLE_VALUE.
typedef std::unique_ptr<HANDLE, handle_deleter> unique_handle;

#else /* !_WIN32 a.k.a. Unix */

#include "fdevent.h"
#include <cutils/misc.h>
#include <cutils/sockets.h>
#include <cutils/threads.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>

#include <string>

#define OS_PATH_SEPARATORS "/"
#define OS_PATH_SEPARATOR '/'
#define OS_PATH_SEPARATOR_STR "/"
#define ENV_PATH_SEPARATOR_STR ":"

typedef  pthread_mutex_t          adb_mutex_t;

#define  ADB_MUTEX_INITIALIZER    PTHREAD_MUTEX_INITIALIZER
#define  adb_mutex_init           pthread_mutex_init
#define  adb_mutex_lock           pthread_mutex_lock
#define  adb_mutex_unlock         pthread_mutex_unlock
#define  adb_mutex_destroy        pthread_mutex_destroy

#define  ADB_MUTEX_DEFINE(m)      adb_mutex_t   m = PTHREAD_MUTEX_INITIALIZER

#define  adb_cond_t               pthread_cond_t
#define  adb_cond_init            pthread_cond_init
#define  adb_cond_wait            pthread_cond_wait
#define  adb_cond_broadcast       pthread_cond_broadcast
#define  adb_cond_signal          pthread_cond_signal
#define  adb_cond_destroy         pthread_cond_destroy

/* declare all mutexes */
#define  ADB_MUTEX(x)   extern adb_mutex_t  x;
#include "mutex_list.h"

static __inline__ void  close_on_exec(int  fd)
{
    fcntl( fd, F_SETFD, FD_CLOEXEC );
}

// Open a file and return a file descriptor that may be used with unix_read(),
// unix_write(), unix_close(), but not adb_read(), adb_write(), adb_close().
//
// On Unix, this is based on open(), so the file descriptor is a real OS file
// descriptor, but the Windows implementation (in sysdeps_win32.cpp) returns a
// file descriptor that can only be used with C Runtime APIs (which are wrapped
// by unix_read(), unix_write(), unix_close()). Also, the C Runtime has
// configurable CR/LF translation which defaults to text mode, but is settable
// with _setmode().
static __inline__ int  unix_open(const char*  path, int options,...)
{
    if ((options & O_CREAT) == 0)
    {
        return  TEMP_FAILURE_RETRY( open(path, options) );
    }
    else
    {
        int      mode;
        va_list  args;
        va_start( args, options );
        mode = va_arg( args, int );
        va_end( args );
        return TEMP_FAILURE_RETRY( open( path, options, mode ) );
    }
}

// Similar to the two-argument adb_open(), but takes a mode parameter for file
// creation. See adb_open() for more info.
static __inline__ int  adb_open_mode( const char*  pathname, int  options, int  mode )
{
    return TEMP_FAILURE_RETRY( open( pathname, options, mode ) );
}


// Open a file and return a file descriptor that may be used with adb_read(),
// adb_write(), adb_close(), but not unix_read(), unix_write(), unix_close().
//
// On Unix, this is based on open(), but the Windows implementation (in
// sysdeps_win32.cpp) uses Windows native file I/O and bypasses the C Runtime
// and its CR/LF translation. The returned file descriptor should be used with
// adb_read(), adb_write(), adb_close(), etc.
static __inline__ int  adb_open( const char*  pathname, int  options )
{
    int  fd = TEMP_FAILURE_RETRY( open( pathname, options ) );
    if (fd < 0)
        return -1;
    close_on_exec( fd );
    return fd;
}
#undef   open
#define  open    ___xxx_open

static __inline__ int  adb_shutdown(int fd)
{
    return shutdown(fd, SHUT_RDWR);
}
static __inline__ int  adb_shutdown(int fd, int direction)
{
    return shutdown(fd, direction);
}
#undef   shutdown
#define  shutdown   ____xxx_shutdown

// Closes a file descriptor that came from adb_open() or adb_open_mode(), but
// not designed to take a file descriptor from unix_open(). See the comments
// for adb_open() for more info.
static __inline__ int  adb_close(int fd)
{
    return close(fd);
}
#undef   close
#define  close   ____xxx_close


static __inline__  int  adb_read(int  fd, void*  buf, size_t  len)
{
    return TEMP_FAILURE_RETRY( read( fd, buf, len ) );
}

#undef   read
#define  read  ___xxx_read

static __inline__  int  adb_write(int  fd, const void*  buf, size_t  len)
{
    return TEMP_FAILURE_RETRY( write( fd, buf, len ) );
}
#undef   write
#define  write  ___xxx_write

static __inline__ int   adb_lseek(int  fd, int  pos, int  where)
{
    return lseek(fd, pos, where);
}
#undef   lseek
#define  lseek   ___xxx_lseek

static __inline__  int    adb_unlink(const char*  path)
{
    return  unlink(path);
}
#undef  unlink
#define unlink  ___xxx_unlink

static __inline__  int  adb_creat(const char*  path, int  mode)
{
    int  fd = TEMP_FAILURE_RETRY( creat( path, mode ) );

    if ( fd < 0 )
        return -1;

    close_on_exec(fd);
    return fd;
}
#undef   creat
#define  creat  ___xxx_creat

// Helper for network_* functions.
inline int _fd_set_error_str(int fd, std::string* error) {
  if (fd == -1) {
    *error = strerror(errno);
  }
  return fd;
}

inline int network_loopback_client(int port, int type, std::string* error) {
  return _fd_set_error_str(socket_loopback_client(port, type), error);
}

inline int network_loopback_server(int port, int type, std::string* error) {
  return _fd_set_error_str(socket_loopback_server(port, type), error);
}

inline int network_inaddr_any_server(int port, int type, std::string* error) {
  return _fd_set_error_str(socket_inaddr_any_server(port, type), error);
}

inline int network_local_server(const char *name, int namespace_id, int type,
                                std::string* error) {
  return _fd_set_error_str(socket_local_server(name, namespace_id, type),
                           error);
}

inline int network_connect(const std::string& host, int port, int type,
                           int timeout, std::string* error) {
  int getaddrinfo_error = 0;
  int fd = socket_network_client_timeout(host.c_str(), port, type, timeout,
                                         &getaddrinfo_error);
  if (fd != -1) {
    return fd;
  }
  if (getaddrinfo_error != 0) {
    *error = gai_strerror(getaddrinfo_error);
  } else {
    *error = strerror(errno);
  }
  return -1;
}

static __inline__ int  adb_socket_accept(int  serverfd, struct sockaddr*  addr, socklen_t  *addrlen)
{
    int fd;

    fd = TEMP_FAILURE_RETRY( accept( serverfd, addr, addrlen ) );
    if (fd >= 0)
        close_on_exec(fd);

    return fd;
}

#undef   accept
#define  accept  ___xxx_accept

// Operate on a file descriptor returned from unix_open() or a well-known file
// descriptor such as STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO.
//
// On Unix, unix_read(), unix_write(), unix_close() map to adb_read(),
// adb_write(), adb_close() (which all map to Unix system calls), but the
// Windows implementations (in the ifdef above and in sysdeps_win32.cpp) call
// into the C Runtime and its configurable CR/LF translation (which is settable
// via _setmode()).
#define  unix_read   adb_read
#define  unix_write  adb_write
#define  unix_close  adb_close

typedef void*  (*adb_thread_func_t)( void*  arg );

static __inline__ bool adb_thread_create(adb_thread_func_t start, void* arg) {
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    pthread_t thread;
    errno = pthread_create(&thread, &attr, start, arg);
    return (errno == 0);
}

static __inline__ int adb_thread_setname(const std::string& name) {
#ifdef __APPLE__
    return pthread_setname_np(name.c_str());
#else
    const char *s = name.c_str();

    // pthread_setname_np fails rather than truncating long strings.
    const int max_task_comm_len = 16; // including the null terminator
    if (name.length() > (max_task_comm_len - 1)) {
        char buf[max_task_comm_len];
        strncpy(buf, name.c_str(), sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        s = buf;
    }

    return pthread_setname_np(pthread_self(), s) ;
#endif
}

static __inline__  int  adb_socket_setbufsize(int fd, int  bufsize )
{
    int opt = bufsize;
    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
}

static __inline__ void  disable_tcp_nagle(int fd)
{
    int  on = 1;
    setsockopt( fd, IPPROTO_TCP, TCP_NODELAY, (void*)&on, sizeof(on) );
}

static __inline__ int  adb_setsockopt( int  fd, int  level, int  optname, const void*  optval, socklen_t  optlen )
{
    return setsockopt( fd, level, optname, optval, optlen );
}

#undef   setsockopt
#define  setsockopt  ___xxx_setsockopt

static __inline__ int  unix_socketpair( int  d, int  type, int  protocol, int sv[2] )
{
    return socketpair( d, type, protocol, sv );
}

static __inline__ int  adb_socketpair( int  sv[2] )
{
    int  rc;

    rc = unix_socketpair( AF_UNIX, SOCK_STREAM, 0, sv );
    if (rc < 0)
        return -1;

    close_on_exec( sv[0] );
    close_on_exec( sv[1] );
    return 0;
}

#undef   socketpair
#define  socketpair   ___xxx_socketpair

static __inline__ void  adb_sleep_ms( int  mseconds )
{
    usleep( mseconds*1000 );
}

static __inline__ int  adb_mkdir(const std::string& path, int mode)
{
    return mkdir(path.c_str(), mode);
}

#undef   mkdir
#define  mkdir  ___xxx_mkdir

static __inline__ void  adb_sysdeps_init(void)
{
}

static __inline__ int adb_is_absolute_host_path(const char* path) {
    return path[0] == '/';
}

static __inline__ unsigned long adb_thread_id()
{
    return (unsigned long)gettid();
}

#endif /* !_WIN32 */

#endif /* _ADB_SYSDEPS_H */

/*
 * Copyright 2006, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "crasher"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

// We test both kinds of logging.
#include <android-base/logging.h>
#include <log/log.h>

#include "seccomp_policy.h"

#if defined(STATIC_CRASHER)
#include "debuggerd/handler.h"
#endif

extern "C" void android_set_abort_message(const char* msg);

#if defined(__arm__)
// See https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt for details.
#define __kuser_helper_version (*(int32_t*) 0xffff0ffc)
typedef void * (__kuser_get_tls_t)(void);
#define __kuser_get_tls (*(__kuser_get_tls_t*) 0xffff0fe0)
typedef int (__kuser_cmpxchg_t)(int oldval, int newval, volatile int *ptr);
#define __kuser_cmpxchg (*(__kuser_cmpxchg_t*) 0xffff0fc0)
typedef void (__kuser_dmb_t)(void);
#define __kuser_dmb (*(__kuser_dmb_t*) 0xffff0fa0)
typedef int (__kuser_cmpxchg64_t)(const int64_t*, const int64_t*, volatile int64_t*);
#define __kuser_cmpxchg64 (*(__kuser_cmpxchg64_t*) 0xffff0f60)
#endif

#define noinline __attribute__((__noinline__))

// Avoid name mangling so that stacks are more readable.
extern "C" {

void crash1();
void crash_no_stack();
void crash_bti();
void crash_pac();

int do_action(const char* arg);

noinline void maybe_abort() {
    if (time(0) != 42) {
        abort();
    }
}

char* smash_stack_dummy_buf;
noinline void smash_stack_dummy_function(volatile int* plen) {
  smash_stack_dummy_buf[*plen] = 0;
}

// This must be marked with "__attribute__ ((noinline))", to ensure the
// compiler generates the proper stack guards around this function.
// Assign local array address to global variable to force stack guards.
// Use another noinline function to corrupt the stack.
noinline int smash_stack(volatile int* plen) {
    printf("%s: deliberately corrupting stack...\n", getprogname());

    char buf[128];
    smash_stack_dummy_buf = buf;
    // This should corrupt stack guards and make process abort.
    smash_stack_dummy_function(plen);
    return 0;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winfinite-recursion"

void* global = 0; // So GCC doesn't optimize the tail recursion out of overflow_stack.

noinline void overflow_stack(void* p) {
    void* buf[1];
    buf[0] = p;
    global = buf;
    overflow_stack(&buf);
}

#pragma clang diagnostic pop

noinline void* thread_callback(void* raw_arg) {
    const char* arg = reinterpret_cast<const char*>(raw_arg);
    return reinterpret_cast<void*>(static_cast<uintptr_t>(do_action(arg)));
}

noinline int do_action_on_thread(const char* arg) {
    pthread_t t;
    pthread_create(&t, nullptr, thread_callback, const_cast<char*>(arg));
    void* result = nullptr;
    pthread_join(t, &result);
    return reinterpret_cast<uintptr_t>(result);
}

noinline int do_action_on_signal(const char* arg, bool use_alt_stack) {
  struct sigaction sa = {.sa_flags = SA_SIGINFO};
  if (use_alt_stack) {
    sa.sa_flags |= SA_ONSTACK;
  }
  static const char* action = arg;
  sa.sa_sigaction = [](int, siginfo_t*, void*) { do_action(action); };
  sigaction(SIGUSR1, &sa, nullptr);
  kill(getpid(), SIGUSR1);
  return 0;
}

noinline int crash_null() {
  int (*null_func)() = nullptr;
  return null_func();
}

noinline int crash3(int a) {
    *reinterpret_cast<int*>(0xdead) = a;
    return a*4;
}

noinline int crash2(int a) {
    a = crash3(a) + 2;
    return a*3;
}

noinline int crash(int a) {
    a = crash2(a) + 1;
    return a*2;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wfree-nonheap-object"

noinline void invalid_free() {
    char buf[16];
    free(buf); // The compiler is smart enough to warn about this, but we're doing it deliberately.
}
#pragma clang diagnostic pop

noinline void heap_buffer_overflow() {
    volatile char* p = reinterpret_cast<volatile char*>(malloc(32));
    p[32] = p[32];
}

noinline void use_after_free() {
    void* allocation = malloc(32);
    volatile char* p = reinterpret_cast<volatile char*>(allocation);
    free(allocation);
    p[0] = p[0];
}

noinline void leak() {
    while (true) {
        void* mapping =
            mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        static_cast<volatile char*>(mapping)[0] = 'a';
    }
}

noinline void sigsegv_non_null() {
    int* a = (int *)(&do_action);
    *a = 42;
}

noinline void sigsegv_write() {
  int* a = reinterpret_cast<int*>(0xdeadbeef);
  *a = 10;
}

noinline void sigsegv_read() {
  volatile int* a = reinterpret_cast<volatile int*>(0xdeadbeef);
  android::base::DoNotOptimize(*a);
}

noinline void fprintf_null() {
    FILE* sneaky_null = nullptr;
    fprintf(sneaky_null, "oops");
}

noinline void readdir_null() {
    DIR* sneaky_null = nullptr;
    readdir(sneaky_null);
}

noinline int strlen_null() {
    char* sneaky_null = nullptr;
    return strlen(sneaky_null);
}

static int usage() {
    fprintf(stderr, "usage: %s KIND\n", getprogname());
    fprintf(stderr, "\n");
    fprintf(stderr, "where KIND is:\n");
    fprintf(stderr, "  smash-stack           overwrite a -fstack-protector guard\n");
    fprintf(stderr, "  stack-overflow        recurse until the stack overflows\n");
    fprintf(stderr, "  nostack               crash with a NULL stack pointer\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  heap-buffer-overflow  write past the end of a heap allocation\n");
    fprintf(stderr, "  invalid-free          pass a non-heap pointer to free()\n");
    fprintf(stderr, "  use-after-free        write to a buffer after free()\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  call-null             cause a crash by calling through a nullptr\n");
    fprintf(stderr, "  leak                  leak memory until we get OOM-killed\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  abort                 call abort()\n");
    fprintf(stderr, "  abort_with_msg        call abort() setting an abort message\n");
    fprintf(stderr, "  abort_with_null_msg   call abort() setting a null abort message\n");
    fprintf(stderr, "  assert                call assert() without a function\n");
    fprintf(stderr, "  assert2               call assert() with a function\n");
    fprintf(stderr, "  exit                  call exit(1)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  fortify               fail a _FORTIFY_SOURCE check\n");
    fprintf(stderr, "  fdsan_file            close a file descriptor that's owned by a FILE*\n");
    fprintf(stderr, "  fdsan_dir             close a file descriptor that's owned by a DIR*\n");
    fprintf(stderr, "  seccomp               fail a seccomp check\n");
#if defined(__LP64__)
    fprintf(stderr, "  xom                   read execute-only memory\n");
#endif
    fprintf(stderr, "\n");
    fprintf(stderr, "  LOG_ALWAYS_FATAL      call liblog LOG_ALWAYS_FATAL\n");
    fprintf(stderr, "  LOG_ALWAYS_FATAL_IF   call liblog LOG_ALWAYS_FATAL_IF\n");
    fprintf(stderr, "  LOG-FATAL             call libbase LOG(FATAL)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  SIGFPE                cause a SIGFPE\n");
    fprintf(stderr, "  SIGILL                cause a SIGILL\n");
    fprintf(stderr, "  SIGSEGV               cause a SIGSEGV at address 0x0 (synonym: crash)\n");
    fprintf(stderr, "  SIGSEGV-non-null      cause a SIGSEGV at a non-zero address\n");
    fprintf(stderr, "  SIGSEGV-unmapped      mmap/munmap a region of memory and then attempt to access it\n");
    fprintf(stderr, "  SIGSEGV-read          cause a SIGSEGV reading from a non-zero address\n");
    fprintf(stderr, "  SIGSEGV-write         cause a SIGSEGV writing to a non-zero address\n");
    fprintf(stderr, "  SIGTRAP               cause a SIGTRAP\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  fprintf-NULL          pass a null pointer to fprintf\n");
    fprintf(stderr, "  readdir-NULL          pass a null pointer to readdir\n");
    fprintf(stderr, "  strlen-NULL           pass a null pointer to strlen\n");
    fprintf(stderr, "  pthread_join-NULL     pass a null pointer to pthread_join\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "  no_new_privs          set PR_SET_NO_NEW_PRIVS and then abort\n");
    fprintf(stderr, "\n");
#if defined(__arm__)
    fprintf(stderr, "Also, since this is an arm32 binary:\n");
    fprintf(stderr, "  kuser_helper_version  call kuser_helper_version\n");
    fprintf(stderr, "  kuser_get_tls         call kuser_get_tls\n");
    fprintf(stderr, "  kuser_cmpxchg         call kuser_cmpxchg\n");
    fprintf(stderr, "  kuser_memory_barrier  call kuser_memory_barrier\n");
    fprintf(stderr, "  kuser_cmpxchg64       call kuser_cmpxchg64\n");
#endif
#if defined(__aarch64__)
    fprintf(stderr, "Also, since this is an arm64 binary:\n");
    fprintf(stderr, "  bti                   fail a branch target identification (BTI) check\n");
    fprintf(stderr, "  pac                   fail a pointer authentication (PAC) check\n");
#endif
    fprintf(stderr, "\n");
    fprintf(stderr, "prefix any of the above with 'thread-' to run on a new thread\n");
    fprintf(stderr, "prefix any of the above with 'exhaustfd-' to exhaust\n");
    fprintf(stderr, "prefix any of the above with 'signal-' to call in a signal handler.\n");
    fprintf(stderr,
            "prefix any of the above with 'signal-altstack-' to call in a signal handler using the "
            "alternate stack.\n");
    fprintf(stderr, "all available file descriptors before crashing.\n");
    fprintf(stderr, "prefix any of the above with 'wait-' to wait until input is received on stdin\n");

    return EXIT_FAILURE;
}

[[maybe_unused]] static void CheckCpuFeature(const std::string& name) {
    std::string cpuinfo;
    if (!android::base::ReadFileToString("/proc/cpuinfo", &cpuinfo)) {
        error(1, errno, "couldn't read /proc/cpuinfo");
    }
    std::vector<std::string> lines = android::base::Split(cpuinfo, "\n");
    for (std::string_view line : lines) {
        if (!android::base::ConsumePrefix(&line, "Features\t:")) continue;
        std::vector<std::string> features = android::base::Split(std::string(line), " ");
        if (std::find(features.begin(), features.end(), name) == features.end()) {
          error(1, 0, "/proc/cpuinfo does not report feature '%s'", name.c_str());
        }
    }
}

noinline int do_action(const char* arg) {
    // Prefixes.
    if (!strncmp(arg, "wait-", strlen("wait-"))) {
      char buf[1];
      UNUSED(TEMP_FAILURE_RETRY(read(STDIN_FILENO, buf, sizeof(buf))));
      return do_action(arg + strlen("wait-"));
    } else if (!strncmp(arg, "exhaustfd-", strlen("exhaustfd-"))) {
      errno = 0;
      while (errno != EMFILE) {
        open("/dev/null", O_RDONLY);
      }
      return do_action(arg + strlen("exhaustfd-"));
    } else if (!strncmp(arg, "thread-", strlen("thread-"))) {
        return do_action_on_thread(arg + strlen("thread-"));
    } else if (!strncmp(arg, "signal-altstack-", strlen("signal-altstack-"))) {
      return do_action_on_signal(arg + strlen("signal-altstack-"), /*use_alt_stack*/ true);
    } else if (!strncmp(arg, "signal-", strlen("signal-"))) {
      return do_action_on_signal(arg + strlen("signal-"), /*use_alt_stack*/ false);
    }

    // Actions.
    if (!strcasecmp(arg, "SIGSEGV-non-null")) {
      sigsegv_non_null();
    } else if (!strcasecmp(arg, "SIGSEGV-read")) {
      sigsegv_read();
    } else if (!strcasecmp(arg, "SIGSEGV-write")) {
      sigsegv_write();
    } else if (!strcasecmp(arg, "smash-stack")) {
      volatile int len = 128;
      return smash_stack(&len);
    } else if (!strcasecmp(arg, "stack-overflow")) {
      overflow_stack(nullptr);
    } else if (!strcasecmp(arg, "nostack")) {
      crash_no_stack();
    } else if (!strcasecmp(arg, "exit")) {
      exit(1);
    } else if (!strcasecmp(arg, "call-null")) {
      return crash_null();
    } else if (!strcasecmp(arg, "crash") || !strcmp(arg, "SIGSEGV")) {
      return crash(42);
    } else if (!strcasecmp(arg, "abort")) {
      maybe_abort();
    } else if (!strcasecmp(arg, "abort_with_msg")) {
      android_set_abort_message("Aborting due to crasher");
      maybe_abort();
    } else if (!strcasecmp(arg, "abort_with_null")) {
      android_set_abort_message(nullptr);
      maybe_abort();
    } else if (!strcasecmp(arg, "assert")) {
      __assert("some_file.c", 123, "false");
    } else if (!strcasecmp(arg, "assert2")) {
      __assert2("some_file.c", 123, "some_function", "false");
#if !defined(__clang_analyzer__)
    } else if (!strcasecmp(arg, "fortify")) {
      // FORTIFY is disabled when running clang-tidy and other tools, so this
      // shouldn't depend on internal implementation details of it.
      char buf[10];
      __read_chk(-1, buf, 32, 10);
      while (true) pause();
#endif
    } else if (!strcasecmp(arg, "fdsan_file")) {
      FILE* f = fopen("/dev/null", "r");
      close(fileno(f));
    } else if (!strcasecmp(arg, "fdsan_dir")) {
      DIR* d = opendir("/dev/");
      close(dirfd(d));
    } else if (!strcasecmp(arg, "LOG(FATAL)")) {
      LOG(FATAL) << "hello " << 123;
    } else if (!strcasecmp(arg, "LOG_ALWAYS_FATAL")) {
      LOG_ALWAYS_FATAL("hello %s", "world");
    } else if (!strcasecmp(arg, "LOG_ALWAYS_FATAL_IF")) {
      LOG_ALWAYS_FATAL_IF(true, "hello %s", "world");
    } else if (!strcasecmp(arg, "SIGFPE")) {
      raise(SIGFPE);
      return EXIT_SUCCESS;
    } else if (!strcasecmp(arg, "SIGILL")) {
#if defined(__aarch64__)
      __asm__ volatile(".word 0\n");
#elif defined(__arm__)
      __asm__ volatile(".word 0xe7f0def0\n");
#elif defined(__i386__) || defined(__x86_64__)
      __asm__ volatile("ud2\n");
#elif defined(__riscv)
      __asm__ volatile("unimp\n");
#else
#error
#endif
    } else if (!strcasecmp(arg, "SIGTRAP")) {
      raise(SIGTRAP);
      return EXIT_SUCCESS;
    } else if (!strcasecmp(arg, "fprintf-NULL")) {
      fprintf_null();
    } else if (!strcasecmp(arg, "readdir-NULL")) {
      readdir_null();
    } else if (!strcasecmp(arg, "strlen-NULL")) {
      return strlen_null();
    } else if (!strcasecmp(arg, "pthread_join-NULL")) {
      return pthread_join(0, nullptr);
    } else if (!strcasecmp(arg, "heap-buffer-overflow")) {
      heap_buffer_overflow();
    } else if (!strcasecmp(arg, "invalid-free")) {
      invalid_free();
    } else if (!strcasecmp(arg, "use-after-free")) {
      use_after_free();
    } else if (!strcasecmp(arg, "leak")) {
      leak();
    } else if (!strcasecmp(arg, "SIGSEGV-unmapped")) {
      char* map = reinterpret_cast<char*>(
          mmap(nullptr, sizeof(int), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0));
      munmap(map, sizeof(int));
      map[0] = '8';
    } else if (!strcasecmp(arg, "seccomp")) {
      set_system_seccomp_filter();
      syscall(99999);
#if defined(__LP64__)
    } else if (!strcasecmp(arg, "xom")) {
      // Try to read part of our code, which will fail if XOM is active.
      printf("*%lx = %lx\n", reinterpret_cast<long>(usage), *reinterpret_cast<long*>(usage));
#endif
#if defined(__arm__)
    } else if (!strcasecmp(arg, "kuser_helper_version")) {
        return __kuser_helper_version;
    } else if (!strcasecmp(arg, "kuser_get_tls")) {
        return !__kuser_get_tls();
    } else if (!strcasecmp(arg, "kuser_cmpxchg")) {
        return __kuser_cmpxchg(0, 0, 0);
    } else if (!strcasecmp(arg, "kuser_memory_barrier")) {
        __kuser_dmb();
    } else if (!strcasecmp(arg, "kuser_cmpxchg64")) {
        return __kuser_cmpxchg64(0, 0, 0);
#endif
#if defined(__aarch64__)
    } else if (!strcasecmp(arg, "bti")) {
        CheckCpuFeature("bti");
        crash_bti();
    } else if (!strcasecmp(arg, "pac")) {
        CheckCpuFeature("paca");
        crash_pac();
#endif
    } else if (!strcasecmp(arg, "no_new_privs")) {
        if (prctl(PR_SET_NO_NEW_PRIVS, 1) != 0) {
          fprintf(stderr, "prctl(PR_SET_NO_NEW_PRIVS, 1) failed: %s\n", strerror(errno));
          return EXIT_SUCCESS;
        }
        abort();
    } else {
      return usage();
    }

    fprintf(stderr, "%s: exiting normally (which is unexpected)!\n", getprogname());
    return EXIT_SUCCESS;
}

}  // extern "C"

int main(int argc, char** argv) {
#if defined(STATIC_CRASHER)
    debuggerd_callbacks_t callbacks = {
      .get_process_info = []() {
        static struct {
          size_t size;
          char msg[32];
        } msg;

        msg.size = strlen("dummy abort message");
        memcpy(msg.msg, "dummy abort message", strlen("dummy abort message"));
        return debugger_process_info{
            .abort_msg = reinterpret_cast<void*>(&msg),
        };
      },
      .post_dump = nullptr
    };
    debuggerd_init(&callbacks);
#endif

    if (argc == 1) crash1();
    else if (argc == 2) return do_action(argv[1]);

    return usage();
}

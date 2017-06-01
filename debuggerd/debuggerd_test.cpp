/*
 * Copyright 2016, The Android Open Source Project
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

#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include <chrono>
#include <regex>
#include <thread>

#include <android/set_abort_message.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <gtest/gtest.h>

#include "debuggerd/handler.h"
#include "protocol.h"
#include "tombstoned/tombstoned.h"
#include "util.h"

using namespace std::chrono_literals;
using android::base::unique_fd;

#if defined(__LP64__)
#define ARCH_SUFFIX "64"
#else
#define ARCH_SUFFIX ""
#endif

constexpr char kWaitForGdbKey[] = "debug.debuggerd.wait_for_gdb";

#define TIMEOUT(seconds, expr)                                     \
  [&]() {                                                          \
    struct sigaction old_sigaction;                                \
    struct sigaction new_sigaction = {};                           \
    new_sigaction.sa_handler = [](int) {};                         \
    if (sigaction(SIGALRM, &new_sigaction, &new_sigaction) != 0) { \
      err(1, "sigaction failed");                                  \
    }                                                              \
    alarm(seconds);                                                \
    auto value = expr;                                             \
    int saved_errno = errno;                                       \
    if (sigaction(SIGALRM, &old_sigaction, nullptr) != 0) {        \
      err(1, "sigaction failed");                                  \
    }                                                              \
    alarm(0);                                                      \
    errno = saved_errno;                                           \
    return value;                                                  \
  }()

#define ASSERT_MATCH(str, pattern)                                              \
  do {                                                                          \
    std::regex r((pattern));                                                    \
    if (!std::regex_search((str), r)) {                                         \
      FAIL() << "regex mismatch: expected " << (pattern) << " in: \n" << (str); \
    }                                                                           \
  } while (0)

#define ASSERT_NOT_MATCH(str, pattern)                                                      \
  do {                                                                                      \
    std::regex r((pattern));                                                                \
    if (std::regex_search((str), r)) {                                                      \
      FAIL() << "regex mismatch: expected to not find " << (pattern) << " in: \n" << (str); \
    }                                                                                       \
  } while (0)

static void tombstoned_intercept(pid_t target_pid, unique_fd* intercept_fd, unique_fd* output_fd,
                                 DebuggerdDumpType intercept_type) {
  intercept_fd->reset(socket_local_client(kTombstonedInterceptSocketName,
                                          ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (intercept_fd->get() == -1) {
    FAIL() << "failed to contact tombstoned: " << strerror(errno);
  }

  InterceptRequest req = {.pid = target_pid, .dump_type = intercept_type};

  unique_fd output_pipe_write;
  if (!Pipe(output_fd, &output_pipe_write)) {
    FAIL() << "failed to create output pipe: " << strerror(errno);
  }

  std::string pipe_size_str;
  int pipe_buffer_size;
  if (!android::base::ReadFileToString("/proc/sys/fs/pipe-max-size", &pipe_size_str)) {
    FAIL() << "failed to read /proc/sys/fs/pipe-max-size: " << strerror(errno);
  }

  pipe_size_str = android::base::Trim(pipe_size_str);

  if (!android::base::ParseInt(pipe_size_str.c_str(), &pipe_buffer_size, 0)) {
    FAIL() << "failed to parse pipe max size";
  }

  if (fcntl(output_fd->get(), F_SETPIPE_SZ, pipe_buffer_size) != pipe_buffer_size) {
    FAIL() << "failed to set pipe size: " << strerror(errno);
  }

  ASSERT_GE(pipe_buffer_size, 1024 * 1024);

  if (send_fd(intercept_fd->get(), &req, sizeof(req), std::move(output_pipe_write)) != sizeof(req)) {
    FAIL() << "failed to send output fd to tombstoned: " << strerror(errno);
  }

  InterceptResponse response;
  ssize_t rc = TEMP_FAILURE_RETRY(read(intercept_fd->get(), &response, sizeof(response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "failed to read response from tombstoned (EOF)";
  } else if (rc != sizeof(response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
           << ", received " << rc;
  }

  ASSERT_EQ(InterceptStatus::kRegistered, response.status);
}

class CrasherTest : public ::testing::Test {
 public:
  pid_t crasher_pid = -1;
  bool previous_wait_for_gdb;
  unique_fd crasher_pipe;
  unique_fd intercept_fd;

  CrasherTest();
  ~CrasherTest();

  void StartIntercept(unique_fd* output_fd, DebuggerdDumpType intercept_type = kDebuggerdTombstone);

  // Returns -1 if we fail to read a response from tombstoned, otherwise the received return code.
  void FinishIntercept(int* result);

  void StartProcess(std::function<void()> function, std::function<pid_t()> forker = fork);
  void StartCrasher(const std::string& crash_type);
  void FinishCrasher();
  void AssertDeath(int signo);
};

CrasherTest::CrasherTest() {
  previous_wait_for_gdb = android::base::GetBoolProperty(kWaitForGdbKey, false);
  android::base::SetProperty(kWaitForGdbKey, "0");
}

CrasherTest::~CrasherTest() {
  if (crasher_pid != -1) {
    kill(crasher_pid, SIGKILL);
    int status;
    waitpid(crasher_pid, &status, WUNTRACED);
  }

  android::base::SetProperty(kWaitForGdbKey, previous_wait_for_gdb ? "1" : "0");
}

void CrasherTest::StartIntercept(unique_fd* output_fd, DebuggerdDumpType intercept_type) {
  if (crasher_pid == -1) {
    FAIL() << "crasher hasn't been started";
  }

  tombstoned_intercept(crasher_pid, &this->intercept_fd, output_fd, intercept_type);
}

void CrasherTest::FinishIntercept(int* result) {
  InterceptResponse response;

  // Timeout for tombstoned intercept is 10 seconds.
  ssize_t rc = TIMEOUT(20, read(intercept_fd.get(), &response, sizeof(response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    *result = -1;
  } else if (rc != sizeof(response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
           << ", received " << rc;
  } else {
    *result = response.status == InterceptStatus::kStarted ? 1 : 0;
  }
}

void CrasherTest::StartProcess(std::function<void()> function, std::function<pid_t()> forker) {
  unique_fd read_pipe;
  unique_fd crasher_read_pipe;
  if (!Pipe(&crasher_read_pipe, &crasher_pipe)) {
    FAIL() << "failed to create pipe: " << strerror(errno);
  }

  crasher_pid = forker();
  if (crasher_pid == -1) {
    FAIL() << "fork failed: " << strerror(errno);
  } else if (crasher_pid == 0) {
    char dummy;
    crasher_pipe.reset();
    TEMP_FAILURE_RETRY(read(crasher_read_pipe.get(), &dummy, 1));
    function();
    _exit(0);
  }
}

void CrasherTest::FinishCrasher() {
  if (crasher_pipe == -1) {
    FAIL() << "crasher pipe uninitialized";
  }

  ssize_t rc = write(crasher_pipe.get(), "\n", 1);
  if (rc == -1) {
    FAIL() << "failed to write to crasher pipe: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "crasher pipe was closed";
  }
}

void CrasherTest::AssertDeath(int signo) {
  int status;
  pid_t pid = TIMEOUT(5, waitpid(crasher_pid, &status, 0));
  if (pid != crasher_pid) {
    FAIL() << "failed to wait for crasher: " << strerror(errno);
  }

  if (signo == 0) {
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(signo));
  } else {
    ASSERT_FALSE(WIFEXITED(status));
    ASSERT_TRUE(WIFSIGNALED(status)) << "crasher didn't terminate via a signal";
    ASSERT_EQ(signo, WTERMSIG(status));
  }
  crasher_pid = -1;
}

static void ConsumeFd(unique_fd fd, std::string* output) {
  constexpr size_t read_length = PAGE_SIZE;
  std::string result;

  while (true) {
    size_t offset = result.size();
    result.resize(result.size() + PAGE_SIZE);
    ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), &result[offset], read_length));
    if (rc == -1) {
      FAIL() << "read failed: " << strerror(errno);
    } else if (rc == 0) {
      result.resize(result.size() - PAGE_SIZE);
      break;
    }

    result.resize(result.size() - PAGE_SIZE + rc);
  }

  *output = std::move(result);
}

TEST_F(CrasherTest, smoke) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    *reinterpret_cast<volatile char*>(0xdead) = '1';
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0xdead)");
}

TEST_F(CrasherTest, abort) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST_F(CrasherTest, signal) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd);

  // Wait for a bit, or we might end up killing the process before the signal
  // handler even gets a chance to be registered.
  std::this_thread::sleep_for(100ms);
  ASSERT_EQ(0, kill(crasher_pid, SIGSEGV));

  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 0 \(SI_USER\), fault addr --------)");
  ASSERT_MATCH(result, R"(backtrace:)");
}

TEST_F(CrasherTest, abort_message) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_set_abort_message("abort message goes here");
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(Abort message: 'abort message goes here')");
}

TEST_F(CrasherTest, abort_message_backtrace) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_set_abort_message("not actually aborting");
    raise(DEBUGGER_SIGNAL);
    exit(0);
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_NOT_MATCH(result, R"(Abort message:)");
}

TEST_F(CrasherTest, intercept_timeout) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd);

  // Don't let crasher finish until we timeout.
  FinishIntercept(&intercept_result);

  ASSERT_NE(1, intercept_result) << "tombstoned reported success? (intercept_result = "
                                 << intercept_result << ")";

  FinishCrasher();
  AssertDeath(SIGABRT);
}

TEST_F(CrasherTest, wait_for_gdb) {
  if (!android::base::SetProperty(kWaitForGdbKey, "1")) {
    FAIL() << "failed to enable wait_for_gdb";
  }
  sleep(1);

  StartProcess([]() {
    abort();
  });
  FinishCrasher();

  int status;
  ASSERT_EQ(crasher_pid, waitpid(crasher_pid, &status, WUNTRACED));
  ASSERT_TRUE(WIFSTOPPED(status));
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status));

  ASSERT_EQ(0, kill(crasher_pid, SIGCONT));

  AssertDeath(SIGABRT);
}

// wait_for_gdb shouldn't trigger on manually sent signals.
TEST_F(CrasherTest, wait_for_gdb_signal) {
  if (!android::base::SetProperty(kWaitForGdbKey, "1")) {
    FAIL() << "failed to enable wait_for_gdb";
  }

  StartProcess([]() {
    abort();
  });
  ASSERT_EQ(0, kill(crasher_pid, SIGSEGV)) << strerror(errno);
  AssertDeath(SIGSEGV);
}

TEST_F(CrasherTest, backtrace) {
  std::string result;
  int intercept_result;
  unique_fd output_fd;

  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd, kDebuggerdNativeBacktrace);

  std::this_thread::sleep_for(500ms);

  sigval val;
  val.sival_int = 1;
  ASSERT_EQ(0, sigqueue(crasher_pid, DEBUGGER_SIGNAL, val)) << strerror(errno);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+  /system/lib)" ARCH_SUFFIX R"(/libc.so \(read\+)");

  int status;
  ASSERT_EQ(0, waitpid(crasher_pid, &status, WNOHANG | WUNTRACED));

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST_F(CrasherTest, PR_SET_DUMPABLE_0_crash) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    prctl(PR_SET_DUMPABLE, 0);
    abort();
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST_F(CrasherTest, capabilities) {
  ASSERT_EQ(0U, getuid()) << "capability test requires root";

  StartProcess([]() {
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
      err(1, "failed to set PR_SET_KEEPCAPS");
    }

    if (setresuid(1, 1, 1) != 0) {
      err(1, "setresuid failed");
    }

    __user_cap_header_struct capheader;
    __user_cap_data_struct capdata[2];
    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));

    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;

    // Turn on every third capability.
    static_assert(CAP_LAST_CAP > 33, "CAP_LAST_CAP <= 32");
    for (int i = 0; i < CAP_LAST_CAP; i += 3) {
      capdata[CAP_TO_INDEX(i)].permitted |= CAP_TO_MASK(i);
      capdata[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
    }

    // Make sure CAP_SYS_PTRACE is off.
    capdata[CAP_TO_INDEX(CAP_SYS_PTRACE)].permitted &= ~(CAP_TO_MASK(CAP_SYS_PTRACE));
    capdata[CAP_TO_INDEX(CAP_SYS_PTRACE)].effective &= ~(CAP_TO_MASK(CAP_SYS_PTRACE));

    if (capset(&capheader, &capdata[0]) != 0) {
      err(1, "capset failed");
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
      err(1, "failed to drop ambient capabilities");
    }

    pthread_setname_np(pthread_self(), "thread_name");
    raise(SIGSYS);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSYS);

  std::string result;
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(name: thread_name\s+>>> .+debuggerd_test(32|64) <<<)");
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST_F(CrasherTest, fake_pid) {
  int intercept_result;
  unique_fd output_fd;

  // Prime the getpid/gettid caches.
  UNUSED(getpid());
  UNUSED(gettid());

  std::function<pid_t()> clone_fn = []() {
    return syscall(__NR_clone, SIGCHLD, nullptr, nullptr, nullptr, nullptr);
  };
  StartProcess(
      []() {
        ASSERT_NE(getpid(), syscall(__NR_getpid));
        ASSERT_NE(gettid(), syscall(__NR_gettid));
        raise(SIGSEGV);
      },
      clone_fn);

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST(crash_dump, zombie) {
  pid_t forkpid = fork();

  pid_t rc;
  int status;

  if (forkpid == 0) {
    errno = 0;
    rc = waitpid(-1, &status, WNOHANG | __WALL | __WNOTHREAD);
    if (rc != -1 || errno != ECHILD) {
      errx(2, "first waitpid returned %d (%s), expected failure with ECHILD", rc, strerror(errno));
    }

    raise(DEBUGGER_SIGNAL);

    errno = 0;
    rc = waitpid(-1, &status, __WALL | __WNOTHREAD);
    if (rc != -1 || errno != ECHILD) {
      errx(2, "second waitpid returned %d (%s), expected failure with ECHILD", rc, strerror(errno));
    }
    _exit(0);
  } else {
    rc = waitpid(forkpid, &status, 0);
    ASSERT_EQ(forkpid, rc);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));
  }
}

TEST(tombstoned, no_notify) {
  // Do this a few times.
  for (int i = 0; i < 3; ++i) {
    pid_t pid = 123'456'789 + i;

    unique_fd intercept_fd, output_fd;
    tombstoned_intercept(pid, &intercept_fd, &output_fd, kDebuggerdTombstone);

    {
      unique_fd tombstoned_socket, input_fd;
      ASSERT_TRUE(tombstoned_connect(pid, &tombstoned_socket, &input_fd, kDebuggerdTombstone));
      ASSERT_TRUE(android::base::WriteFully(input_fd.get(), &pid, sizeof(pid)));
    }

    pid_t read_pid;
    ASSERT_TRUE(android::base::ReadFully(output_fd.get(), &read_pid, sizeof(read_pid)));
    ASSERT_EQ(read_pid, pid);
  }
}

TEST(tombstoned, stress) {
  // Spawn threads to simultaneously do a bunch of failing dumps and a bunch of successful dumps.
  static constexpr int kDumpCount = 100;

  std::atomic<bool> start(false);
  std::vector<std::thread> threads;
  threads.emplace_back([&start]() {
    while (!start) {
      continue;
    }

    // Use a way out of range pid, to avoid stomping on an actual process.
    pid_t pid_base = 1'000'000;

    for (int dump = 0; dump < kDumpCount; ++dump) {
      pid_t pid = pid_base + dump;

      unique_fd intercept_fd, output_fd;
      tombstoned_intercept(pid, &intercept_fd, &output_fd, kDebuggerdTombstone);

      // Pretend to crash, and then immediately close the socket.
      unique_fd sockfd(socket_local_client(kTombstonedCrashSocketName,
                                           ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
      if (sockfd == -1) {
        FAIL() << "failed to connect to tombstoned: " << strerror(errno);
      }
      TombstonedCrashPacket packet = {};
      packet.packet_type = CrashPacketType::kDumpRequest;
      packet.packet.dump_request.pid = pid;
      if (TEMP_FAILURE_RETRY(write(sockfd, &packet, sizeof(packet))) != sizeof(packet)) {
        FAIL() << "failed to write to tombstoned: " << strerror(errno);
      }

      continue;
    }
  });

  threads.emplace_back([&start]() {
    while (!start) {
      continue;
    }

    // Use a way out of range pid, to avoid stomping on an actual process.
    pid_t pid_base = 2'000'000;

    for (int dump = 0; dump < kDumpCount; ++dump) {
      pid_t pid = pid_base + dump;

      unique_fd intercept_fd, output_fd;
      tombstoned_intercept(pid, &intercept_fd, &output_fd, kDebuggerdTombstone);

      {
        unique_fd tombstoned_socket, input_fd;
        ASSERT_TRUE(tombstoned_connect(pid, &tombstoned_socket, &input_fd, kDebuggerdTombstone));
        ASSERT_TRUE(android::base::WriteFully(input_fd.get(), &pid, sizeof(pid)));
        tombstoned_notify_completion(tombstoned_socket.get());
      }

      // TODO: Fix the race that requires this sleep.
      std::this_thread::sleep_for(50ms);

      pid_t read_pid;
      ASSERT_TRUE(android::base::ReadFully(output_fd.get(), &read_pid, sizeof(read_pid)));
      ASSERT_EQ(read_pid, pid);
    }
  });

  start = true;

  for (std::thread& thread : threads) {
    thread.join();
  }
}

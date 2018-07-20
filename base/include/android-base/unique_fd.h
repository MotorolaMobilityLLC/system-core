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

#pragma once

#include <fcntl.h>

#if !defined(_WIN32)
#include <sys/socket.h>
#endif

#include <sys/types.h>
#include <unistd.h>

// DO NOT INCLUDE OTHER LIBBASE HEADERS!
// This file gets used in libbinder, and libbinder is used everywhere.
// Including other headers from libbase frequently results in inclusion of
// android-base/macros.h, which causes macro collisions.

// Container for a file descriptor that automatically closes the descriptor as
// it goes out of scope.
//
//      unique_fd ufd(open("/some/path", "r"));
//      if (ufd.get() == -1) return error;
//
//      // Do something useful, possibly including 'return'.
//
//      return 0; // Descriptor is closed for you.
//
// unique_fd is also known as ScopedFd/ScopedFD/scoped_fd; mentioned here to help
// you find this class if you're searching for one of those names.

#if defined(__BIONIC__)
#include <android/fdsan.h>
#endif

namespace android {
namespace base {

struct DefaultCloser {
#if defined(__BIONIC__)
  static void Tag(int fd, void* old_addr, void* new_addr) {
    uint64_t old_tag = android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_UNIQUE_FD,
                                                      reinterpret_cast<uint64_t>(old_addr));
    uint64_t new_tag = android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_UNIQUE_FD,
                                                      reinterpret_cast<uint64_t>(new_addr));
    android_fdsan_exchange_owner_tag(fd, old_tag, new_tag);
  }
  static void Close(int fd, void* addr) {
    uint64_t tag = android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_UNIQUE_FD,
                                                  reinterpret_cast<uint64_t>(addr));
    android_fdsan_close_with_tag(fd, tag);
  }
#else
  static void Close(int fd) {
    // Even if close(2) fails with EINTR, the fd will have been closed.
    // Using TEMP_FAILURE_RETRY will either lead to EBADF or closing someone
    // else's fd.
    // http://lkml.indiana.edu/hypermail/linux/kernel/0509.1/0877.html
    ::close(fd);
  }
#endif
};

template <typename Closer>
class unique_fd_impl final {
 public:
  unique_fd_impl() {}

  explicit unique_fd_impl(int fd) { reset(fd); }
  ~unique_fd_impl() { reset(); }

  unique_fd_impl(unique_fd_impl&& other) { reset(other.release()); }
  unique_fd_impl& operator=(unique_fd_impl&& s) {
    int fd = s.fd_;
    s.fd_ = -1;
    reset(fd, &s);
    return *this;
  }

  void reset(int new_value = -1) { reset(new_value, nullptr); }

  int get() const { return fd_; }
  operator int() const { return get(); }

  int release() __attribute__((warn_unused_result)) {
    tag(fd_, this, nullptr);
    int ret = fd_;
    fd_ = -1;
    return ret;
  }

 private:
  void reset(int new_value, void* previous_tag) {
    if (fd_ != -1) {
      close(fd_, this);
    }

    fd_ = new_value;
    if (new_value != -1) {
      tag(new_value, previous_tag, this);
    }
  }

  int fd_ = -1;

  // Template magic to use Closer::Tag if available, and do nothing if not.
  // If Closer::Tag exists, this implementation is preferred, because int is a better match.
  // If not, this implementation is SFINAEd away, and the no-op below is the only one that exists.
  template <typename T = Closer>
  static auto tag(int fd, void* old_tag, void* new_tag)
      -> decltype(T::Tag(fd, old_tag, new_tag), void()) {
    T::Tag(fd, old_tag, new_tag);
  }

  template <typename T = Closer>
  static void tag(long, void*, void*) {
    // No-op.
  }

  // Same as above, to select between Closer::Close(int) and Closer::Close(int, void*).
  template <typename T = Closer>
  static auto close(int fd, void* tag_value) -> decltype(T::Close(fd, tag_value), void()) {
    T::Close(fd, tag_value);
  }

  template <typename T = Closer>
  static auto close(int fd, void*) -> decltype(T::Close(fd), void()) {
    T::Close(fd);
  }

  unique_fd_impl(const unique_fd_impl&);
  void operator=(const unique_fd_impl&);
};

using unique_fd = unique_fd_impl<DefaultCloser>;

#if !defined(_WIN32)

// Inline functions, so that they can be used header-only.
template <typename Closer>
inline bool Pipe(unique_fd_impl<Closer>* read, unique_fd_impl<Closer>* write) {
  int pipefd[2];

#if defined(__linux__)
  if (pipe2(pipefd, O_CLOEXEC) != 0) {
    return false;
  }
#else  // defined(__APPLE__)
  if (pipe(pipefd) != 0) {
    return false;
  }

  if (fcntl(pipefd[0], F_SETFD, FD_CLOEXEC) != 0 || fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) != 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return false;
  }
#endif

  read->reset(pipefd[0]);
  write->reset(pipefd[1]);
  return true;
}

template <typename Closer>
inline bool Socketpair(int domain, int type, int protocol, unique_fd_impl<Closer>* left,
                       unique_fd_impl<Closer>* right) {
  int sockfd[2];
  if (socketpair(domain, type, protocol, sockfd) != 0) {
    return false;
  }
  left->reset(sockfd[0]);
  right->reset(sockfd[1]);
  return true;
}

template <typename Closer>
inline bool Socketpair(int type, unique_fd_impl<Closer>* left, unique_fd_impl<Closer>* right) {
  return Socketpair(AF_UNIX, type, 0, left, right);
}

#endif  // !defined(_WIN32)

}  // namespace base
}  // namespace android

template <typename T>
int close(const android::base::unique_fd_impl<T>&)
    __attribute__((__unavailable__("close called on unique_fd")));

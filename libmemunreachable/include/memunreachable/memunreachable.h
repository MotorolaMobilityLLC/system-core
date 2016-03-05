/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef LIBMEMUNREACHABLE_MEMUNREACHABLE_H_
#define LIBMEMUNREACHABLE_MEMUNREACHABLE_H_

#include <sys/cdefs.h>

#ifdef __cplusplus

#include <vector>
#include <string>

struct Leak {
  uintptr_t begin;
  size_t size;

  size_t referenced_count;
  size_t referenced_size;

  size_t num_backtrace_frames;

  static const size_t contents_length = 32;
  char contents[contents_length];

  static const size_t backtrace_length = 16;
  uintptr_t backtrace_frames[backtrace_length];

  std::string ToString(bool log_contents) const;
};

struct UnreachableMemoryInfo {
  std::vector<Leak> leaks;
  size_t num_leaks;
  size_t leak_bytes;
  size_t num_allocations;
  size_t allocation_bytes;

  UnreachableMemoryInfo() {}
  ~UnreachableMemoryInfo() {
    // Clear the memory that holds the leaks, otherwise the next attempt to
    // detect leaks may find the old data (for example in the jemalloc tcache)
    // and consider all the leaks to be referenced.
    memset(leaks.data(), 0, leaks.capacity() * sizeof(Leak));
  }

  std::string ToString(bool log_contents) const;
};

bool GetUnreachableMemory(UnreachableMemoryInfo& info, size_t limit = 100);

std::string GetUnreachableMemoryString(bool log_contents = false, size_t limit = 100);

#endif

__BEGIN_DECLS

bool LogUnreachableMemory(bool log_contents, size_t limit);

bool NoLeaks();

__END_DECLS

#endif // LIBMEMUNREACHABLE_MEMUNREACHABLE_H_

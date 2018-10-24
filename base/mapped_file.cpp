/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "android-base/mapped_file.h"

namespace android {
namespace base {

static off64_t InitPageSize() {
#if defined(_WIN32)
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  return si.dwAllocationGranularity;
#else
  return sysconf(_SC_PAGE_SIZE);
#endif
}

std::unique_ptr<MappedFile> MappedFile::FromFd(int fd, off64_t offset, size_t length, int prot) {
  static off64_t page_size = InitPageSize();
  size_t slop = offset % page_size;
  off64_t file_offset = offset - slop;
  off64_t file_length = length + slop;

#if defined(_WIN32)
  HANDLE handle =
      CreateFileMapping(reinterpret_cast<HANDLE>(_get_osfhandle(fd)), nullptr,
                        (prot & PROT_WRITE) ? PAGE_READWRITE : PAGE_READONLY, 0, 0, nullptr);
  if (handle == nullptr) return nullptr;
  void* base = MapViewOfFile(handle, (prot & PROT_WRITE) ? FILE_MAP_ALL_ACCESS : FILE_MAP_READ, 0,
                             file_offset, file_length);
  if (base == nullptr) {
    CloseHandle(handle);
    return nullptr;
  }
  return std::unique_ptr<MappedFile>(
      new MappedFile{static_cast<char*>(base), length, slop, handle});
#else
  void* base = mmap(nullptr, file_length, prot, MAP_SHARED, fd, file_offset);
  if (base == MAP_FAILED) return nullptr;
  return std::unique_ptr<MappedFile>(new MappedFile{static_cast<char*>(base), length, slop});
#endif
}

MappedFile::~MappedFile() {
#if defined(_WIN32)
  if (base_ != nullptr) UnmapViewOfFile(base_);
  if (handle_ != nullptr) CloseHandle(handle_);
#else
  if (base_ != nullptr) munmap(base_, size_);
#endif

  base_ = nullptr;
  offset_ = size_ = 0;
}

}  // namespace base
}  // namespace android

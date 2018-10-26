/*
 * Copyright (C) 2013 The Android Open Source Project
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

/*
 * Read-only access to Zip archives, with minimal heap allocation.
 */

#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/types.h>

#include "android-base/off64_t.h"

/* Zip compression methods we support */
enum {
  kCompressStored = 0,    // no compression
  kCompressDeflated = 8,  // standard deflate
};

struct ZipString {
  const uint8_t* name;
  uint16_t name_length;

  ZipString() {}

  /*
   * entry_name has to be an c-style string with only ASCII characters.
   */
  explicit ZipString(const char* entry_name);

  bool operator==(const ZipString& rhs) const {
    return name && (name_length == rhs.name_length) && (memcmp(name, rhs.name, name_length) == 0);
  }

  bool StartsWith(const ZipString& prefix) const {
    return name && (name_length >= prefix.name_length) &&
           (memcmp(name, prefix.name, prefix.name_length) == 0);
  }

  bool EndsWith(const ZipString& suffix) const {
    return name && (name_length >= suffix.name_length) &&
           (memcmp(name + name_length - suffix.name_length, suffix.name, suffix.name_length) == 0);
  }
};

/*
 * Represents information about a zip entry in a zip file.
 */
struct ZipEntry {
  // Compression method: One of kCompressStored or
  // kCompressDeflated.
  uint16_t method;

  // Modification time. The zipfile format specifies
  // that the first two little endian bytes contain the time
  // and the last two little endian bytes contain the date.
  // See `GetModificationTime`.
  // TODO: should be overridden by extra time field, if present.
  uint32_t mod_time;

  // Returns `mod_time` as a broken-down struct tm.
  struct tm GetModificationTime() const;

  // Suggested Unix mode for this entry, from the zip archive if created on
  // Unix, or a default otherwise.
  mode_t unix_mode;

  // 1 if this entry contains a data descriptor segment, 0
  // otherwise.
  uint8_t has_data_descriptor;

  // Crc32 value of this ZipEntry. This information might
  // either be stored in the local file header or in a special
  // Data descriptor footer at the end of the file entry.
  uint32_t crc32;

  // Compressed length of this ZipEntry. Might be present
  // either in the local file header or in the data descriptor
  // footer.
  uint32_t compressed_length;

  // Uncompressed length of this ZipEntry. Might be present
  // either in the local file header or in the data descriptor
  // footer.
  uint32_t uncompressed_length;

  // The offset to the start of data for this ZipEntry.
  off64_t offset;
};

struct ZipArchive;
typedef ZipArchive* ZipArchiveHandle;

/*
 * Open a Zip archive, and sets handle to the value of the opaque
 * handle for the file. This handle must be released by calling
 * CloseArchive with this handle.
 *
 * Returns 0 on success, and negative values on failure.
 */
int32_t OpenArchive(const char* fileName, ZipArchiveHandle* handle);

/*
 * Like OpenArchive, but takes a file descriptor open for reading
 * at the start of the file.  The descriptor must be mappable (this does
 * not allow access to a stream).
 *
 * Sets handle to the value of the opaque handle for this file descriptor.
 * This handle must be released by calling CloseArchive with this handle.
 *
 * If assume_ownership parameter is 'true' calling CloseArchive will close
 * the file.
 *
 * This function maps and scans the central directory and builds a table
 * of entries for future lookups.
 *
 * "debugFileName" will appear in error messages, but is not otherwise used.
 *
 * Returns 0 on success, and negative values on failure.
 */
int32_t OpenArchiveFd(const int fd, const char* debugFileName, ZipArchiveHandle* handle,
                      bool assume_ownership = true);

int32_t OpenArchiveFromMemory(void* address, size_t length, const char* debugFileName,
                              ZipArchiveHandle* handle);
/*
 * Close archive, releasing resources associated with it. This will
 * unmap the central directory of the zipfile and free all internal
 * data structures associated with the file. It is an error to use
 * this handle for any further operations without an intervening
 * call to one of the OpenArchive variants.
 */
void CloseArchive(ZipArchiveHandle archive);

/*
 * Find an entry in the Zip archive, by name. |entryName| must be a null
 * terminated string, and |data| must point to a writeable memory location.
 *
 * Returns 0 if an entry is found, and populates |data| with information
 * about this entry. Returns negative values otherwise.
 *
 * It's important to note that |data->crc32|, |data->compLen| and
 * |data->uncompLen| might be set to values from the central directory
 * if this file entry contains a data descriptor footer. To verify crc32s
 * and length, a call to VerifyCrcAndLengths must be made after entry data
 * has been processed.
 *
 * On non-Windows platforms this method does not modify internal state and
 * can be called concurrently.
 */
int32_t FindEntry(const ZipArchiveHandle archive, const ZipString& entryName, ZipEntry* data);

/*
 * Start iterating over all entries of a zip file. The order of iteration
 * is not guaranteed to be the same as the order of elements
 * in the central directory but is stable for a given zip file. |cookie| will
 * contain the value of an opaque cookie which can be used to make one or more
 * calls to Next. All calls to StartIteration must be matched by a call to
 * EndIteration to free any allocated memory.
 *
 * This method also accepts optional prefix and suffix to restrict iteration to
 * entry names that start with |optional_prefix| or end with |optional_suffix|.
 *
 * Returns 0 on success and negative values on failure.
 */
int32_t StartIteration(ZipArchiveHandle archive, void** cookie_ptr,
                       const ZipString* optional_prefix, const ZipString* optional_suffix);

/*
 * Advance to the next element in the zipfile in iteration order.
 *
 * Returns 0 on success, -1 if there are no more elements in this
 * archive and lower negative values on failure.
 */
int32_t Next(void* cookie, ZipEntry* data, ZipString* name);

/*
 * End iteration over all entries of a zip file and frees the memory allocated
 * in StartIteration.
 */
void EndIteration(void* cookie);

/*
 * Uncompress and write an entry to an open file identified by |fd|.
 * |entry->uncompressed_length| bytes will be written to the file at
 * its current offset, and the file will be truncated at the end of
 * the uncompressed data (no truncation if |fd| references a block
 * device).
 *
 * Returns 0 on success and negative values on failure.
 */
int32_t ExtractEntryToFile(ZipArchiveHandle archive, ZipEntry* entry, int fd);

/**
 * Uncompress a given zip entry to the memory region at |begin| and of
 * size |size|. This size is expected to be the same as the *declared*
 * uncompressed length of the zip entry. It is an error if the *actual*
 * number of uncompressed bytes differs from this number.
 *
 * Returns 0 on success and negative values on failure.
 */
int32_t ExtractToMemory(ZipArchiveHandle archive, ZipEntry* entry, uint8_t* begin, uint32_t size);

int GetFileDescriptor(const ZipArchiveHandle archive);

const char* ErrorCodeString(int32_t error_code);

#if !defined(_WIN32)
typedef bool (*ProcessZipEntryFunction)(const uint8_t* buf, size_t buf_size, void* cookie);

/*
 * Stream the uncompressed data through the supplied function,
 * passing cookie to it each time it gets called.
 */
int32_t ProcessZipEntryContents(ZipArchiveHandle archive, ZipEntry* entry,
                                ProcessZipEntryFunction func, void* cookie);
#endif

namespace zip_archive {

class Writer {
 public:
  virtual bool Append(uint8_t* buf, size_t buf_size) = 0;
  virtual ~Writer();

 protected:
  Writer() = default;

 private:
  Writer(const Writer&) = delete;
  void operator=(const Writer&) = delete;
};

class Reader {
 public:
  virtual bool ReadAtOffset(uint8_t* buf, size_t len, uint32_t offset) const = 0;
  virtual ~Reader();

 protected:
  Reader() = default;

 private:
  Reader(const Reader&) = delete;
  void operator=(const Reader&) = delete;
};

/*
 * Inflates the first |compressed_length| bytes of |reader| to a given |writer|.
 * |crc_out| is set to the CRC32 checksum of the uncompressed data.
 *
 * Returns 0 on success and negative values on failure, for example if |reader|
 * cannot supply the right amount of data, or if the number of bytes written to
 * data does not match |uncompressed_length|.
 *
 * If |crc_out| is not nullptr, it is set to the crc32 checksum of the
 * uncompressed data.
 */
int32_t Inflate(const Reader& reader, const uint32_t compressed_length,
                const uint32_t uncompressed_length, Writer* writer, uint64_t* crc_out);
}  // namespace zip_archive

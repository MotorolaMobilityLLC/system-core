/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Read-only access to Zip archives, with minimal heap allocation.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utils/Compat.h>
#include <utils/FileMap.h>
#include <zlib.h>

#include <JNIHelp.h>  // TEMP_FAILURE_RETRY may or may not be in unistd

#include "ziparchive/zip_archive.h"

// This is for windows. If we don't open a file in binary mode, weirds
// things will happen.
#ifndef O_BINARY
#define O_BINARY 0
#endif

/*
 * Zip file constants.
 */
static const uint32_t kEOCDSignature    = 0x06054b50;
static const uint32_t kEOCDLen          = 2;
static const uint32_t kEOCDNumEntries   = 8;              // offset to #of entries in file
static const uint32_t kEOCDSize         = 12;             // size of the central directory
static const uint32_t kEOCDFileOffset   = 16;             // offset to central directory

static const uint32_t kMaxCommentLen    = 65535;          // longest possible in ushort
static const uint32_t kMaxEOCDSearch    = (kMaxCommentLen + kEOCDLen);

static const uint32_t kLFHSignature     = 0x04034b50;
static const uint32_t kLFHLen           = 30;             // excluding variable-len fields
static const uint32_t kLFHGPBFlags      = 6;              // general purpose bit flags
static const uint32_t kLFHCRC           = 14;             // offset to CRC
static const uint32_t kLFHCompLen       = 18;             // offset to compressed length
static const uint32_t kLFHUncompLen     = 22;             // offset to uncompressed length
static const uint32_t kLFHNameLen       = 26;             // offset to filename length
static const uint32_t kLFHExtraLen      = 28;             // offset to extra length

static const uint32_t kCDESignature     = 0x02014b50;
static const uint32_t kCDELen           = 46;             // excluding variable-len fields
static const uint32_t kCDEMethod        = 10;             // offset to compression method
static const uint32_t kCDEModWhen       = 12;             // offset to modification timestamp
static const uint32_t kCDECRC           = 16;             // offset to entry CRC
static const uint32_t kCDECompLen       = 20;             // offset to compressed length
static const uint32_t kCDEUncompLen     = 24;             // offset to uncompressed length
static const uint32_t kCDENameLen       = 28;             // offset to filename length
static const uint32_t kCDEExtraLen      = 30;             // offset to extra length
static const uint32_t kCDECommentLen    = 32;             // offset to comment length
static const uint32_t kCDELocalOffset   = 42;             // offset to local hdr

static const uint32_t kDDOptSignature   = 0x08074b50;     // *OPTIONAL* data descriptor signature
static const uint32_t kDDSignatureLen   = 4;
static const uint32_t kDDLen            = 12;
static const uint32_t kDDMaxLen         = 16;             // max of 16 bytes with a signature, 12 bytes without
static const uint32_t kDDCrc32          = 0;              // offset to crc32
static const uint32_t kDDCompLen        = 4;              // offset to compressed length
static const uint32_t kDDUncompLen      = 8;              // offset to uncompressed length

static const uint32_t kGPBDDFlagMask    = 0x0008;         // mask value that signifies that the entry has a DD

static const uint32_t kMaxErrorLen = 1024;

static const char* kErrorMessages[] = {
  "Unknown return code.",
  "Iteration ended",
  "Zlib error",
  "Invalid file",
  "Invalid handle",
  "Duplicate entries in archive",
  "Empty archive",
  "Entry not found",
  "Invalid offset",
  "Inconsistent information",
  "Invalid entry name",
  "I/O Error",
  "File mapping failed"
};

static const int32_t kErrorMessageUpperBound = 0;

static const int32_t kIterationEnd = -1;

// We encountered a Zlib error when inflating a stream from this file.
// Usually indicates file corruption.
static const int32_t kZlibError = -2;

// The input file cannot be processed as a zip archive. Usually because
// it's too small, too large or does not have a valid signature.
static const int32_t kInvalidFile = -3;

// An invalid iteration / ziparchive handle was passed in as an input
// argument.
static const int32_t kInvalidHandle = -4;

// The zip archive contained two (or possibly more) entries with the same
// name.
static const int32_t kDuplicateEntry = -5;

// The zip archive contains no entries.
static const int32_t kEmptyArchive = -6;

// The specified entry was not found in the archive.
static const int32_t kEntryNotFound = -7;

// The zip archive contained an invalid local file header pointer.
static const int32_t kInvalidOffset = -8;

// The zip archive contained inconsistent entry information. This could
// be because the central directory & local file header did not agree, or
// if the actual uncompressed length or crc32 do not match their declared
// values.
static const int32_t kInconsistentInformation = -9;

// An invalid entry name was encountered.
static const int32_t kInvalidEntryName = -10;

// An I/O related system call (read, lseek, ftruncate, map) failed.
static const int32_t kIoError = -11;

// We were not able to mmap the central directory or entry contents.
static const int32_t kMmapFailed = -12;

static const int32_t kErrorMessageLowerBound = -13;

static const char kTempMappingFileName[] = "zip: ExtractFileToFile";

/*
 * A Read-only Zip archive.
 *
 * We want "open" and "find entry by name" to be fast operations, and
 * we want to use as little memory as possible.  We memory-map the zip
 * central directory, and load a hash table with pointers to the filenames
 * (which aren't null-terminated).  The other fields are at a fixed offset
 * from the filename, so we don't need to extract those (but we do need
 * to byte-read and endian-swap them every time we want them).
 *
 * It's possible that somebody has handed us a massive (~1GB) zip archive,
 * so we can't expect to mmap the entire file.
 *
 * To speed comparisons when doing a lookup by name, we could make the mapping
 * "private" (copy-on-write) and null-terminate the filenames after verifying
 * the record structure.  However, this requires a private mapping of
 * every page that the Central Directory touches.  Easier to tuck a copy
 * of the string length into the hash table entry.
 */
struct ZipArchive {
  /* open Zip archive */
  int fd;

  /* mapped central directory area */
  off64_t directory_offset;
  android::FileMap* directory_map;

  /* number of entries in the Zip archive */
  uint16_t num_entries;

  /*
   * We know how many entries are in the Zip archive, so we can have a
   * fixed-size hash table. We define a load factor of 0.75 and overallocat
   * so the maximum number entries can never be higher than
   * ((4 * UINT16_MAX) / 3 + 1) which can safely fit into a uint32_t.
   */
  uint32_t hash_table_size;
  ZipEntryName* hash_table;
};

// Returns 0 on success and negative values on failure.
static android::FileMap* MapFileSegment(const int fd, const off64_t start,
                                        const size_t length, const bool read_only,
                                        const char* debug_file_name) {
  android::FileMap* file_map = new android::FileMap;
  const bool success = file_map->create(debug_file_name, fd, start, length, read_only);
  if (!success) {
    file_map->release();
    return NULL;
  }

  return file_map;
}

static int32_t CopyFileToFile(int fd, uint8_t* begin, const uint32_t length, uint64_t *crc_out) {
  static const uint32_t kBufSize = 32768;
  uint8_t buf[kBufSize];

  uint32_t count = 0;
  uint64_t crc = 0;
  while (count < length) {
    uint32_t remaining = length - count;

    // Safe conversion because kBufSize is narrow enough for a 32 bit signed
    // value.
    ssize_t get_size = (remaining > kBufSize) ? kBufSize : remaining;
    ssize_t actual = TEMP_FAILURE_RETRY(read(fd, buf, get_size));

    if (actual != get_size) {
      ALOGW("CopyFileToFile: copy read failed (" ZD " vs " ZD ")", actual, get_size);
      return kIoError;
    }

    memcpy(begin + count, buf, get_size);
    crc = crc32(crc, buf, get_size);
    count += get_size;
  }

  *crc_out = crc;

  return 0;
}

/*
 * Round up to the next highest power of 2.
 *
 * Found on http://graphics.stanford.edu/~seander/bithacks.html.
 */
static uint32_t RoundUpPower2(uint32_t val) {
  val--;
  val |= val >> 1;
  val |= val >> 2;
  val |= val >> 4;
  val |= val >> 8;
  val |= val >> 16;
  val++;

  return val;
}

static uint32_t ComputeHash(const char* str, uint16_t len) {
  uint32_t hash = 0;

  while (len--) {
    hash = hash * 31 + *str++;
  }

  return hash;
}

/*
 * Convert a ZipEntry to a hash table index, verifying that it's in a
 * valid range.
 */
static int64_t EntryToIndex(const ZipEntryName* hash_table,
                            const uint32_t hash_table_size,
                            const char* name, uint16_t length) {
  const uint32_t hash = ComputeHash(name, length);

  // NOTE: (hash_table_size - 1) is guaranteed to be non-negative.
  uint32_t ent = hash & (hash_table_size - 1);
  while (hash_table[ent].name != NULL) {
    if (hash_table[ent].name_length == length &&
        memcmp(hash_table[ent].name, name, length) == 0) {
      return ent;
    }

    ent = (ent + 1) & (hash_table_size - 1);
  }

  ALOGV("Zip: Unable to find entry %.*s", length, name);
  return kEntryNotFound;
}

/*
 * Add a new entry to the hash table.
 */
static int32_t AddToHash(ZipEntryName *hash_table, const uint64_t hash_table_size,
                         const char* name, uint16_t length) {
  const uint64_t hash = ComputeHash(name, length);
  uint32_t ent = hash & (hash_table_size - 1);

  /*
   * We over-allocated the table, so we're guaranteed to find an empty slot.
   * Further, we guarantee that the hashtable size is not 0.
   */
  while (hash_table[ent].name != NULL) {
    if (hash_table[ent].name_length == length &&
        memcmp(hash_table[ent].name, name, length) == 0) {
      // We've found a duplicate entry. We don't accept it
      ALOGW("Zip: Found duplicate entry %.*s", length, name);
      return kDuplicateEntry;
    }
    ent = (ent + 1) & (hash_table_size - 1);
  }

  hash_table[ent].name = name;
  hash_table[ent].name_length = length;
  return 0;
}

/*
 * Get 2 little-endian bytes.
 */
static uint16_t get2LE(const uint8_t* src) {
  return src[0] | (src[1] << 8);
}

/*
 * Get 4 little-endian bytes.
 */
static uint32_t get4LE(const uint8_t* src) {
  uint32_t result;

  result = src[0];
  result |= src[1] << 8;
  result |= src[2] << 16;
  result |= src[3] << 24;

  return result;
}

static int32_t MapCentralDirectory0(int fd, const char* debug_file_name,
                                    ZipArchive* archive, off64_t file_length,
                                    uint32_t read_amount, uint8_t* scan_buffer) {
  const off64_t search_start = file_length - read_amount;

  if (lseek64(fd, search_start, SEEK_SET) != search_start) {
    ALOGW("Zip: seek %" PRId64 " failed: %s", search_start, strerror(errno));
    return kIoError;
  }
  ssize_t actual = TEMP_FAILURE_RETRY(read(fd, scan_buffer, read_amount));
  if (actual != (ssize_t) read_amount) {
    ALOGW("Zip: read %" PRIu32 " failed: %s", read_amount, strerror(errno));
    return kIoError;
  }

  /*
   * Scan backward for the EOCD magic.  In an archive without a trailing
   * comment, we'll find it on the first try.  (We may want to consider
   * doing an initial minimal read; if we don't find it, retry with a
   * second read as above.)
   */
  int i;
  for (i = read_amount - kEOCDLen; i >= 0; i--) {
    if (scan_buffer[i] == 0x50 && get4LE(&scan_buffer[i]) == kEOCDSignature) {
      ALOGV("+++ Found EOCD at buf+%d", i);
      break;
    }
  }
  if (i < 0) {
    ALOGD("Zip: EOCD not found, %s is not zip", debug_file_name);
    return kInvalidFile;
  }

  const off64_t eocd_offset = search_start + i;
  const uint8_t* eocd_ptr = scan_buffer + i;

  assert(eocd_offset < file_length);

  /*
   * Grab the CD offset and size, and the number of entries in the
   * archive.  Verify that they look reasonable. Widen dir_size and
   * dir_offset to the file offset type.
   */
  const uint16_t num_entries = get2LE(eocd_ptr + kEOCDNumEntries);
  const off64_t dir_size = get4LE(eocd_ptr + kEOCDSize);
  const off64_t dir_offset = get4LE(eocd_ptr + kEOCDFileOffset);

  if (dir_offset + dir_size > eocd_offset) {
    ALOGW("Zip: bad offsets (dir %" PRId64 ", size %" PRId64 ", eocd %" PRId64 ")",
        dir_offset, dir_size, eocd_offset);
    return kInvalidOffset;
  }
  if (num_entries == 0) {
    ALOGW("Zip: empty archive?");
    return kEmptyArchive;
  }

  ALOGV("+++ num_entries=%d dir_size=%" PRId64 " dir_offset=%" PRId64,
        num_entries, dir_size, dir_offset);

  /*
   * It all looks good.  Create a mapping for the CD, and set the fields
   * in archive.
   */
  android::FileMap* map = MapFileSegment(fd, dir_offset, dir_size,
                                         true /* read only */, debug_file_name);
  if (map == NULL) {
    archive->directory_map = NULL;
    return kMmapFailed;
  }

  archive->directory_map = map;
  archive->num_entries = num_entries;
  archive->directory_offset = dir_offset;

  return 0;
}

/*
 * Find the zip Central Directory and memory-map it.
 *
 * On success, returns 0 after populating fields from the EOCD area:
 *   directory_offset
 *   directory_map
 *   num_entries
 */
static int32_t MapCentralDirectory(int fd, const char* debug_file_name,
                                   ZipArchive* archive) {

  // Test file length. We use lseek64 to make sure the file
  // is small enough to be a zip file (Its size must be less than
  // 0xffffffff bytes).
  off64_t file_length = lseek64(fd, 0, SEEK_END);
  if (file_length == -1) {
    ALOGV("Zip: lseek on fd %d failed", fd);
    return kInvalidFile;
  }

  if (file_length > (off64_t) 0xffffffff) {
    ALOGV("Zip: zip file too long %" PRId64, (int64_t)file_length);
    return kInvalidFile;
  }

  if (file_length < (int64_t) kEOCDLen) {
    ALOGV("Zip: length %" PRId64 " is too small to be zip", (int64_t)file_length);
    return kInvalidFile;
  }

  /*
   * Perform the traditional EOCD snipe hunt.
   *
   * We're searching for the End of Central Directory magic number,
   * which appears at the start of the EOCD block.  It's followed by
   * 18 bytes of EOCD stuff and up to 64KB of archive comment.  We
   * need to read the last part of the file into a buffer, dig through
   * it to find the magic number, parse some values out, and use those
   * to determine the extent of the CD.
   *
   * We start by pulling in the last part of the file.
   */
  uint32_t read_amount = kMaxEOCDSearch;
  if (file_length < (off64_t) read_amount) {
    read_amount = file_length;
  }

  uint8_t* scan_buffer = (uint8_t*) malloc(read_amount);
  int32_t result = MapCentralDirectory0(fd, debug_file_name, archive,
                                        file_length, read_amount, scan_buffer);

  free(scan_buffer);
  return result;
}

/*
 * Parses the Zip archive's Central Directory.  Allocates and populates the
 * hash table.
 *
 * Returns 0 on success.
 */
static int32_t ParseZipArchive(ZipArchive* archive) {
  int32_t result = -1;
  const uint8_t* cd_ptr = (const uint8_t*) archive->directory_map->getDataPtr();
  size_t cd_length = archive->directory_map->getDataLength();
  uint16_t num_entries = archive->num_entries;

  /*
   * Create hash table.  We have a minimum 75% load factor, possibly as
   * low as 50% after we round off to a power of 2.  There must be at
   * least one unused entry to avoid an infinite loop during creation.
   */
  archive->hash_table_size = RoundUpPower2(1 + (num_entries * 4) / 3);
  archive->hash_table = (ZipEntryName*) calloc(archive->hash_table_size,
      sizeof(ZipEntryName));

  /*
   * Walk through the central directory, adding entries to the hash
   * table and verifying values.
   */
  const uint8_t* ptr = cd_ptr;
  for (uint16_t i = 0; i < num_entries; i++) {
    if (get4LE(ptr) != kCDESignature) {
      ALOGW("Zip: missed a central dir sig (at %" PRIu16 ")", i);
      goto bail;
    }

    if (ptr + kCDELen > cd_ptr + cd_length) {
      ALOGW("Zip: ran off the end (at %" PRIu16 ")", i);
      goto bail;
    }

    const off64_t local_header_offset = get4LE(ptr + kCDELocalOffset);
    if (local_header_offset >= archive->directory_offset) {
      ALOGW("Zip: bad LFH offset %" PRId64 " at entry %" PRIu16, (int64_t)local_header_offset, i);
      goto bail;
    }

    const uint16_t file_name_length = get2LE(ptr + kCDENameLen);
    const uint16_t extra_length = get2LE(ptr + kCDEExtraLen);
    const uint16_t comment_length = get2LE(ptr + kCDECommentLen);

    /* add the CDE filename to the hash table */
    const int add_result = AddToHash(archive->hash_table,
        archive->hash_table_size, (const char*) ptr + kCDELen, file_name_length);
    if (add_result) {
      ALOGW("Zip: Error adding entry to hash table %d", add_result);
      result = add_result;
      goto bail;
    }

    ptr += kCDELen + file_name_length + extra_length + comment_length;
    if ((size_t)(ptr - cd_ptr) > cd_length) {
      ALOGW("Zip: bad CD advance (%tu vs %zu) at entry %" PRIu16,
          ptr - cd_ptr, cd_length, i);
      goto bail;
    }
  }
  ALOGV("+++ zip good scan %" PRIu16 " entries", num_entries);

  result = 0;

bail:
  return result;
}

static int32_t OpenArchiveInternal(ZipArchive* archive,
                                   const char* debug_file_name) {
  int32_t result = -1;
  if ((result = MapCentralDirectory(archive->fd, debug_file_name, archive))) {
    return result;
  }

  if ((result = ParseZipArchive(archive))) {
    return result;
  }

  return 0;
}

int32_t OpenArchiveFd(int fd, const char* debug_file_name,
                      ZipArchiveHandle* handle) {
  ZipArchive* archive = (ZipArchive*) malloc(sizeof(ZipArchive));
  memset(archive, 0, sizeof(*archive));
  *handle = archive;

  archive->fd = fd;

  return OpenArchiveInternal(archive, debug_file_name);
}

int32_t OpenArchive(const char* fileName, ZipArchiveHandle* handle) {
  ZipArchive* archive = (ZipArchive*) malloc(sizeof(ZipArchive));
  memset(archive, 0, sizeof(*archive));
  *handle = archive;

  const int fd = open(fileName, O_RDONLY | O_BINARY, 0);
  if (fd < 0) {
    ALOGW("Unable to open '%s': %s", fileName, strerror(errno));
    return kIoError;
  } else {
    archive->fd = fd;
  }

  return OpenArchiveInternal(archive, fileName);
}

/*
 * Close a ZipArchive, closing the file and freeing the contents.
 */
void CloseArchive(ZipArchiveHandle handle) {
  ZipArchive* archive = (ZipArchive*) handle;
  ALOGV("Closing archive %p", archive);

  if (archive->fd >= 0) {
    close(archive->fd);
  }

  if (archive->directory_map != NULL) {
    archive->directory_map->release();
  }
  free(archive->hash_table);
  free(archive);
}

static int32_t UpdateEntryFromDataDescriptor(int fd,
                                             ZipEntry *entry) {
  uint8_t ddBuf[kDDMaxLen];
  ssize_t actual = TEMP_FAILURE_RETRY(read(fd, ddBuf, sizeof(ddBuf)));
  if (actual != sizeof(ddBuf)) {
    return kIoError;
  }

  const uint32_t ddSignature = get4LE(ddBuf);
  uint16_t ddOffset = 0;
  if (ddSignature == kDDOptSignature) {
    ddOffset = 4;
  }

  entry->crc32 = get4LE(ddBuf + ddOffset + kDDCrc32);
  entry->compressed_length = get4LE(ddBuf + ddOffset + kDDCompLen);
  entry->uncompressed_length = get4LE(ddBuf + ddOffset + kDDUncompLen);

  return 0;
}

// Attempts to read |len| bytes into |buf| at offset |off|.
//
// This method uses pread64 on platforms that support it and
// lseek64 + read on platforms that don't. This implies that
// callers should not rely on the |fd| offset being incremented
// as a side effect of this call.
static inline ssize_t ReadAtOffset(int fd, uint8_t* buf, size_t len,
                                   off64_t off) {
#ifdef HAVE_PREAD
  return TEMP_FAILURE_RETRY(pread64(fd, buf, len, off));
#else
  // The only supported platform that doesn't support pread at the moment
  // is Windows. Only recent versions of windows support unix like forks,
  // and even there the semantics are quite different.
  if (lseek64(fd, off, SEEK_SET) != off) {
    ALOGW("Zip: failed seek to offset %" PRId64, off);
    return kIoError;
  }

  return TEMP_FAILURE_RETRY(read(fd, buf, len));
#endif  // HAVE_PREAD
}

static int32_t FindEntry(const ZipArchive* archive, const int ent,
                         ZipEntry* data) {
  const uint16_t nameLen = archive->hash_table[ent].name_length;
  const char* name = archive->hash_table[ent].name;

  // Recover the start of the central directory entry from the filename
  // pointer.  The filename is the first entry past the fixed-size data,
  // so we can just subtract back from that.
  const unsigned char* ptr = (const unsigned char*) name;
  ptr -= kCDELen;

  // This is the base of our mmapped region, we have to sanity check that
  // the name that's in the hash table is a pointer to a location within
  // this mapped region.
  const unsigned char* base_ptr = (const unsigned char*)
    archive->directory_map->getDataPtr();
  if (ptr < base_ptr || ptr > base_ptr + archive->directory_map->getDataLength()) {
    ALOGW("Zip: Invalid entry pointer");
    return kInvalidOffset;
  }

  // The offset of the start of the central directory in the zipfile.
  // We keep this lying around so that we can sanity check all our lengths
  // and our per-file structures.
  const off64_t cd_offset = archive->directory_offset;

  // Fill out the compression method, modification time, crc32
  // and other interesting attributes from the central directory. These
  // will later be compared against values from the local file header.
  data->method = get2LE(ptr + kCDEMethod);
  data->mod_time = get4LE(ptr + kCDEModWhen);
  data->crc32 = get4LE(ptr + kCDECRC);
  data->compressed_length = get4LE(ptr + kCDECompLen);
  data->uncompressed_length = get4LE(ptr + kCDEUncompLen);

  // Figure out the local header offset from the central directory. The
  // actual file data will begin after the local header and the name /
  // extra comments.
  const off64_t local_header_offset = get4LE(ptr + kCDELocalOffset);
  if (local_header_offset + (off64_t) kLFHLen >= cd_offset) {
    ALOGW("Zip: bad local hdr offset in zip");
    return kInvalidOffset;
  }

  uint8_t lfh_buf[kLFHLen];
  ssize_t actual = ReadAtOffset(archive->fd, lfh_buf, sizeof(lfh_buf),
                                 local_header_offset);
  if (actual != sizeof(lfh_buf)) {
    ALOGW("Zip: failed reading lfh name from offset %" PRId64, (int64_t)local_header_offset);
    return kIoError;
  }

  if (get4LE(lfh_buf) != kLFHSignature) {
    ALOGW("Zip: didn't find signature at start of lfh, offset=%" PRId64,
        (int64_t)local_header_offset);
    return kInvalidOffset;
  }

  // Paranoia: Match the values specified in the local file header
  // to those specified in the central directory.
  const uint16_t lfhGpbFlags = get2LE(lfh_buf + kLFHGPBFlags);
  const uint16_t lfhNameLen = get2LE(lfh_buf + kLFHNameLen);
  const uint16_t lfhExtraLen = get2LE(lfh_buf + kLFHExtraLen);

  if ((lfhGpbFlags & kGPBDDFlagMask) == 0) {
    const uint32_t lfhCrc = get4LE(lfh_buf + kLFHCRC);
    const uint32_t lfhCompLen = get4LE(lfh_buf + kLFHCompLen);
    const uint32_t lfhUncompLen = get4LE(lfh_buf + kLFHUncompLen);

    data->has_data_descriptor = 0;
    if (data->compressed_length != lfhCompLen || data->uncompressed_length != lfhUncompLen
        || data->crc32 != lfhCrc) {
      ALOGW("Zip: size/crc32 mismatch. expected {%" PRIu32 ", %" PRIu32
        ", %" PRIx32 "}, was {%" PRIu32 ", %" PRIu32 ", %" PRIx32 "}",
        data->compressed_length, data->uncompressed_length, data->crc32,
        lfhCompLen, lfhUncompLen, lfhCrc);
      return kInconsistentInformation;
    }
  } else {
    data->has_data_descriptor = 1;
  }

  // Check that the local file header name matches the declared
  // name in the central directory.
  if (lfhNameLen == nameLen) {
    const off64_t name_offset = local_header_offset + kLFHLen;
    if (name_offset + lfhNameLen >= cd_offset) {
      ALOGW("Zip: Invalid declared length");
      return kInvalidOffset;
    }

    uint8_t* name_buf = (uint8_t*) malloc(nameLen);
    ssize_t actual = ReadAtOffset(archive->fd, name_buf, nameLen,
                                  name_offset);

    if (actual != nameLen) {
      ALOGW("Zip: failed reading lfh name from offset %" PRId64, (int64_t)name_offset);
      free(name_buf);
      return kIoError;
    }

    if (memcmp(name, name_buf, nameLen)) {
      free(name_buf);
      return kInconsistentInformation;
    }

    free(name_buf);
  } else {
    ALOGW("Zip: lfh name did not match central directory.");
    return kInconsistentInformation;
  }

  const off64_t data_offset = local_header_offset + kLFHLen + lfhNameLen + lfhExtraLen;
  if (data_offset > cd_offset) {
    ALOGW("Zip: bad data offset %" PRId64 " in zip", (int64_t)data_offset);
    return kInvalidOffset;
  }

  if ((off64_t)(data_offset + data->compressed_length) > cd_offset) {
    ALOGW("Zip: bad compressed length in zip (%" PRId64 " + %" PRIu32 " > %" PRId64 ")",
      (int64_t)data_offset, data->compressed_length, (int64_t)cd_offset);
    return kInvalidOffset;
  }

  if (data->method == kCompressStored &&
    (off64_t)(data_offset + data->uncompressed_length) > cd_offset) {
     ALOGW("Zip: bad uncompressed length in zip (%" PRId64 " + %" PRIu32 " > %" PRId64 ")",
       data_offset, data->uncompressed_length, cd_offset);
     return kInvalidOffset;
  }

  data->offset = data_offset;
  return 0;
}

struct IterationHandle {
  uint32_t position;
  const char* prefix;
  uint16_t prefix_len;
  ZipArchive* archive;
};

int32_t StartIteration(ZipArchiveHandle handle, void** cookie_ptr, const char* prefix) {
  ZipArchive* archive = (ZipArchive *) handle;

  if (archive == NULL || archive->hash_table == NULL) {
    ALOGW("Zip: Invalid ZipArchiveHandle");
    return kInvalidHandle;
  }

  IterationHandle* cookie = (IterationHandle*) malloc(sizeof(IterationHandle));
  cookie->position = 0;
  cookie->prefix = prefix;
  cookie->archive = archive;
  if (prefix != NULL) {
    cookie->prefix_len = strlen(prefix);
  }

  *cookie_ptr = cookie ;
  return 0;
}

int32_t FindEntry(const ZipArchiveHandle handle, const char* entryName,
                  ZipEntry* data) {
  const ZipArchive* archive = (ZipArchive*) handle;
  const int nameLen = strlen(entryName);
  if (nameLen == 0 || nameLen > 65535) {
    ALOGW("Zip: Invalid filename %s", entryName);
    return kInvalidEntryName;
  }

  const int64_t ent = EntryToIndex(archive->hash_table,
    archive->hash_table_size, entryName, nameLen);

  if (ent < 0) {
    ALOGV("Zip: Could not find entry %.*s", nameLen, entryName);
    return ent;
  }

  return FindEntry(archive, ent, data);
}

int32_t Next(void* cookie, ZipEntry* data, ZipEntryName* name) {
  IterationHandle* handle = (IterationHandle *) cookie;
  if (handle == NULL) {
    return kInvalidHandle;
  }

  ZipArchive* archive = handle->archive;
  if (archive == NULL || archive->hash_table == NULL) {
    ALOGW("Zip: Invalid ZipArchiveHandle");
    return kInvalidHandle;
  }

  const uint32_t currentOffset = handle->position;
  const uint32_t hash_table_length = archive->hash_table_size;
  const ZipEntryName *hash_table = archive->hash_table;

  for (uint32_t i = currentOffset; i < hash_table_length; ++i) {
    if (hash_table[i].name != NULL &&
        (handle->prefix == NULL ||
         (memcmp(handle->prefix, hash_table[i].name, handle->prefix_len) == 0))) {
      handle->position = (i + 1);
      const int error = FindEntry(archive, i, data);
      if (!error) {
        name->name = hash_table[i].name;
        name->name_length = hash_table[i].name_length;
      }

      return error;
    }
  }

  handle->position = 0;
  return kIterationEnd;
}

static int32_t InflateToFile(int fd, const ZipEntry* entry,
                             uint8_t* begin, uint32_t length,
                             uint64_t* crc_out) {
  int32_t result = -1;
  const uint32_t kBufSize = 32768;
  uint8_t read_buf[kBufSize];
  uint8_t write_buf[kBufSize];
  z_stream zstream;
  int zerr;

  /*
   * Initialize the zlib stream struct.
   */
  memset(&zstream, 0, sizeof(zstream));
  zstream.zalloc = Z_NULL;
  zstream.zfree = Z_NULL;
  zstream.opaque = Z_NULL;
  zstream.next_in = NULL;
  zstream.avail_in = 0;
  zstream.next_out = (Bytef*) write_buf;
  zstream.avail_out = kBufSize;
  zstream.data_type = Z_UNKNOWN;

  /*
   * Use the undocumented "negative window bits" feature to tell zlib
   * that there's no zlib header waiting for it.
   */
  zerr = inflateInit2(&zstream, -MAX_WBITS);
  if (zerr != Z_OK) {
    if (zerr == Z_VERSION_ERROR) {
      ALOGE("Installed zlib is not compatible with linked version (%s)",
        ZLIB_VERSION);
    } else {
      ALOGW("Call to inflateInit2 failed (zerr=%d)", zerr);
    }

    return kZlibError;
  }

  const uint32_t uncompressed_length = entry->uncompressed_length;

  uint32_t compressed_length = entry->compressed_length;
  uint32_t write_count = 0;
  do {
    /* read as much as we can */
    if (zstream.avail_in == 0) {
      const ZD_TYPE getSize = (compressed_length > kBufSize) ? kBufSize : compressed_length;
      const ZD_TYPE actual = TEMP_FAILURE_RETRY(read(fd, read_buf, getSize));
      if (actual != getSize) {
        ALOGW("Zip: inflate read failed (" ZD " vs " ZD ")", actual, getSize);
        result = kIoError;
        goto z_bail;
      }

      compressed_length -= getSize;

      zstream.next_in = read_buf;
      zstream.avail_in = getSize;
    }

    /* uncompress the data */
    zerr = inflate(&zstream, Z_NO_FLUSH);
    if (zerr != Z_OK && zerr != Z_STREAM_END) {
      ALOGW("Zip: inflate zerr=%d (nIn=%p aIn=%u nOut=%p aOut=%u)",
          zerr, zstream.next_in, zstream.avail_in,
          zstream.next_out, zstream.avail_out);
      result = kZlibError;
      goto z_bail;
    }

    /* write when we're full or when we're done */
    if (zstream.avail_out == 0 ||
      (zerr == Z_STREAM_END && zstream.avail_out != kBufSize)) {
      const size_t write_size = zstream.next_out - write_buf;
      // The file might have declared a bogus length.
      if (write_size + write_count > length) {
        goto z_bail;
      }
      memcpy(begin + write_count, write_buf, write_size);
      write_count += write_size;

      zstream.next_out = write_buf;
      zstream.avail_out = kBufSize;
    }
  } while (zerr == Z_OK);

  assert(zerr == Z_STREAM_END);     /* other errors should've been caught */

  // stream.adler holds the crc32 value for such streams.
  *crc_out = zstream.adler;

  if (zstream.total_out != uncompressed_length || compressed_length != 0) {
    ALOGW("Zip: size mismatch on inflated file (%lu vs %" PRIu32 ")",
        zstream.total_out, uncompressed_length);
    result = kInconsistentInformation;
    goto z_bail;
  }

  result = 0;

z_bail:
  inflateEnd(&zstream);    /* free up any allocated structures */

  return result;
}

int32_t ExtractToMemory(ZipArchiveHandle handle,
                        ZipEntry* entry, uint8_t* begin, uint32_t size) {
  ZipArchive* archive = (ZipArchive*) handle;
  const uint16_t method = entry->method;
  off64_t data_offset = entry->offset;

  if (lseek64(archive->fd, data_offset, SEEK_SET) != data_offset) {
    ALOGW("Zip: lseek to data at %" PRId64 " failed", (int64_t)data_offset);
    return kIoError;
  }

  // this should default to kUnknownCompressionMethod.
  int32_t return_value = -1;
  uint64_t crc = 0;
  if (method == kCompressStored) {
    return_value = CopyFileToFile(archive->fd, begin, size, &crc);
  } else if (method == kCompressDeflated) {
    return_value = InflateToFile(archive->fd, entry, begin, size, &crc);
  }

  if (!return_value && entry->has_data_descriptor) {
    return_value = UpdateEntryFromDataDescriptor(archive->fd, entry);
    if (return_value) {
      return return_value;
    }
  }

  // TODO: Fix this check by passing the right flags to inflate2 so that
  // it calculates the CRC for us.
  if (entry->crc32 != crc && false) {
    ALOGW("Zip: crc mismatch: expected %" PRIu32 ", was %" PRIu64, entry->crc32, crc);
    return kInconsistentInformation;
  }

  return return_value;
}

int32_t ExtractEntryToFile(ZipArchiveHandle handle,
                           ZipEntry* entry, int fd) {
  const int32_t declared_length = entry->uncompressed_length;

  const off64_t current_offset = lseek64(fd, 0, SEEK_CUR);
  if (current_offset == -1) {
    ALOGW("Zip: unable to seek to current location on fd %d: %s", fd,
          strerror(errno));
    return kIoError;
  }

  int result = TEMP_FAILURE_RETRY(ftruncate(fd, declared_length + current_offset));
  if (result == -1) {
    ALOGW("Zip: unable to truncate file to %" PRId64 ": %s",
          (int64_t)(declared_length + current_offset), strerror(errno));
    return kIoError;
  }

  // Don't attempt to map a region of length 0. We still need the
  // ftruncate() though, since the API guarantees that we will truncate
  // the file to the end of the uncompressed output.
  if (declared_length == 0) {
      return 0;
  }

  android::FileMap* map  = MapFileSegment(fd, current_offset, declared_length,
                                          false, kTempMappingFileName);
  if (map == NULL) {
    return kMmapFailed;
  }

  const int32_t error = ExtractToMemory(handle, entry,
                                        reinterpret_cast<uint8_t*>(map->getDataPtr()),
                                        map->getDataLength());
  map->release();
  return error;
}

const char* ErrorCodeString(int32_t error_code) {
  if (error_code > kErrorMessageLowerBound && error_code < kErrorMessageUpperBound) {
    return kErrorMessages[error_code * -1];
  }

  return kErrorMessages[0];
}

int GetFileDescriptor(const ZipArchiveHandle handle) {
  return ((ZipArchive*) handle)->fd;
}


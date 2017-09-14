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

#include "ziparchive/zip_archive.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <unistd.h>
#include <vector>

#include <gtest/gtest.h>

static std::string test_data_dir;

static const std::string kMissingZip = "missing.zip";
static const std::string kValidZip = "valid.zip";

static const uint8_t kATxtContents[] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  '\n'
};

static const uint8_t kBTxtContents[] = {
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
  '\n'
};

static int32_t OpenArchiveWrapper(const std::string& name,
                                  ZipArchiveHandle* handle) {
  const std::string abs_path = test_data_dir + "/" + name;
  return OpenArchive(abs_path.c_str(), handle);
}

static void AssertNameEquals(const std::string& name_str,
                             const ZipEntryName& name) {
  ASSERT_EQ(name_str.size(), name.name_length);
  ASSERT_EQ(0, memcmp(name_str.c_str(), name.name, name.name_length));
}

TEST(ziparchive, Open) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  CloseArchive(handle);
}

TEST(ziparchive, OpenMissing) {
  ZipArchiveHandle handle;
  ASSERT_NE(0, OpenArchiveWrapper(kMissingZip, &handle));

  // Confirm the file descriptor is not going to be mistaken for a valid one.
  ASSERT_EQ(-1, GetFileDescriptor(handle));
}

TEST(ziparchive, Iteration) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  void* iteration_cookie;
  ASSERT_EQ(0, StartIteration(handle, &iteration_cookie, NULL));

  ZipEntry data;
  ZipEntryName name;

  // b/c.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/c.txt", name);

  // b/d.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/d.txt", name);

  // a.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("a.txt", name);

  // b.txt
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b.txt", name);

  // b/
  ASSERT_EQ(0, Next(iteration_cookie, &data, &name));
  AssertNameEquals("b/", name);

  // End of iteration.
  ASSERT_EQ(-1, Next(iteration_cookie, &data, &name));

  CloseArchive(handle);
}

TEST(ziparchive, FindEntry) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry data;
  ASSERT_EQ(0, FindEntry(handle, "a.txt", &data));

  // Known facts about a.txt, from zipinfo -v.
  ASSERT_EQ(63, data.offset);
  ASSERT_EQ(kCompressDeflated, data.method);
  ASSERT_EQ(static_cast<uint32_t>(17), data.uncompressed_length);
  ASSERT_EQ(static_cast<uint32_t>(13), data.compressed_length);
  ASSERT_EQ(0x950821c5, data.crc32);

  // An entry that doesn't exist. Should be a negative return code.
  ASSERT_LT(FindEntry(handle, "nonexistent.txt", &data), 0);

  CloseArchive(handle);
}

TEST(ziparchive, ExtractToMemory) {
  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  // An entry that's deflated.
  ZipEntry data;
  ASSERT_EQ(0, FindEntry(handle, "a.txt", &data));
  const uint32_t a_size = data.uncompressed_length;
  ASSERT_EQ(a_size, sizeof(kATxtContents));
  uint8_t* buffer = new uint8_t[a_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, a_size));
  ASSERT_EQ(0, memcmp(buffer, kATxtContents, a_size));
  delete[] buffer;

  // An entry that's stored.
  ASSERT_EQ(0, FindEntry(handle, "b.txt", &data));
  const uint32_t b_size = data.uncompressed_length;
  ASSERT_EQ(b_size, sizeof(kBTxtContents));
  buffer = new uint8_t[b_size];
  ASSERT_EQ(0, ExtractToMemory(handle, &data, buffer, b_size));
  ASSERT_EQ(0, memcmp(buffer, kBTxtContents, b_size));
  delete[] buffer;

  CloseArchive(handle);
}

static const uint32_t kEmptyEntriesZip[] = {
      0x04034b50, 0x0000000a, 0x63600000, 0x00004438, 0x00000000, 0x00000000,
      0x00090000, 0x6d65001c, 0x2e797470, 0x55747874, 0x03000954, 0x52e25c13,
      0x52e25c24, 0x000b7875, 0x42890401, 0x88040000, 0x50000013, 0x1e02014b,
      0x00000a03, 0x60000000, 0x00443863, 0x00000000, 0x00000000, 0x09000000,
      0x00001800, 0x00000000, 0xa0000000, 0x00000081, 0x706d6500, 0x742e7974,
      0x54557478, 0x13030005, 0x7552e25c, 0x01000b78, 0x00428904, 0x13880400,
      0x4b500000, 0x00000605, 0x00010000, 0x004f0001, 0x00430000, 0x00000000 };

static int make_temporary_file(const char* file_name_pattern) {
  char full_path[1024];
  // Account for differences between the host and the target.
  //
  // TODO: Maybe reuse bionic/tests/TemporaryFile.h.
  snprintf(full_path, sizeof(full_path), "/data/local/tmp/%s", file_name_pattern);
  int fd = mkstemp(full_path);
  if (fd == -1) {
    snprintf(full_path, sizeof(full_path), "/tmp/%s", file_name_pattern);
    fd = mkstemp(full_path);
  }

  return fd;
}

TEST(ziparchive, EmptyEntries) {
  char temp_file_pattern[] = "empty_entries_test_XXXXXX";
  int fd = make_temporary_file(temp_file_pattern);
  ASSERT_NE(-1, fd);
  const ssize_t file_size = sizeof(kEmptyEntriesZip);
  ASSERT_EQ(file_size, TEMP_FAILURE_RETRY(write(fd, kEmptyEntriesZip, file_size)));

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveFd(fd, "EmptyEntriesTest", &handle));

  ZipEntry entry;
  ASSERT_EQ(0, FindEntry(handle, "empty.txt", &entry));
  ASSERT_EQ(static_cast<uint32_t>(0), entry.uncompressed_length);
  uint8_t buffer[1];
  ASSERT_EQ(0, ExtractToMemory(handle, &entry, buffer, 1));

  char output_file_pattern[] = "empty_entries_output_XXXXXX";
  int output_fd = make_temporary_file(output_file_pattern);
  ASSERT_NE(-1, output_fd);
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, output_fd));

  struct stat stat_buf;
  ASSERT_EQ(0, fstat(output_fd, &stat_buf));
  ASSERT_EQ(0, stat_buf.st_size);

  close(fd);
  close(output_fd);
}

TEST(ziparchive, TrailerAfterEOCD) {
  char temp_file_pattern[] = "trailer_after_eocd_test_XXXXXX";
  int fd = make_temporary_file(temp_file_pattern);
  ASSERT_NE(-1, fd);

  // Create a file with 8 bytes of random garbage.
  static const uint8_t trailer[] = { 'A' ,'n', 'd', 'r', 'o', 'i', 'd', 'z' };
  const ssize_t file_size = sizeof(kEmptyEntriesZip);
  const ssize_t trailer_size = sizeof(trailer);
  ASSERT_EQ(file_size, TEMP_FAILURE_RETRY(write(fd, kEmptyEntriesZip, file_size)));
  ASSERT_EQ(trailer_size, TEMP_FAILURE_RETRY(write(fd, trailer, trailer_size)));

  ZipArchiveHandle handle;
  ASSERT_GT(0, OpenArchiveFd(fd, "EmptyEntriesTest", &handle));
}

TEST(ziparchive, ExtractToFile) {
  char kTempFilePattern[] = "zip_archive_input_XXXXXX";
  int fd = make_temporary_file(kTempFilePattern);
  ASSERT_NE(-1, fd);
  const uint8_t data[8] = { '1', '2', '3', '4', '5', '6', '7', '8' };
  const ssize_t data_size = sizeof(data);

  ASSERT_EQ(data_size, TEMP_FAILURE_RETRY(write(fd, data, data_size)));

  ZipArchiveHandle handle;
  ASSERT_EQ(0, OpenArchiveWrapper(kValidZip, &handle));

  ZipEntry entry;
  ASSERT_EQ(0, FindEntry(handle, "a.txt", &entry));
  ASSERT_EQ(0, ExtractEntryToFile(handle, &entry, fd));


  // Assert that the first 8 bytes of the file haven't been clobbered.
  uint8_t read_buffer[data_size];
  ASSERT_EQ(0, lseek64(fd, 0, SEEK_SET));
  ASSERT_EQ(data_size, TEMP_FAILURE_RETRY(read(fd, read_buffer, data_size)));
  ASSERT_EQ(0, memcmp(read_buffer, data, data_size));

  // Assert that the remainder of the file contains the incompressed data.
  std::vector<uint8_t> uncompressed_data(entry.uncompressed_length);
  ASSERT_EQ(static_cast<ssize_t>(entry.uncompressed_length),
            TEMP_FAILURE_RETRY(
                read(fd, &uncompressed_data[0], entry.uncompressed_length)));
  ASSERT_EQ(0, memcmp(&uncompressed_data[0], kATxtContents,
                      sizeof(kATxtContents)));

  // Assert that the total length of the file is sane
  ASSERT_EQ(data_size + static_cast<ssize_t>(sizeof(kATxtContents)),
            lseek64(fd, 0, SEEK_END));

  close(fd);
}

// A zip file whose local file header at offset zero is corrupted.
//
// ---------------
// cat foo > a.txt
// zip a.zip a.txt
// cat a.zip | xxd -i
//
// Manual changes :
// [2] = 0xff  // Corrupt the LFH signature of entry 0.
// [3] = 0xff  // Corrupt the LFH signature of entry 0.
static const uint8_t kZipFileWithBrokenLfhSignature[] = {
    //[lfh-sig-----------], [lfh contents---------------------------------
    0x50, 0x4b, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x80,
    //--------------------------------------------------------------------
    0x09, 0x4b, 0xa8, 0x65, 0x32, 0x7e, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00,
    //-------------------------------]  [file-name-----------------], [---
    0x00, 0x00, 0x05, 0x00, 0x1c, 0x00, 0x61, 0x2e, 0x74, 0x78, 0x74, 0x55,
    // entry-contents------------------------------------------------------
    0x54, 0x09, 0x00, 0x03, 0x51, 0x24, 0x8b, 0x59, 0x51, 0x24, 0x8b, 0x59,
    //--------------------------------------------------------------------
    0x75, 0x78, 0x0b, 0x00, 0x01, 0x04, 0x89, 0x42, 0x00, 0x00, 0x04, 0x88,
    //-------------------------------------], [cd-record-sig-------], [---
    0x13, 0x00, 0x00, 0x66, 0x6f, 0x6f, 0x0a, 0x50, 0x4b, 0x01, 0x02, 0x1e,
    // cd-record-----------------------------------------------------------
    0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77, 0x80, 0x09, 0x4b, 0xa8,
    //--------------------------------------------------------------------
    0x65, 0x32, 0x7e, 0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05,
    //--------------------------------------------------------------------
    0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0,
    //-]  [lfh-file-header-off-], [file-name-----------------], [extra----
    0x81, 0x00, 0x00, 0x00, 0x00, 0x61, 0x2e, 0x74, 0x78, 0x74, 0x55, 0x54,
    //--------------------------------------------------------------------
    0x05, 0x00, 0x03, 0x51, 0x24, 0x8b, 0x59, 0x75, 0x78, 0x0b, 0x00, 0x01,
    //-------------------------------------------------------], [eocd-sig-
    0x04, 0x89, 0x42, 0x00, 0x00, 0x04, 0x88, 0x13, 0x00, 0x00, 0x50, 0x4b,
    //-------], [---------------------------------------------------------
    0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x4b, 0x00,
    //-------------------------------------------]
    0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00};

TEST(ziparchive, BrokenLfhSignature) {
  char kTempFilePattern[] = "zip_archive_input_XXXXXX";
  int fd = make_temporary_file(kTempFilePattern);
  ASSERT_NE(-1, fd);

  ASSERT_EQ(static_cast<int32_t>(sizeof(kZipFileWithBrokenLfhSignature)),
      TEMP_FAILURE_RETRY(write(fd, kZipFileWithBrokenLfhSignature,
                               sizeof(kZipFileWithBrokenLfhSignature))));
  ZipArchiveHandle handle;
  ASSERT_EQ(-1, OpenArchiveFd(fd, "LeadingNonZipBytes", &handle));
  close(fd);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);

  static struct option options[] = {
    { "test_data_dir", required_argument, NULL, 't' },
    { NULL, 0, NULL, 0 }
  };

  while (true) {
    int option_index;
    const int c = getopt_long_only(argc, argv, "", options, &option_index);
    if (c == -1) {
      break;
    }

    if (c == 't') {
      test_data_dir = optarg;
    }
  }

  if (test_data_dir.size() == 0) {
    printf("Test data flag (--test_data_dir) required\n\n");
    return -1;
  }

  if (test_data_dir[0] != '/') {
    printf("Test data must be an absolute path, was %s\n\n",
           test_data_dir.c_str());
    return -2;
  }

  return RUN_ALL_TESTS();
}

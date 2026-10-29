//
// Copyright (C) 2023 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#pragma once

#include <gmock/gmock.h>
#include "fastboot_driver_interface.h"
#include "transport.h"

namespace fastboot {

class MockFastbootDriver : public IFastBootDriver {
  public:
    MOCK_METHOD(RetCode, FlashPartition, (const std::string&, android::base::borrowed_fd, uint32_t),
                (override));
    MOCK_METHOD(RetCode, FlashPartition, (const std::string&, const std::vector<char>&),
                (override));
    MOCK_METHOD(RetCode, DeletePartition, (const std::string&), (override));
    MOCK_METHOD(RetCode, Reboot, (std::string*, std::vector<std::string>*), (override));
    MOCK_METHOD(RetCode, RebootTo, (std::string, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, GetVar, (const std::string&, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, FetchToFd,
                (const std::string&, android::base::borrowed_fd, int64_t offset, int64_t size,
                 std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, Fetch,
                (const std::string&, const std::function<RetCode(const char*, uint64_t)>& write_fn,
                 int64_t offset, int64_t size, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, Download,
                (const std::string&, android::base::borrowed_fd, size_t, std::string*,
                 std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, Download,
                (android::base::borrowed_fd, size_t, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, Download,
                (const std::string&, const std::vector<char>&, std::string*,
                 std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, Download,
                (const std::vector<char>&, std::string*, std::vector<std::string>*), (override));
    MOCK_METHOD(RetCode, Download,
                (const std::string&, sparse_file*, uint32_t, size_t, size_t, bool, std::string*,
                 std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, RawCommand,
                (const std::string&, const std::string&, std::string*, std::vector<std::string>*,
                 int*),
                (override));
    MOCK_METHOD(RetCode, RawCommand,
                (const std::string&, std::string*, std::vector<std::string>*, int*), (override));
    MOCK_METHOD(RetCode, ResizePartition, (const std::string&, const std::string&), (override));
    MOCK_METHOD(RetCode, Erase, (const std::string&, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(RetCode, WaitForDisconnect, (), (override));
    MOCK_METHOD(RetCode, Flash, (const std::string&, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(std::string, Error, (), (override));
    MOCK_METHOD(RetCode, SetActive, (const std::string&, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(void, set_transport, (std::unique_ptr<Transport>), (override));
    MOCK_METHOD(RetCode, SnapshotUpdateCommand,
                (const std::string&, std::string*, std::vector<std::string>*), (override));
    MOCK_METHOD(RetCode, Boot, (std::string*, std::vector<std::string>*), (override));
    MOCK_METHOD(RetCode, Continue, (std::string*, std::vector<std::string>*), (override));
    MOCK_METHOD(RetCode, CreatePartition, (const std::string&, const std::string&), (override));
    MOCK_METHOD(RetCode, Upload, (const std::string&, std::string*, std::vector<std::string>*),
                (override));
    MOCK_METHOD(bool, GetCrashOnError, (), (const override));
    MOCK_METHOD(void, SetCrashOnError, (bool), (override));
};

}  // namespace fastboot

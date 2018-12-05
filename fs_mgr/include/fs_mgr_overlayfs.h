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

#pragma once

#include <fstab/fstab.h>

#include <string>
#include <vector>

bool fs_mgr_overlayfs_mount_all(fstab* fstab);
bool fs_mgr_overlayfs_mount_all(const std::vector<fstab_rec*>& fstab);
std::vector<std::string> fs_mgr_overlayfs_required_devices(fstab* fstab);
std::vector<std::string> fs_mgr_overlayfs_required_devices(const std::vector<fstab_rec*>& fstab);
bool fs_mgr_overlayfs_setup(const char* backing = nullptr, const char* mount_point = nullptr,
                            bool* change = nullptr);
bool fs_mgr_overlayfs_teardown(const char* mount_point = nullptr, bool* change = nullptr);
bool fs_mgr_has_shared_blocks(const std::string& mount_point, const std::string& dev);
std::string fs_mgr_get_context(const std::string& mount_point);

enum class OverlayfsValidResult {
    kNotSupported = 0,
    kOk,
    kOverrideCredsRequired,
};
OverlayfsValidResult fs_mgr_overlayfs_valid();

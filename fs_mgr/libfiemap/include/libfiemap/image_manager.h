//
// Copyright (C) 2019 The Android Open Source Project
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

#include <stdint.h>

#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include <android-base/unique_fd.h>
#include <liblp/partition_opener.h>

namespace android {
namespace fiemap {

class IImageManager {
  public:
    using IPartitionOpener = android::fs_mgr::IPartitionOpener;

    virtual ~IImageManager() {}

    // When linking to libfiemap_binder, the Open() call will use binder.
    // Otherwise, the Open() call will use the ImageManager implementation
    // below.
    static std::unique_ptr<IImageManager> Open(const std::string& dir_prefix,
                                               const std::chrono::milliseconds& timeout_ms);

    // Flags for CreateBackingImage().
    static constexpr int CREATE_IMAGE_DEFAULT = 0x0;
    static constexpr int CREATE_IMAGE_READONLY = 0x1;
    static constexpr int CREATE_IMAGE_ZERO_FILL = 0x2;

    // Create an image that can be mapped as a block-device. If |force_zero_fill|
    // is true, the image will be zero-filled. Otherwise, the initial content
    // of the image is undefined. If zero-fill is requested, and the operation
    // cannot be completed, the image will be deleted and this function will
    // return false.
    virtual bool CreateBackingImage(const std::string& name, uint64_t size, int flags) = 0;

    // Delete an image created with CreateBackingImage. Its entry will be
    // removed from the associated lp_metadata file.
    virtual bool DeleteBackingImage(const std::string& name) = 0;

    // Create a block device for an image previously created with
    // CreateBackingImage. This will wait for at most |timeout_ms| milliseconds
    // for |path| to be available, and will return false if not available in
    // the requested time. If |timeout_ms| is zero, this is NOT guaranteed to
    // return true. A timeout of 10s is recommended.
    //
    // Note that snapshots created with a readonly flag are always mapped
    // writable. The flag is persisted in the lp_metadata file however, so if
    // fs_mgr::CreateLogicalPartition(s) is used, the flag will be respected.
    virtual bool MapImageDevice(const std::string& name,
                                const std::chrono::milliseconds& timeout_ms, std::string* path) = 0;

    // Unmap a block device previously mapped with mapBackingImage.
    virtual bool UnmapImageDevice(const std::string& name) = 0;

    // Returns true whether the named backing image exists.
    virtual bool BackingImageExists(const std::string& name) = 0;

    // Returns true if the specified image is mapped to a device.
    virtual bool IsImageMapped(const std::string& name) = 0;

    // Map an image using device-mapper. This is not available over binder, and
    // is intended only for first-stage init. The returned device is a major:minor
    // device string.
    virtual bool MapImageWithDeviceMapper(const IPartitionOpener& opener, const std::string& name,
                                          std::string* dev) = 0;

    // Get all backing image names.
    virtual std::vector<std::string> GetAllBackingImages() = 0;

    // Writes |bytes| zeros to |name| file. If |bytes| is 0, then the
    // whole file if filled with zeros.
    virtual bool ZeroFillNewImage(const std::string& name, uint64_t bytes) = 0;

    // Find and remove all images and metadata for this manager.
    virtual bool RemoveAllImages() = 0;

    virtual bool UnmapImageIfExists(const std::string& name);
};

class ImageManager final : public IImageManager {
  public:
    // Return an ImageManager for the given metadata and data directories. Both
    // directories must already exist.
    static std::unique_ptr<ImageManager> Open(const std::string& metadata_dir,
                                              const std::string& data_dir);

    // Helper function that derives the metadata and data dirs given a single
    // prefix.
    static std::unique_ptr<ImageManager> Open(const std::string& dir_prefix);

    // Methods that must be implemented from IImageManager.
    bool CreateBackingImage(const std::string& name, uint64_t size, int flags) override;
    bool DeleteBackingImage(const std::string& name) override;
    bool MapImageDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms,
                        std::string* path) override;
    bool UnmapImageDevice(const std::string& name) override;
    bool BackingImageExists(const std::string& name) override;
    bool IsImageMapped(const std::string& name) override;
    bool MapImageWithDeviceMapper(const IPartitionOpener& opener, const std::string& name,
                                  std::string* dev) override;
    bool RemoveAllImages() override;

    std::vector<std::string> GetAllBackingImages();
    // Same as CreateBackingImage, but provides a progress notification.
    bool CreateBackingImage(const std::string& name, uint64_t size, int flags,
                            std::function<bool(uint64_t, uint64_t)>&& on_progress);

    // Returns true if the named partition exists. This does not check the
    // consistency of the backing image/data file.
    bool PartitionExists(const std::string& name);

    // Validates that all images still have pinned extents. This will be removed
    // once b/134588268 is fixed.
    bool Validate();

    void set_partition_opener(std::unique_ptr<IPartitionOpener>&& opener);

    // Writes |bytes| zeros at the beginning of the passed image
    bool ZeroFillNewImage(const std::string& name, uint64_t bytes);

  private:
    ImageManager(const std::string& metadata_dir, const std::string& data_dir);
    std::string GetImageHeaderPath(const std::string& name);
    std::string GetStatusFilePath(const std::string& image_name);
    bool MapWithLoopDevice(const std::string& name, const std::chrono::milliseconds& timeout_ms,
                           std::string* path);
    bool MapWithLoopDeviceList(const std::vector<std::string>& device_list, const std::string& name,
                               const std::chrono::milliseconds& timeout_ms, std::string* path);
    bool MapWithDmLinear(const IPartitionOpener& opener, const std::string& name,
                         const std::chrono::milliseconds& timeout_ms, std::string* path);
    bool UnmapImageDevice(const std::string& name, bool force);

    ImageManager(const ImageManager&) = delete;
    ImageManager& operator=(const ImageManager&) = delete;
    ImageManager& operator=(ImageManager&&) = delete;
    ImageManager(ImageManager&&) = delete;

    std::string metadata_dir_;
    std::string data_dir_;
    std::unique_ptr<IPartitionOpener> partition_opener_;
};

// RAII helper class for mapping and opening devices with an ImageManager.
class MappedDevice final {
  public:
    static std::unique_ptr<MappedDevice> Open(IImageManager* manager,
                                              const std::chrono::milliseconds& timeout_ms,
                                              const std::string& name);

    ~MappedDevice();

    int fd() const { return fd_; }
    const std::string& path() const { return path_; }

  protected:
    MappedDevice(IImageManager* manager, const std::string& name, const std::string& path);

    IImageManager* manager_;
    std::string name_;
    std::string path_;
    android::base::unique_fd fd_;
};

}  // namespace fiemap
}  // namespace android

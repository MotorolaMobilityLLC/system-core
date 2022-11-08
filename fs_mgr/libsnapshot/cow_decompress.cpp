//
// Copyright (C) 2020 The Android Open Source Project
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

#include "cow_decompress.h"

#include <utility>

#include <android-base/logging.h>
#include <brotli/decode.h>
#include <zlib.h>

namespace android {
namespace snapshot {

class NoDecompressor final : public IDecompressor {
  public:
    bool Decompress(size_t) override;
};

bool NoDecompressor::Decompress(size_t) {
    size_t stream_remaining = stream_->Size();
    while (stream_remaining) {
        size_t buffer_size = stream_remaining;
        uint8_t* buffer = reinterpret_cast<uint8_t*>(sink_->GetBuffer(buffer_size, &buffer_size));
        if (!buffer) {
            LOG(ERROR) << "Could not acquire buffer from sink";
            return false;
        }

        // Read until we can fill the buffer.
        uint8_t* buffer_pos = buffer;
        size_t bytes_to_read = std::min(buffer_size, stream_remaining);
        while (bytes_to_read) {
            size_t read;
            if (!stream_->Read(buffer_pos, bytes_to_read, &read)) {
                return false;
            }
            if (!read) {
                LOG(ERROR) << "Stream ended prematurely";
                return false;
            }
            if (!sink_->ReturnData(buffer_pos, read)) {
                LOG(ERROR) << "Could not return buffer to sink";
                return false;
            }
            buffer_pos += read;
            bytes_to_read -= read;
            stream_remaining -= read;
        }
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::Uncompressed() {
    return std::unique_ptr<IDecompressor>(new NoDecompressor());
}

// Read chunks of the COW and incrementally stream them to the decoder.
class StreamDecompressor : public IDecompressor {
  public:
    bool Decompress(size_t output_bytes) override;

    virtual bool Init() = 0;
    virtual bool DecompressInput(const uint8_t* data, size_t length) = 0;
    virtual bool Done() = 0;

  protected:
    bool GetFreshBuffer();

    size_t output_bytes_;
    size_t stream_remaining_;
    uint8_t* output_buffer_ = nullptr;
    size_t output_buffer_remaining_ = 0;
};

static constexpr size_t kChunkSize = 4096;

bool StreamDecompressor::Decompress(size_t output_bytes) {
    if (!Init()) {
        return false;
    }

    stream_remaining_ = stream_->Size();
    output_bytes_ = output_bytes;

    uint8_t chunk[kChunkSize];
    while (stream_remaining_) {
        size_t read = std::min(stream_remaining_, sizeof(chunk));
        if (!stream_->Read(chunk, read, &read)) {
            return false;
        }
        if (!read) {
            LOG(ERROR) << "Stream ended prematurely";
            return false;
        }
        if (!DecompressInput(chunk, read)) {
            return false;
        }

        stream_remaining_ -= read;

        if (stream_remaining_ && Done()) {
            LOG(ERROR) << "Decompressor terminated early";
            return false;
        }
    }
    if (!Done()) {
        LOG(ERROR) << "Decompressor expected more bytes";
        return false;
    }
    return true;
}

bool StreamDecompressor::GetFreshBuffer() {
    size_t request_size = std::min(output_bytes_, kChunkSize);
    output_buffer_ =
            reinterpret_cast<uint8_t*>(sink_->GetBuffer(request_size, &output_buffer_remaining_));
    if (!output_buffer_) {
        LOG(ERROR) << "Could not acquire buffer from sink";
        return false;
    }
    return true;
}

class GzDecompressor final : public StreamDecompressor {
  public:
    ~GzDecompressor();

    bool Init() override;
    bool DecompressInput(const uint8_t* data, size_t length) override;
    bool Done() override { return ended_; }

  private:
    z_stream z_ = {};
    bool ended_ = false;
};

bool GzDecompressor::Init() {
    if (int rv = inflateInit(&z_); rv != Z_OK) {
        LOG(ERROR) << "inflateInit returned error code " << rv;
        return false;
    }
    return true;
}

GzDecompressor::~GzDecompressor() {
    inflateEnd(&z_);
}

bool GzDecompressor::DecompressInput(const uint8_t* data, size_t length) {
    z_.next_in = reinterpret_cast<Bytef*>(const_cast<uint8_t*>(data));
    z_.avail_in = length;

    while (z_.avail_in) {
        // If no more output buffer, grab a new buffer.
        if (z_.avail_out == 0) {
            if (!GetFreshBuffer()) {
                return false;
            }
            z_.next_out = reinterpret_cast<Bytef*>(output_buffer_);
            z_.avail_out = output_buffer_remaining_;
        }

        // Remember the position of the output buffer so we can call ReturnData.
        auto avail_out = z_.avail_out;

        // Decompress.
        int rv = inflate(&z_, Z_NO_FLUSH);
        if (rv != Z_OK && rv != Z_STREAM_END) {
            LOG(ERROR) << "inflate returned error code " << rv;
            return false;
        }

        size_t returned = avail_out - z_.avail_out;
        if (!sink_->ReturnData(output_buffer_, returned)) {
            LOG(ERROR) << "Could not return buffer to sink";
            return false;
        }
        output_buffer_ += returned;
        output_buffer_remaining_ -= returned;

        if (rv == Z_STREAM_END) {
            if (z_.avail_in) {
                LOG(ERROR) << "Gz stream ended prematurely";
                return false;
            }
            ended_ = true;
            return true;
        }
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::Gz() {
    return std::unique_ptr<IDecompressor>(new GzDecompressor());
}

class BrotliDecompressor final : public StreamDecompressor {
  public:
    ~BrotliDecompressor();

    bool Init() override;
    bool DecompressInput(const uint8_t* data, size_t length) override;
    bool Done() override { return BrotliDecoderIsFinished(decoder_); }

  private:
    BrotliDecoderState* decoder_ = nullptr;
};

bool BrotliDecompressor::Init() {
    decoder_ = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
    return true;
}

BrotliDecompressor::~BrotliDecompressor() {
    if (decoder_) {
        BrotliDecoderDestroyInstance(decoder_);
    }
}

bool BrotliDecompressor::DecompressInput(const uint8_t* data, size_t length) {
    size_t available_in = length;
    const uint8_t* next_in = data;

    bool needs_more_output = false;
    while (available_in || needs_more_output) {
        if (!output_buffer_remaining_ && !GetFreshBuffer()) {
            return false;
        }

        auto output_buffer = output_buffer_;
        auto r = BrotliDecoderDecompressStream(decoder_, &available_in, &next_in,
                                               &output_buffer_remaining_, &output_buffer_, nullptr);
        if (r == BROTLI_DECODER_RESULT_ERROR) {
            LOG(ERROR) << "brotli decode failed";
            return false;
        }
        if (!sink_->ReturnData(output_buffer, output_buffer_ - output_buffer)) {
            return false;
        }
        needs_more_output = (r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT);
    }
    return true;
}

std::unique_ptr<IDecompressor> IDecompressor::Brotli() {
    return std::unique_ptr<IDecompressor>(new BrotliDecompressor());
}

}  // namespace snapshot
}  // namespace android

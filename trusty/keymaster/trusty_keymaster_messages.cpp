/*
 * Copyright 2014 The Android Open Source Project
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

#include <keymaster/android_keymaster_messages.h>
#include <keymaster/android_keymaster_utils.h>
#include <trusty_keymaster/trusty_keymaster_messages.h>

namespace keymaster {

/*
 * Helper functions for working with key blobs.
 */
static void set_key_blob(keymaster_key_blob_t* key_blob, const void* key_material, size_t length) {
    delete[] key_blob->key_material;
    key_blob->key_material = dup_buffer(key_material, length);
    key_blob->key_material_size = length;
}

static size_t key_blob_size(const keymaster_key_blob_t& key_blob) {
    return sizeof(uint32_t) /* key size */ + key_blob.key_material_size;
}

static uint8_t* serialize_key_blob(const keymaster_key_blob_t& key_blob, uint8_t* buf,
                                   const uint8_t* end) {
    return append_size_and_data_to_buf(buf, end, key_blob.key_material, key_blob.key_material_size);
}

static bool deserialize_key_blob(keymaster_key_blob_t* key_blob, const uint8_t** buf_ptr,
                                 const uint8_t* end) {
    delete[] key_blob->key_material;
    key_blob->key_material = nullptr;
    UniquePtr<uint8_t[]> deserialized_key_material;
    if (!copy_size_and_data_from_buf(buf_ptr, end, &key_blob->key_material_size,
                                     &deserialized_key_material))
        return false;
    key_blob->key_material = deserialized_key_material.release();
    return true;
}

static size_t blob_size(const keymaster_blob_t& blob) {
    return sizeof(uint32_t) /* data size */ + blob.data_length;
}

static uint8_t* serialize_blob(const keymaster_blob_t& blob, uint8_t* buf, const uint8_t* end) {
    return append_size_and_data_to_buf(buf, end, blob.data, blob.data_length);
}

static bool deserialize_blob(keymaster_blob_t* blob, const uint8_t** buf_ptr, const uint8_t* end) {
    delete[] blob->data;
    *blob = {};
    UniquePtr<uint8_t[]> deserialized_blob;
    if (!copy_size_and_data_from_buf(buf_ptr, end, &blob->data_length, &deserialized_blob))
        return false;
    blob->data = deserialized_blob.release();
    return true;
}

size_t TrustyHmacSharingParameters::SerializedSize() const {
    return blob_size(seed) + sizeof(nonce);
}

uint8_t* TrustyHmacSharingParameters::Serialize(uint8_t* buf, const uint8_t* end) const {
    //buf = serialize_blob(seed, buf, end);
    buf = seed.Serialize(buf, end);
    return append_to_buf(buf, end, nonce, sizeof(nonce));
}

bool TrustyHmacSharingParameters::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    return //deserialize_blob(&seed, buf_ptr, end) &&
           seed.Deserialize(buf_ptr, end) &&
           copy_from_buf(buf_ptr, end, nonce, sizeof(nonce));
}

size_t TrustyHmacSharingParametersArray::SerializedSize() const {
    size_t size = sizeof(uint32_t);  // num_params size
    for (size_t i = 0; i < num_params; ++i) {
        size += params_array[i].SerializedSize();
    }
    return size;
}

uint8_t* TrustyHmacSharingParametersArray::Serialize(uint8_t* buf, const uint8_t* end) const {
    buf = append_uint32_to_buf(buf, end, num_params);
    for (size_t i = 0; i < num_params; ++i) {
        buf = params_array[i].Serialize(buf, end);
    }
    return buf;
}

bool TrustyHmacSharingParametersArray::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    if (!copy_uint32_from_buf(buf_ptr, end, &num_params)) return false;
    params_array = new (std::nothrow) TrustyHmacSharingParameters[num_params];
    if (!params_array) return false;
    for (size_t i = 0; i < num_params; ++i) {
        if (!params_array[i].Deserialize(buf_ptr, end)) return false;
    }
    return true;
}

size_t TrustyComputeSharedHmacResponse::NonErrorSerializedSize() const {
    return blob_size(sharing_check);
}

uint8_t* TrustyComputeSharedHmacResponse::NonErrorSerialize(uint8_t* buf, const uint8_t* end) const {
    return serialize_blob(sharing_check, buf, end);
}

bool TrustyComputeSharedHmacResponse::NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    return deserialize_blob(&sharing_check, buf_ptr, end);
}

size_t TrustyImportWrappedKeyRequest::SerializedSize() const {
    return sizeof(uint32_t) /* wrapped_key_data_length */ + wrapped_key.key_material_size +
           sizeof(uint32_t) /* wrapping_key_data_length */ + wrapping_key.key_material_size +
           sizeof(uint32_t) /* masking_key_data_length */ + masking_key.key_material_size +
           additional_params.SerializedSize() + sizeof(uint64_t) + sizeof(uint64_t);
}

uint8_t* TrustyImportWrappedKeyRequest::Serialize(uint8_t* buf, const uint8_t* end) const {
    //serialize_key_blob(wrapped_key, buf, end);
    //serialize_key_blob(wrapping_key, buf, end);
    //serialize_key_blob(masking_key, buf, end);
    buf = wrapped_key.Serialize(buf, end);
    buf = wrapping_key.Serialize(buf, end);
    buf = masking_key.Serialize(buf, end);
    buf = additional_params.Serialize(buf, end);
    buf = append_uint64_to_buf(buf, end, password_sid);
    return append_uint64_to_buf(buf, end, biometric_sid);
}

bool TrustyImportWrappedKeyRequest::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    return //deserialize_key_blob(&wrapped_key, buf_ptr, end) &&
           //deserialize_key_blob(&wrapping_key, buf_ptr, end) &&
           //deserialize_key_blob(&masking_key, buf_ptr, end) &&
           wrapped_key.Deserialize(buf_ptr, end) &&
           wrapping_key.Deserialize(buf_ptr, end) &&
           masking_key.Deserialize(buf_ptr, end) &&
           additional_params.Deserialize(buf_ptr, end) &&
           copy_uint64_from_buf(buf_ptr, end, &password_sid) &&
           copy_uint64_from_buf(buf_ptr, end, &biometric_sid);
}

void TrustyImportWrappedKeyRequest::SetWrappedMaterial(const void* key_material, size_t length) {
    set_key_blob(&wrapped_key, key_material, length);
}

void TrustyImportWrappedKeyRequest::SetWrappingMaterial(const void* key_material, size_t length) {
    set_key_blob(&wrapping_key, key_material, length);
}

void TrustyImportWrappedKeyRequest::SetMaskingKeyMaterial(const void* key_material, size_t length) {
    set_key_blob(&masking_key, key_material, length);
}

void TrustyImportWrappedKeyResponse::SetKeyMaterial(const void* key_material, size_t length) {
    set_key_blob(&key_blob, key_material, length);
}

size_t TrustyImportWrappedKeyResponse::NonErrorSerializedSize() const {
    return key_blob_size(key_blob) + enforced.SerializedSize() + unenforced.SerializedSize();
}

uint8_t* TrustyImportWrappedKeyResponse::NonErrorSerialize(uint8_t* buf, const uint8_t* end) const {
    buf = serialize_key_blob(key_blob, buf, end);
    buf = enforced.Serialize(buf, end);
    return unenforced.Serialize(buf, end);
}

bool TrustyImportWrappedKeyResponse::NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    return deserialize_key_blob(&key_blob, buf_ptr, end) && enforced.Deserialize(buf_ptr, end) &&
           unenforced.Deserialize(buf_ptr, end);
}

size_t TrustyHardwareAuthToken::SerializedSize() const {
    return sizeof(challenge) + sizeof(user_id) + sizeof(authenticator_id) +
           sizeof(authenticator_type) + sizeof(timestamp) + blob_size(mac);
}

uint8_t* TrustyHardwareAuthToken::Serialize(uint8_t* buf, const uint8_t* end) const {
    buf = append_uint64_to_buf(buf, end, challenge);
    buf = append_uint64_to_buf(buf, end, user_id);
    buf = append_uint64_to_buf(buf, end, authenticator_id);
    buf = append_uint32_to_buf(buf, end, authenticator_type);
    buf = append_uint64_to_buf(buf, end, timestamp);
    return //serialize_blob(mac, buf, end);
           mac.Serialize(buf, end);
}

bool TrustyHardwareAuthToken::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    return copy_uint64_from_buf(buf_ptr, end, &challenge) &&
           copy_uint64_from_buf(buf_ptr, end, &user_id) &&
           copy_uint64_from_buf(buf_ptr, end, &authenticator_id) &&
           copy_uint32_from_buf(buf_ptr, end, &authenticator_type) &&
           copy_uint64_from_buf(buf_ptr, end, &timestamp) &&  //
           //deserialize_blob(&mac, buf_ptr, end);
           mac.Deserialize(buf_ptr, end);
}

size_t TrustyVerificationToken::SerializedSize() const {
    return sizeof(challenge) + sizeof(timestamp) + parameters_verified.SerializedSize() +
           sizeof(security_level) + blob_size(mac);
}

uint8_t* TrustyVerificationToken::Serialize(uint8_t* buf, const uint8_t* end) const {
    buf = append_uint64_to_buf(buf, end, challenge);
    buf = append_uint64_to_buf(buf, end, timestamp);
    buf = parameters_verified.Serialize(buf, end);
    buf = append_uint32_to_buf(buf, end, security_level);
    return //serialize_blob(mac, buf, end);
           mac.Serialize(buf, end);
}

bool TrustyVerificationToken::Deserialize(const uint8_t** buf_ptr, const uint8_t* end) {
    return copy_uint64_from_buf(buf_ptr, end, &challenge) &&
           copy_uint64_from_buf(buf_ptr, end, &timestamp) &&
           parameters_verified.Deserialize(buf_ptr, end) &&
           copy_uint32_from_buf(buf_ptr, end, &security_level) &&
           //deserialize_blob(&mac, buf_ptr, end);
           mac.Deserialize(buf_ptr, end);
}

}  // namespace keymaster

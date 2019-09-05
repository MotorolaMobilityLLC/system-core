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

#ifndef TRUSTY_KEYMASTER_MESSAGES_H_
#define TRUSTY_KEYMASTER_MESSAGES_H_

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <keymaster/android_keymaster_utils.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/authorization_set.h>

namespace keymaster {

struct TrustyHmacSharingParameters : public Serializable {
    TrustyHmacSharingParameters() : seed({}) { memset(nonce, 0, sizeof(nonce)); }
    TrustyHmacSharingParameters(HmacSharingParameters&& other) {
        seed = move(other.seed);
        memcpy(nonce, other.nonce, sizeof(nonce));
    }

    void SetSeed(KeymasterBlob&& value) { seed = move(value); }

    size_t SerializedSize() const override;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    KeymasterBlob seed{};
    uint8_t nonce[32];
};

struct TrustyHmacSharingParametersArray : public Serializable {
    TrustyHmacSharingParametersArray() : params_array(nullptr), num_params(0) {}
    TrustyHmacSharingParametersArray(TrustyHmacSharingParametersArray&& other) {
        delete[] params_array;
        params_array = other.params_array;
        num_params = other.num_params;
        other.params_array = nullptr;
        other.num_params = 0;
    }
    ~TrustyHmacSharingParametersArray() override { delete[] params_array; }

    size_t SerializedSize() const override;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    TrustyHmacSharingParameters* params_array;
    size_t num_params;
};

struct TrustyGetHmacSharingParametersResponse : public KeymasterResponse {
    explicit TrustyGetHmacSharingParametersResponse(int32_t ver = MAX_MESSAGE_VERSION)
        : KeymasterResponse(ver) {}
    TrustyGetHmacSharingParametersResponse(TrustyGetHmacSharingParametersResponse&& other)
        : KeymasterResponse(other.message_version), params(move(other.params)) {}

    void SetSeed(KeymasterBlob&& seed_data) { params.SetSeed(move(seed_data)); }

    size_t NonErrorSerializedSize() const override { return params.SerializedSize(); }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        return params.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return params.Deserialize(buf_ptr, end);
    }

    TrustyHmacSharingParameters params;
};

struct TrustyComputeSharedHmacRequest : public KeymasterMessage {
    explicit TrustyComputeSharedHmacRequest(int32_t ver = MAX_MESSAGE_VERSION) : KeymasterMessage(ver) {}

    size_t SerializedSize() const override { return params_array.SerializedSize(); }
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        return params_array.Serialize(buf, end);
    }
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return params_array.Deserialize(buf_ptr, end);
    }

    TrustyHmacSharingParametersArray params_array;
};

struct TrustyComputeSharedHmacResponse : public KeymasterResponse {
    explicit TrustyComputeSharedHmacResponse(int32_t ver = MAX_MESSAGE_VERSION)
        : KeymasterResponse(ver) {}
    TrustyComputeSharedHmacResponse(TrustyComputeSharedHmacResponse&& other) : KeymasterResponse(move(other)) {
        sharing_check = move(other.sharing_check);
    }

    size_t NonErrorSerializedSize() const override;
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override;
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    KeymasterBlob sharing_check;
};

struct TrustyImportWrappedKeyRequest : public KeymasterMessage {
    explicit TrustyImportWrappedKeyRequest(int32_t ver = MAX_MESSAGE_VERSION) : KeymasterMessage(ver) {}

    void SetWrappedMaterial(const void* key_material, size_t length);
    void SetWrappingMaterial(const void* key_material, size_t length);
    void SetMaskingKeyMaterial(const void* key_material, size_t length);

    void SetKeyMaterial(const keymaster_key_blob_t& wrapped, const keymaster_key_blob_t& wrapping) {
        SetWrappedMaterial(wrapped.key_material, wrapped.key_material_size);
        SetWrappingMaterial(wrapping.key_material, wrapping.key_material_size);
    }

    size_t SerializedSize() const override;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    KeymasterKeyBlob wrapped_key;
    KeymasterKeyBlob wrapping_key;
    KeymasterKeyBlob masking_key;
    AuthorizationSet additional_params;
    uint64_t password_sid{};
    uint64_t biometric_sid{};
};

struct TrustyImportWrappedKeyResponse : public KeymasterResponse {
    explicit TrustyImportWrappedKeyResponse(int32_t ver = MAX_MESSAGE_VERSION) : KeymasterResponse(ver) {}

    void SetKeyMaterial(const void* key_material, size_t length);
    void SetKeyMaterial(const keymaster_key_blob_t& blob) {
        SetKeyMaterial(blob.key_material, blob.key_material_size);
    }

    size_t NonErrorSerializedSize() const override;
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override;
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    KeymasterKeyBlob key_blob;
    AuthorizationSet enforced;
    AuthorizationSet unenforced;
};

struct TrustyHardwareAuthToken : public Serializable {
    TrustyHardwareAuthToken() = default;
    TrustyHardwareAuthToken(TrustyHardwareAuthToken&& other) {
        challenge = other.challenge;
        user_id = other.user_id;
        authenticator_id = other.authenticator_id;
        authenticator_type = other.authenticator_type;
        timestamp = other.timestamp;
        mac = move(other.mac);
    }

    size_t SerializedSize() const override;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    uint64_t challenge{};
    uint64_t user_id{};
    uint64_t authenticator_id{};
    hw_authenticator_type_t authenticator_type{};
    uint64_t timestamp{};
    KeymasterBlob mac;
};

struct TrustyVerificationToken : public Serializable {
    TrustyVerificationToken() = default;
    TrustyVerificationToken(TrustyVerificationToken&& other) {
        challenge = other.challenge;
        timestamp = other.timestamp;
        parameters_verified = move(other.parameters_verified);
        security_level = other.security_level;
        mac = move(other.mac);
    }

    size_t SerializedSize() const override;
    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override;
    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override;

    uint64_t challenge{};
    uint64_t timestamp{};
    AuthorizationSet parameters_verified{};
    keymaster_security_level_t security_level{};
    KeymasterBlob mac{};
};

struct TrustyVerifyAuthorizationRequest : public KeymasterMessage {
    explicit TrustyVerifyAuthorizationRequest(int32_t ver = MAX_MESSAGE_VERSION)
        : KeymasterMessage(ver) {}
    TrustyVerifyAuthorizationRequest(TrustyVerifyAuthorizationRequest&& other) = default;

    size_t SerializedSize() const override {
        return sizeof(challenge) + parameters_to_verify.SerializedSize() +
               auth_token.SerializedSize();
    }

    uint8_t* Serialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint64_to_buf(buf, end, challenge);
        buf = parameters_to_verify.Serialize(buf, end);
        return auth_token.Serialize(buf, end);
    }

    bool Deserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return (copy_uint64_from_buf(buf_ptr, end, &challenge) &&
                parameters_to_verify.Deserialize(buf_ptr, end) &&
                auth_token.Deserialize(buf_ptr, end));
    }

    uint64_t challenge{};
    AuthorizationSet parameters_to_verify;
    TrustyHardwareAuthToken auth_token;
};

struct TrustyVerifyAuthorizationResponse : public KeymasterResponse {
    explicit TrustyVerifyAuthorizationResponse(int32_t ver = MAX_MESSAGE_VERSION)
        : KeymasterResponse(ver) {}
    TrustyVerifyAuthorizationResponse(TrustyVerifyAuthorizationResponse&& other) = default;

    size_t NonErrorSerializedSize() const override {
        return sizeof(error) + token.SerializedSize();
    }
    uint8_t* NonErrorSerialize(uint8_t* buf, const uint8_t* end) const override {
        buf = append_uint32_to_buf(buf, end, error);
        return token.Serialize(buf, end);
    }
    bool NonErrorDeserialize(const uint8_t** buf_ptr, const uint8_t* end) override {
        return copy_uint32_from_buf(buf_ptr, end, &error) && token.Deserialize(buf_ptr, end);
    }

    keymaster_error_t error{KM_ERROR_UNKNOWN_ERROR};
    TrustyVerificationToken token;
};

}  // namespace keymaster

#endif  // TRUSTY_KEYMASTER_MESSAGES_H_

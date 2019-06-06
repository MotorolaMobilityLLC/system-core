/*
 **
 ** Copyright 2018, The Android Open Source Project
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

#define LOG_TAG "android.hardware.keymaster@4.0-impl.unisoc.trusty"

#include <authorization_set.h>
#include <cutils/log.h>
#include <keymaster/android_keymaster_messages.h>
#include <trusty_keymaster/TrustyKeymaster4Device.h>
#include <trusty_keymaster/ipc/trusty_keymaster_ipc.h>
#ifdef TRUSTY_KEYMASTER_MESSAGE
#include <trusty_keymaster/trusty_keymaster_messages.h>
#endif
#include <hardware/hw_auth_token.h>

using ::keymaster::AbortOperationRequest;
using ::keymaster::AbortOperationResponse;
using ::keymaster::AddEntropyRequest;
using ::keymaster::AddEntropyResponse;
using ::keymaster::AttestKeyRequest;
using ::keymaster::AttestKeyResponse;
using ::keymaster::AuthorizationSet;
using ::keymaster::BeginOperationRequest;
using ::keymaster::BeginOperationResponse;
using ::keymaster::ExportKeyRequest;
using ::keymaster::ExportKeyResponse;
using ::keymaster::FinishOperationRequest;
using ::keymaster::FinishOperationResponse;
using ::keymaster::GenerateKeyRequest;
using ::keymaster::GenerateKeyResponse;
using ::keymaster::GetKeyCharacteristicsRequest;
using ::keymaster::GetKeyCharacteristicsResponse;
using ::keymaster::ImportKeyRequest;
using ::keymaster::ImportKeyResponse;
using ::keymaster::UpdateOperationRequest;
using ::keymaster::UpdateOperationResponse;
#ifdef TRUSTY_KEYMASTER_MESSAGE
using ::keymaster::TrustyVerifyAuthorizationRequest;
using ::keymaster::TrustyVerifyAuthorizationResponse;
using ::keymaster::TrustyComputeSharedHmacRequest;
using ::keymaster::TrustyComputeSharedHmacResponse;
using ::keymaster::TrustyGetHmacSharingParametersResponse;
#else
using ::keymaster::VerifyAuthorizationRequest;
using ::keymaster::VerifyAuthorizationResponse;
using ::keymaster::ComputeSharedHmacRequest;
using ::keymaster::ComputeSharedHmacResponse;
using ::keymaster::GetHmacSharingParametersResponse;
#endif
using ::keymaster::ng::Tag;

namespace keymaster {

namespace {

const size_t kMaximumAttestationChallengeLength = 128;
const uint32_t ROUND_BUF_SIZE = (4*990);

inline keymaster_tag_t legacy_enum_conversion(const Tag value) {
    return keymaster_tag_t(value);
}

inline Tag legacy_enum_conversion(const keymaster_tag_t value) {
    return Tag(value);
}

inline keymaster_purpose_t legacy_enum_conversion(const KeyPurpose value) {
    return static_cast<keymaster_purpose_t>(value);
}

inline keymaster_key_format_t legacy_enum_conversion(const KeyFormat value) {
    return static_cast<keymaster_key_format_t>(value);
}

inline SecurityLevel legacy_enum_conversion(const keymaster_security_level_t value) {
    return static_cast<SecurityLevel>(value);
}

inline hw_authenticator_type_t legacy_enum_conversion(const HardwareAuthenticatorType value) {
    return static_cast<hw_authenticator_type_t>(value);
}

inline ErrorCode legacy_enum_conversion(const keymaster_error_t value) {
    return static_cast<ErrorCode>(value);
}

inline keymaster_tag_type_t typeFromTag(const keymaster_tag_t tag) {
    return keymaster_tag_get_type(tag);
}

KeyParameter convert(const ::android::hardware::keymaster::V3_0::KeyParameter& param) {
    KeyParameter converted;
    converted.tag = static_cast<Tag>(param.tag);
    static_assert(sizeof(converted.f) == sizeof(param.f), "This function assumes sizes match");
    memcpy(&converted.f, &param.f, sizeof(param.f));
    converted.blob = param.blob;
    return converted;
}

::android::hardware::keymaster::V3_0::KeyParameter convert(const KeyParameter& param) {
    ::android::hardware::keymaster::V3_0::KeyParameter converted;
    converted.tag = static_cast<::android::hardware::keymaster::V3_0::Tag>(param.tag);
    static_assert(sizeof(converted.f) == sizeof(param.f), "This function assumes sizes match");
    memcpy(&converted.f, &param.f, sizeof(param.f));
    converted.blob = param.blob;
    return converted;
}

template <typename T, typename OutIter>
inline static OutIter copy_bytes_to_iterator(const T& value, OutIter dest) {
    const uint8_t* value_ptr = reinterpret_cast<const uint8_t*>(&value);
    return std::copy(value_ptr, value_ptr + sizeof(value), dest);
}

constexpr size_t kHmacSize = 32;

hidl_vec<uint8_t> authToken2HidlVec(const ::android::hardware::keymaster::V4_0::HardwareAuthToken& token) {
    static_assert(1 /* version size */ + sizeof(token.challenge) + sizeof(token.userId) +
                          sizeof(token.authenticatorId) + sizeof(token.authenticatorType) +
                          sizeof(token.timestamp) + kHmacSize ==
                      sizeof(hw_auth_token_t),
                  "HardwareAuthToken content size does not match hw_auth_token_t size");

    hidl_vec<uint8_t> result;
    result.resize(sizeof(hw_auth_token_t));
    auto pos = result.begin();
    *pos++ = 0;  // Version byte
    pos = copy_bytes_to_iterator(token.challenge, pos);
    pos = copy_bytes_to_iterator(token.userId, pos);
    pos = copy_bytes_to_iterator(token.authenticatorId, pos);
    auto auth_type = htonl(static_cast<uint32_t>(token.authenticatorType));
    pos = copy_bytes_to_iterator(auth_type, pos);
    auto timestamp = htonq(token.timestamp);
    pos = copy_bytes_to_iterator(timestamp, pos);
    if (token.mac.size() != kHmacSize) {
        std::fill(pos, pos + kHmacSize, 0);
    } else {
        std::copy(token.mac.begin(), token.mac.end(), pos);
    }

    return result;
}

hidl_vec<KeyParameter>
convertAndAddAuthToken(const hidl_vec<KeyParameter>& params,
                       const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken) {
    hidl_vec<::android::hardware::keymaster::V3_0::KeyParameter> first_converted(params.size() + 1);
    for (size_t i = 0; i < params.size(); ++i) {
        first_converted[i] = convert(params[i]);
    }
    first_converted[params.size()].tag = ::android::hardware::keymaster::V3_0::Tag::AUTH_TOKEN;
    first_converted[params.size()].blob = authToken2HidlVec(authToken);

    hidl_vec<KeyParameter> second_converted(first_converted.size());
    for (size_t i = 0; i < first_converted.size(); ++i) {
        second_converted[i] = convert(first_converted[i]);
    }

    return second_converted;
}

class KmParamSet : public keymaster_key_param_set_t {
  public:
    KmParamSet(const hidl_vec<KeyParameter>& keyParams) {
        params = new keymaster_key_param_t[keyParams.size()];
        length = keyParams.size();
        for (size_t i = 0; i < keyParams.size(); ++i) {
            auto tag = legacy_enum_conversion(keyParams[i].tag);
            switch (typeFromTag(tag)) {
            case KM_ENUM:
            case KM_ENUM_REP:
                params[i] = keymaster_param_enum(tag, keyParams[i].f.integer);
                break;
            case KM_UINT:
            case KM_UINT_REP:
                params[i] = keymaster_param_int(tag, keyParams[i].f.integer);
                break;
            case KM_ULONG:
            case KM_ULONG_REP:
                params[i] = keymaster_param_long(tag, keyParams[i].f.longInteger);
                break;
            case KM_DATE:
                params[i] = keymaster_param_date(tag, keyParams[i].f.dateTime);
                break;
            case KM_BOOL:
                if (keyParams[i].f.boolValue)
                    params[i] = keymaster_param_bool(tag);
                else
                    params[i].tag = KM_TAG_INVALID;
                break;
            case KM_BIGNUM:
            case KM_BYTES:
                params[i] =
                    keymaster_param_blob(tag, &keyParams[i].blob[0], keyParams[i].blob.size());
                break;
            case KM_INVALID:
            default:
                params[i].tag = KM_TAG_INVALID;
                /* just skip */
                break;
            }
        }
    }
    KmParamSet(KmParamSet&& other) : keymaster_key_param_set_t{other.params, other.length} {
        other.length = 0;
        other.params = nullptr;
    }
    KmParamSet(const KmParamSet&) = delete;
    ~KmParamSet() { delete[] params; }
};

inline hidl_vec<uint8_t> kmBlob2hidlVec(const keymaster_key_blob_t& blob) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(blob.key_material), blob.key_material_size);
    return result;
}

inline hidl_vec<uint8_t> kmBlob2hidlVec(const keymaster_blob_t& blob) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(blob.data), blob.data_length);
    return result;
}

inline hidl_vec<uint8_t> kmBuffer2hidlVec(const ::keymaster::Buffer& buf) {
    hidl_vec<uint8_t> result;
    result.setToExternal(const_cast<unsigned char*>(buf.peek_read()), buf.available_read());
    return result;
}

inline static hidl_vec<hidl_vec<uint8_t>>
kmCertChain2Hidl(const keymaster_cert_chain_t& cert_chain) {
    hidl_vec<hidl_vec<uint8_t>> result;
    if (!cert_chain.entry_count || !cert_chain.entries)
        return result;

    result.resize(cert_chain.entry_count);
    for (size_t i = 0; i < cert_chain.entry_count; ++i) {
        result[i] = kmBlob2hidlVec(cert_chain.entries[i]);
    }

    return result;
}

static inline hidl_vec<KeyParameter> kmParamSet2Hidl(const keymaster_key_param_set_t& set) {
    hidl_vec<KeyParameter> result;
    if (set.length == 0 || set.params == nullptr)
        return result;

    result.resize(set.length);
    keymaster_key_param_t* params = set.params;
    for (size_t i = 0; i < set.length; ++i) {
        auto tag = params[i].tag;
        result[i].tag = legacy_enum_conversion(tag);
        switch (typeFromTag(tag)) {
        case KM_ENUM:
        case KM_ENUM_REP:
            result[i].f.integer = params[i].enumerated;
            break;
        case KM_UINT:
        case KM_UINT_REP:
            result[i].f.integer = params[i].integer;
            break;
        case KM_ULONG:
        case KM_ULONG_REP:
            result[i].f.longInteger = params[i].long_integer;
            break;
        case KM_DATE:
            result[i].f.dateTime = params[i].date_time;
            break;
        case KM_BOOL:
            result[i].f.boolValue = params[i].boolean;
            break;
        case KM_BIGNUM:
        case KM_BYTES:
            result[i].blob.setToExternal(const_cast<unsigned char*>(params[i].blob.data),
                                         params[i].blob.data_length);
            break;
        case KM_INVALID:
        default:
            params[i].tag = KM_TAG_INVALID;
            /* just skip */
            break;
        }
    }
    return result;
}

void addClientAndAppData(const hidl_vec<uint8_t>& clientId, const hidl_vec<uint8_t>& appData,
                         ::keymaster::AuthorizationSet* params) {
    params->Clear();
    if (clientId.size()) {
        params->push_back(::keymaster::TAG_APPLICATION_ID, clientId.data(), clientId.size());
    }
    if (appData.size()) {
        params->push_back(::keymaster::TAG_APPLICATION_DATA, appData.data(), appData.size());
    }
}

}  // anonymous namespace

TrustyKeymaster4Device::TrustyKeymaster4Device(TrustyKeymaster* impl) : impl_(impl) {}

TrustyKeymaster4Device::~TrustyKeymaster4Device() {}

Return<void> TrustyKeymaster4Device::getHardwareInfo(getHardwareInfo_cb _hidl_cb) {
    _hidl_cb(SecurityLevel::TRUSTED_ENVIRONMENT /* securityLevel */, "TrustyKeymaster", "Unisoc");
    return Void();
}

Return<void> TrustyKeymaster4Device::getHmacSharingParameters(getHmacSharingParameters_cb _hidl_cb) {
#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyGetHmacSharingParametersResponse response = impl_->GetHmacSharingParameters();
#else
    GetHmacSharingParametersResponse response = impl_->GetHmacSharingParameters();
#endif

    ::android::hardware::keymaster::V4_0::HmacSharingParameters params;
    params.seed.setToExternal(const_cast<uint8_t*>(response.params.seed.data),
                              response.params.seed.data_length);
    static_assert(sizeof(response.params.nonce) == params.nonce.size(), "Nonce sizes don't match");
    memcpy(params.nonce.data(), response.params.nonce, params.nonce.size());
    _hidl_cb(legacy_enum_conversion(response.error), params);
    return Void();
}

Return<void> TrustyKeymaster4Device::computeSharedHmac(
    const hidl_vec<::android::hardware::keymaster::V4_0::HmacSharingParameters>& params,
    computeSharedHmac_cb _hidl_cb) {
#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyComputeSharedHmacRequest request;
    request.params_array.params_array = new keymaster::TrustyHmacSharingParameters[params.size()];
#else
    ComputeSharedHmacRequest request;
    request.params_array.params_array = new keymaster::HmacSharingParameters[params.size()];
#endif
    request.params_array.num_params = params.size();
    for (size_t i = 0; i < params.size(); ++i) {
        request.params_array.params_array[i].seed = {params[i].seed.data(), params[i].seed.size()};
        static_assert(sizeof(request.params_array.params_array[i].nonce) ==
                          decltype(params[i].nonce)::size(),
                      "Nonce sizes don't match");
        memcpy(request.params_array.params_array[i].nonce, params[i].nonce.data(),
               params[i].nonce.size());
    }

#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyComputeSharedHmacResponse response = impl_->ComputeSharedHmac(request);
#else
    ComputeSharedHmacResponse response = impl_->ComputeSharedHmac(request);
#endif
    hidl_vec<uint8_t> sharing_check;
    if (response.error == KM_ERROR_OK) sharing_check = kmBlob2hidlVec(response.sharing_check);

    _hidl_cb(legacy_enum_conversion(response.error), sharing_check);
    return Void();
}

Return<void> TrustyKeymaster4Device::verifyAuthorization(
    uint64_t operationHandle, const hidl_vec<KeyParameter>& parametersToVerify,
    const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken,
    verifyAuthorization_cb _hidl_cb) {
#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyVerifyAuthorizationRequest request;
#else
    VerifyAuthorizationRequest request;
#endif
    request.challenge = operationHandle;
    request.parameters_to_verify.Reinitialize(KmParamSet(parametersToVerify));
    request.auth_token.challenge = authToken.challenge;
    request.auth_token.user_id = authToken.userId;
    request.auth_token.authenticator_id = authToken.authenticatorId;
    request.auth_token.authenticator_type = legacy_enum_conversion(authToken.authenticatorType);
    request.auth_token.timestamp = authToken.timestamp;
    KeymasterBlob mac(authToken.mac.data(), authToken.mac.size());
    request.auth_token.mac = mac;

#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyVerifyAuthorizationResponse response = impl_->VerifyAuthorization(request);
#else
    VerifyAuthorizationResponse response = impl_->VerifyAuthorization(request);
#endif

    ::android::hardware::keymaster::V4_0::VerificationToken token;
    token.challenge = response.token.challenge;
    token.timestamp = response.token.timestamp;
    token.parametersVerified = kmParamSet2Hidl(response.token.parameters_verified);
    token.securityLevel = legacy_enum_conversion(response.token.security_level);
    token.mac = kmBlob2hidlVec(response.token.mac);

    _hidl_cb(legacy_enum_conversion(response.error), token);

    return Void();
}

Return<ErrorCode> TrustyKeymaster4Device::addRngEntropy(const hidl_vec<uint8_t>& data) {
    if (data.size() == 0)
        return ErrorCode::OK;
    AddEntropyRequest request;
    request.random_data.Reinitialize(data.data(), data.size());

    AddEntropyResponse response;
    impl_->AddRngEntropy(request, &response);

    return legacy_enum_conversion(response.error);
}

Return<void> TrustyKeymaster4Device::generateKey(const hidl_vec<KeyParameter>& keyParams,
                                                 generateKey_cb _hidl_cb) {
    GenerateKeyRequest request;
    request.key_description.Reinitialize(KmParamSet(keyParams));

    GenerateKeyResponse response;
    impl_->GenerateKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::getKeyCharacteristics(const hidl_vec<uint8_t>& keyBlob,
                                                           const hidl_vec<uint8_t>& clientId,
                                                           const hidl_vec<uint8_t>& appData,
                                                           getKeyCharacteristics_cb _hidl_cb) {
    GetKeyCharacteristicsRequest request;
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    GetKeyCharacteristicsResponse response;
    impl_->GetKeyCharacteristics(request, &response);

    KeyCharacteristics resultCharacteristics;
    if (response.error == KM_ERROR_OK) {
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::importKey(const hidl_vec<KeyParameter>& params,
                                               KeyFormat keyFormat,
                                               const hidl_vec<uint8_t>& keyData,
                                               importKey_cb _hidl_cb) {
    ImportKeyRequest request;
    request.key_description.Reinitialize(KmParamSet(params));
    request.key_format = legacy_enum_conversion(keyFormat);
    request.SetKeyMaterial(keyData.data(), keyData.size());

    ImportKeyResponse response;
    impl_->ImportKey(request, &response);

    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::importWrappedKey(
    const hidl_vec<uint8_t>& wrappedKeyData, const hidl_vec<uint8_t>& wrappingKeyBlob,
    const hidl_vec<uint8_t>& maskingKey, const hidl_vec<KeyParameter>& unwrappingParams,
    uint64_t passwordSid, uint64_t biometricSid, importWrappedKey_cb _hidl_cb) {

#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyImportWrappedKeyRequest request;
#else
    ImportWrappedKeyRequest request;
#endif

    request.SetWrappedMaterial(wrappedKeyData.data(), wrappedKeyData.size());
    request.SetWrappingMaterial(wrappingKeyBlob.data(), wrappingKeyBlob.size());
    request.SetMaskingKeyMaterial(maskingKey.data(), maskingKey.size());
    request.additional_params.Reinitialize(KmParamSet(unwrappingParams));
    request.password_sid = passwordSid;
    request.biometric_sid = biometricSid;

#ifdef TRUSTY_KEYMASTER_MESSAGE
    TrustyImportWrappedKeyResponse response;
#else
    ImportWrappedKeyResponse response;
#endif

    impl_->ImportWrappedKey(request, &response);
    KeyCharacteristics resultCharacteristics;
    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob = kmBlob2hidlVec(response.key_blob);
        resultCharacteristics.hardwareEnforced = kmParamSet2Hidl(response.enforced);
        resultCharacteristics.softwareEnforced = kmParamSet2Hidl(response.unenforced);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob, resultCharacteristics);
    return Void();
}

Return<void> TrustyKeymaster4Device::exportKey(KeyFormat exportFormat,
                                               const hidl_vec<uint8_t>& keyBlob,
                                               const hidl_vec<uint8_t>& clientId,
                                               const hidl_vec<uint8_t>& appData,
                                               exportKey_cb _hidl_cb) {
    ExportKeyRequest request;
    request.key_format = legacy_enum_conversion(exportFormat);
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());
    addClientAndAppData(clientId, appData, &request.additional_params);

    ExportKeyResponse response;
    impl_->ExportKey(request, &response);

    hidl_vec<uint8_t> resultKeyBlob;
    if (response.error == KM_ERROR_OK) {
        resultKeyBlob.setToExternal(response.key_data, response.key_data_length);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultKeyBlob);
    return Void();
}

Return<void> TrustyKeymaster4Device::attestKey(const hidl_vec<uint8_t>& keyToAttest,
                                               const hidl_vec<KeyParameter>& attestParams,
                                               attestKey_cb _hidl_cb) {
    AttestKeyResponse response;
    AttestKeyRequest request;
    hidl_vec<hidl_vec<uint8_t>> resultCertChain;
    keymaster_blob_t attestation_challenge = {};

    if (!keyToAttest.data() || !attestParams.data()) {
        response.error = KM_ERROR_UNEXPECTED_NULL_POINTER;
        goto fail_return;
    }

    request.SetKeyMaterial(keyToAttest.data(), keyToAttest.size());
    request.attest_params.Reinitialize(KmParamSet(attestParams));

    request.attest_params.GetTagValue(TAG_ATTESTATION_CHALLENGE, &attestation_challenge);
    if (attestation_challenge.data_length > kMaximumAttestationChallengeLength) {
        ALOGE("%d-byte attestation challenge; only %d bytes allowed",
              (int)attestation_challenge.data_length, (int)kMaximumAttestationChallengeLength);
        response.error =  KM_ERROR_INVALID_INPUT_LENGTH;
        goto fail_return;
    }

    impl_->AttestKey(request, &response);

    if (response.error == KM_ERROR_OK) {
        resultCertChain = kmCertChain2Hidl(response.certificate_chain);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultCertChain);
    return Void();

fail_return:
    _hidl_cb(legacy_enum_conversion(response.error), hidl_vec<hidl_vec<uint8_t>>());
    return Void();
}

Return<void> TrustyKeymaster4Device::upgradeKey(const hidl_vec<uint8_t>& keyBlobToUpgrade,
                                                const hidl_vec<KeyParameter>& upgradeParams,
                                                upgradeKey_cb _hidl_cb) {
    UpgradeKeyRequest request;
    request.SetKeyMaterial(keyBlobToUpgrade.data(), keyBlobToUpgrade.size());
    request.upgrade_params.Reinitialize(KmParamSet(upgradeParams));

    UpgradeKeyResponse response;
    impl_->UpgradeKey(request, &response);

    if (response.error == KM_ERROR_OK) {
        _hidl_cb(ErrorCode::OK, kmBlob2hidlVec(response.upgraded_key));
    } else {
        _hidl_cb(legacy_enum_conversion(response.error), hidl_vec<uint8_t>());
    }
    return Void();
}

Return<ErrorCode> TrustyKeymaster4Device::deleteKey(const hidl_vec<uint8_t>& keyBlob) {
    DeleteKeyRequest request;
    request.SetKeyMaterial(keyBlob.data(), keyBlob.size());

    DeleteKeyResponse response;
    //impl_->DeleteKey(request, &response);

    response.error = KM_ERROR_OK;

    return legacy_enum_conversion(response.error);
}

Return<ErrorCode> TrustyKeymaster4Device::deleteAllKeys() {
    DeleteAllKeysRequest request;
    DeleteAllKeysResponse response;
    //impl_->DeleteAllKeys(request, &response);

    response.error = KM_ERROR_OK;

    return legacy_enum_conversion(response.error);
}

Return<ErrorCode> TrustyKeymaster4Device::destroyAttestationIds() {
    return ErrorCode::UNIMPLEMENTED;
}

Return<void> TrustyKeymaster4Device::begin(KeyPurpose purpose, const hidl_vec<uint8_t>& key,
                                           const hidl_vec<KeyParameter>& inParams,
                                           const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken,
                                           begin_cb _hidl_cb) {
    BeginOperationRequest request;
    request.purpose = legacy_enum_conversion(purpose);
    request.SetKeyMaterial(key.data(), key.size());
    request.additional_params.Reinitialize(KmParamSet(convertAndAddAuthToken(inParams, authToken)));

    BeginOperationResponse response;
    impl_->BeginOperation(request, &response);

    hidl_vec<KeyParameter> resultParams;
    if (response.error == KM_ERROR_OK) {
        resultParams = kmParamSet2Hidl(response.output_params);
    }

    _hidl_cb(legacy_enum_conversion(response.error), resultParams, response.op_handle);
    return Void();
}

Return<void> TrustyKeymaster4Device::update(uint64_t operationHandle,
                                            const hidl_vec<KeyParameter>& inParams,
                                            const hidl_vec<uint8_t>& input,
                                            const ::android::hardware::keymaster::V4_0::HardwareAuthToken& authToken,
                                            const ::android::hardware::keymaster::V4_0::VerificationToken& /* verificationToken */,
                                            update_cb _hidl_cb) {
    UpdateOperationRequest request;
    UpdateOperationResponse response;
    hidl_vec<KeyParameter> resultParams;
    hidl_vec<uint8_t> resultBlob;
    uint32_t resultConsumed = 0;
    uint32_t round = 0;
    uint32_t left = 0;
    uint8_t *tmp = NULL;
    keymaster_blob_t output = {
        .data = nullptr,
        .data_length = 0,
    };
    keymaster_key_param_set_t out_params = {
        .params = nullptr,
        .length = 0,
    };

    if (input.data()) {
        round = input.size()/ROUND_BUF_SIZE;
        left = input.size()%ROUND_BUF_SIZE;

        if (left > 0)
            round++;

        ALOGD("There have %dst rounds to send, left:%d, total:%d", round, left, (int)input.size());

        if (round > 0) {
            tmp = reinterpret_cast<uint8_t*>(malloc(input.size()+ROUND_BUF_SIZE));
            if (!tmp) {
                response.error = KM_ERROR_MEMORY_ALLOCATION_FAILED;
                _hidl_cb(legacy_enum_conversion(response.error), resultConsumed, resultParams, resultBlob);
                return Void();
            }
            output.data = tmp;
        }
    }

    //here for AES GCM aad update
    if(0 == round) {
        request.op_handle = operationHandle;
        request.input.Reinitialize(input.data(), 0);
        request.additional_params.Reinitialize(KmParamSet(convertAndAddAuthToken(inParams, authToken)));

        impl_->UpdateOperation(request, &response);

        if (response.error == KM_ERROR_OK) {
            resultConsumed = response.input_consumed;
            resultParams = kmParamSet2Hidl(response.output_params);
            resultBlob = kmBuffer2hidlVec(response.output);
        } else {
            ALOGE("UpdateOperation done, line: %d, receive error:%d", __LINE__, response.error);
        }

        if (tmp)
            free(tmp);
        output.data = NULL;
        output.data_length = 0;
        _hidl_cb(legacy_enum_conversion(response.error), resultConsumed, resultParams, resultBlob);
        return Void();
    }

    for(uint32_t i = 0; i < round; i++) {
        request.op_handle = operationHandle;
        uint32_t data_len = (i == round-1 && left > 0) ? left : ROUND_BUF_SIZE;
        request.input.Reinitialize(input.data() + ROUND_BUF_SIZE*i, data_len);
        if (0 == i)
            request.additional_params.Reinitialize(KmParamSet(convertAndAddAuthToken(inParams, authToken)));

        impl_->UpdateOperation(request, &response);
        if (response.error != KM_ERROR_OK) {
            ALOGE("UpdateOperation done, line: %d, receive error:%d", __LINE__, response.error);
            if (tmp)
                free(tmp);
            output.data = NULL;
            output.data_length = 0;

            _hidl_cb(legacy_enum_conversion(response.error), resultConsumed, resultParams, resultBlob);
            return Void();
        }

        if (response.output_params.size() > 0) {
            response.output_params.CopyToParamSet(&out_params);
        }

        resultConsumed += response.input_consumed;
        memcpy(tmp + output.data_length, response.output.peek_read(), response.output.available_read());
        output.data_length += response.output.available_read();
    }

    resultParams = kmParamSet2Hidl(out_params);
    resultBlob = kmBlob2hidlVec(output);

    if (tmp)
        free(tmp);
    output.data = NULL;
    output.data_length = 0;

    _hidl_cb(legacy_enum_conversion(response.error), resultConsumed, resultParams, resultBlob);
    return Void();
}

Return<void> TrustyKeymaster4Device::finish(uint64_t operationHandle,
                                            const hidl_vec<KeyParameter>& inParams,
                                            const hidl_vec<uint8_t>& input,
                                            const hidl_vec<uint8_t>& signature,
                                            const ::android::hardware::keymaster::V4_0::HardwareAuthToken&  authToken,
                                            const ::android::hardware::keymaster::V4_0::VerificationToken& /* verificationToken */,
                                            finish_cb _hidl_cb) {
    FinishOperationRequest request;
    request.op_handle = operationHandle;
    request.input.Reinitialize(input.data(), input.size());
    request.signature.Reinitialize(signature.data(), signature.size());
    request.additional_params.Reinitialize(KmParamSet(convertAndAddAuthToken(inParams, authToken)));

    FinishOperationResponse response;
    impl_->FinishOperation(request, &response);

    hidl_vec<KeyParameter> resultParams;
    hidl_vec<uint8_t> resultBlob;
    if (response.error == KM_ERROR_OK) {
        resultParams = kmParamSet2Hidl(response.output_params);
        resultBlob = kmBuffer2hidlVec(response.output);
    }
    _hidl_cb(legacy_enum_conversion(response.error), resultParams, resultBlob);
    return Void();
}

Return<ErrorCode> TrustyKeymaster4Device::abort(uint64_t operationHandle) {
    AbortOperationRequest request;
    request.op_handle = operationHandle;

    AbortOperationResponse response;
    impl_->AbortOperation(request, &response);

    return legacy_enum_conversion(response.error);
}
}  // namespace keymaster

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

#define LOG_TAG "healthd"

#include <healthd/BatteryMonitor.h>
#include <healthd/healthd.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <optional>

#include <aidl/android/hardware/health/HealthInfo.h>
#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android/hardware/health/2.1/types.h>
#include <android/hardware/health/translate-ndk.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>
#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/Vector.h>

#define POWER_SUPPLY_SUBSYSTEM "power_supply"
#define POWER_SUPPLY_SYSFS_PATH "/sys/class/" POWER_SUPPLY_SUBSYSTEM
#define DEV_GLOB "/sys/devices/platform/*gcdd/system_dev_stat"
#define CDD_SYSTEM_DEVICE_TEMP 8
#define FAKE_BATTERY_CAPACITY 42
#define FAKE_BATTERY_TEMPERATURE 424
#define MILLION 1.0e6
#define DEFAULT_VBUS_VOLTAGE 5000000

using HealthInfo_1_0 = android::hardware::health::V1_0::HealthInfo;
using HealthInfo_2_0 = android::hardware::health::V2_0::HealthInfo;
using HealthInfo_2_1 = android::hardware::health::V2_1::HealthInfo;
using aidl::android::hardware::health::BatteryCapacityLevel;
using aidl::android::hardware::health::BatteryChargingPolicy;
using aidl::android::hardware::health::BatteryChargingState;
using aidl::android::hardware::health::BatteryHealth;
using aidl::android::hardware::health::BatteryHealthData;
using aidl::android::hardware::health::BatteryPartStatus;
using aidl::android::hardware::health::BatteryStatus;
using aidl::android::hardware::health::HealthInfo;

namespace {

// Translate from AIDL back to HIDL definition for getHealthInfo_*_* calls.
// Skips storageInfo and diskStats.
void translateToHidl(const ::aidl::android::hardware::health::HealthInfo& in,
                     ::android::hardware::health::V1_0::HealthInfo* out) {
    out->chargerAcOnline = in.chargerAcOnline;
    out->chargerUsbOnline = in.chargerUsbOnline;
    out->chargerWirelessOnline = in.chargerWirelessOnline;
    out->maxChargingCurrent = in.maxChargingCurrentMicroamps;
    out->maxChargingVoltage = in.maxChargingVoltageMicrovolts;
    out->batteryStatus =
            static_cast<::android::hardware::health::V1_0::BatteryStatus>(in.batteryStatus);
    out->batteryHealth =
            static_cast<::android::hardware::health::V1_0::BatteryHealth>(in.batteryHealth);
    out->batteryPresent = in.batteryPresent;
    out->batteryLevel = in.batteryLevel;
    out->batteryVoltage = in.batteryVoltageMillivolts;
    out->batteryTemperature = in.batteryTemperatureTenthsCelsius;
    out->batteryCurrent = in.batteryCurrentMicroamps;
    out->batteryCycleCount = in.batteryCycleCount;
    out->batteryFullCharge = in.batteryFullChargeUah;
    out->batteryChargeCounter = in.batteryChargeCounterUah;
    out->batteryTechnology = in.batteryTechnology;
}

void translateToHidl(const ::aidl::android::hardware::health::HealthInfo& in,
                     ::android::hardware::health::V2_0::HealthInfo* out) {
    translateToHidl(in, &out->legacy);
    out->batteryCurrentAverage = in.batteryCurrentAverageMicroamps;
    // Skip storageInfo and diskStats
}

void translateToHidl(const ::aidl::android::hardware::health::HealthInfo& in,
                     ::android::hardware::health::V2_1::HealthInfo* out) {
    translateToHidl(in, &out->legacy);
    out->batteryCapacityLevel = static_cast<android::hardware::health::V2_1::BatteryCapacityLevel>(
            in.batteryCapacityLevel);
    out->batteryChargeTimeToFullNowSeconds = in.batteryChargeTimeToFullNowSeconds;
    out->batteryFullChargeDesignCapacityUah = in.batteryFullChargeDesignCapacityUah;
}

}  // namespace

namespace android {

template <typename T>
struct SysfsStringEnumMap {
    const char* s;
    T val;
};

template <typename T>
static std::optional<T> mapSysfsString(const char* str, SysfsStringEnumMap<T> map[]) {
    for (int i = 0; map[i].s; i++)
        if (!strcmp(str, map[i].s)) return map[i].val;

    return std::nullopt;
}

static void initHealthInfo(HealthInfo* health_info) {
    *health_info = {
            .batteryStatus = BatteryStatus::UNKNOWN,
            .batteryHealth = BatteryHealth::UNKNOWN,
            .batteryCapacityLevel = BatteryCapacityLevel::UNSUPPORTED,
            .batteryChargeTimeToFullNowSeconds =
                    (int64_t)HealthInfo::BATTERY_CHARGE_TIME_TO_FULL_NOW_SECONDS_UNSUPPORTED,
            .batteryHealthData = std::nullopt,
    };
}

BatteryMonitor::BatteryMonitor()
    : mHealthdConfig(nullptr),
      mBatteryDevicePresent(false),
      mBatteryFixedCapacity(0),
      mBatteryFixedTemperature(0),
      mBatteryHealthStatus(BatteryMonitor::BH_UNKNOWN),
      mHealthInfo(std::make_unique<HealthInfo>()),
      mLastGoodBatteryLevel(std::nullopt) {
    initHealthInfo(mHealthInfo.get());
    glob_t globbuf;
    int ret = glob(DEV_GLOB, GLOB_MARK, nullptr, &globbuf);
    if (ret) {
        KLOG_ERROR(LOG_TAG, "Failed to lookup glob %s: %d\n", DEV_GLOB, ret);
    } else {
        for (int i = 0; globbuf.gl_pathv[i]; i++) {
            if (access(globbuf.gl_pathv[i], F_OK) == 0) {
                mDevPath = String8(globbuf.gl_pathv[i]);
            }
        }
    }
}

BatteryMonitor::~BatteryMonitor() {}

HealthInfo_2_1 BatteryMonitor::getHealthInfo_2_1() const {
    HealthInfo_2_1 health_info_2_1;
    translateToHidl(*mHealthInfo, &health_info_2_1);
    return health_info_2_1;
}

const HealthInfo& BatteryMonitor::getHealthInfo() const {
    return *mHealthInfo;
}

static base::Result<int, base::Errno, false> readFromFile(const String8& path, std::string* buf) {
    buf->clear();

    if (path.empty()) return base::ResultError<base::Errno, false>(ENOENT);

    if (android::base::ReadFileToString(path.c_str(), buf)) {
        *buf = android::base::Trim(*buf);
    } else {
        return base::ErrnoError();
    }
    return buf->length();
}

static bool writeToFile(const String8& path, int32_t in_value) {
    return android::base::WriteStringToFile(std::to_string(in_value), path.c_str());
}

BatteryStatus getBatteryStatus(const char* status) {
    static SysfsStringEnumMap<BatteryStatus> batteryStatusMap[] = {
            {"Unknown", BatteryStatus::UNKNOWN},
            {"Charging", BatteryStatus::CHARGING},
            {"Discharging", BatteryStatus::DISCHARGING},
            {"Not charging", BatteryStatus::NOT_CHARGING},
            {"Full", BatteryStatus::FULL},
            {NULL, BatteryStatus::UNKNOWN},
    };

    auto ret = mapSysfsString(status, batteryStatusMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unknown battery status '%s'\n", status);
        *ret = BatteryStatus::UNKNOWN;
    }

    return *ret;
}

BatteryCapacityLevel getBatteryCapacityLevel(const char* capacityLevel) {
    static SysfsStringEnumMap<BatteryCapacityLevel> batteryCapacityLevelMap[] = {
            {"Unknown", BatteryCapacityLevel::UNKNOWN},
            {"Critical", BatteryCapacityLevel::CRITICAL},
            {"Low", BatteryCapacityLevel::LOW},
            {"Normal", BatteryCapacityLevel::NORMAL},
            {"High", BatteryCapacityLevel::HIGH},
            {"Full", BatteryCapacityLevel::FULL},
            {NULL, BatteryCapacityLevel::UNSUPPORTED},
    };

    auto ret = mapSysfsString(capacityLevel, batteryCapacityLevelMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unsupported battery capacity level '%s'\n", capacityLevel);
        *ret = BatteryCapacityLevel::UNSUPPORTED;
    }

    return *ret;
}

BatteryHealth getBatteryHealth(const char* status) {
    static SysfsStringEnumMap<BatteryHealth> batteryHealthMap[] = {
            {"Unknown", BatteryHealth::UNKNOWN},
            {"Good", BatteryHealth::GOOD},
            {"Overheat", BatteryHealth::OVERHEAT},
            {"Dead", BatteryHealth::DEAD},
            {"Over voltage", BatteryHealth::OVER_VOLTAGE},
            {"Unspecified failure", BatteryHealth::UNSPECIFIED_FAILURE},
            {"Cold", BatteryHealth::COLD},
            // battery health values from JEITA spec
            {"Warm", BatteryHealth::GOOD},
            {"Cool", BatteryHealth::GOOD},
            {"Hot", BatteryHealth::OVERHEAT},
            {"Calibration required", BatteryHealth::INCONSISTENT},
            {NULL, BatteryHealth::UNKNOWN},
    };

    auto ret = mapSysfsString(status, batteryHealthMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unknown battery health '%s'\n", status);
        *ret = BatteryHealth::UNKNOWN;
    }

    return *ret;
}

BatteryHealth getBatteryHealthStatus(int status) {
    BatteryHealth value;

    if (status == BatteryMonitor::BH_NOMINAL)
        value = BatteryHealth::GOOD;
    else if (status == BatteryMonitor::BH_MARGINAL)
        value = BatteryHealth::FAIR;
    else if (status == BatteryMonitor::BH_NEEDS_REPLACEMENT)
        value = BatteryHealth::DEAD;
    else if (status == BatteryMonitor::BH_FAILED)
        value = BatteryHealth::UNSPECIFIED_FAILURE;
    else if (status == BatteryMonitor::BH_NOT_AVAILABLE)
        value = BatteryHealth::NOT_AVAILABLE;
    else if (status == BatteryMonitor::BH_INCONSISTENT)
        value = BatteryHealth::INCONSISTENT;
    else
        value = BatteryHealth::UNKNOWN;

    return value;
}

BatteryChargingPolicy getBatteryChargingPolicy(const char* chargingPolicy) {
    static SysfsStringEnumMap<BatteryChargingPolicy> batteryChargingPolicyMap[] = {
            {"0", BatteryChargingPolicy::INVALID},
            {"1", BatteryChargingPolicy::DEFAULT},
            {"2", BatteryChargingPolicy::ADAPTIVE},
            {"3", BatteryChargingPolicy::ADAPTIVE},
            {"4", BatteryChargingPolicy::LONG_LIFE},
            {"5", BatteryChargingPolicy::FORCE_FULL_CHARGE},
            {NULL, BatteryChargingPolicy::DEFAULT},
    };

    auto ret = mapSysfsString(chargingPolicy, batteryChargingPolicyMap);
    if (!ret) {
        *ret = BatteryChargingPolicy::DEFAULT;
    }

    return *ret;
}

BatteryChargingState getBatteryChargingState(const char* chargingState) {
    static SysfsStringEnumMap<BatteryChargingState> batteryChargingStateMap[] = {
            {"0", BatteryChargingState::INVALID},   {"1", BatteryChargingState::NORMAL},
            {"2", BatteryChargingState::TOO_COLD},  {"3", BatteryChargingState::TOO_HOT},
            {"4", BatteryChargingState::LONG_LIFE}, {"5", BatteryChargingState::ADAPTIVE},
            {NULL, BatteryChargingState::NORMAL},
    };

    auto ret = mapSysfsString(chargingState, batteryChargingStateMap);
    if (!ret) {
        *ret = BatteryChargingState::NORMAL;
    }

    return *ret;
}

static BatteryMonitor::PowerSupplyType readRawPowerSupplyType(const String8& path) {
    static SysfsStringEnumMap<int> supplyTypeMap[] = {
            {"Unknown", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_UNKNOWN},
            {"Battery", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_BATTERY},
            {"UPS", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"Mains", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_USB},
            {"USB_DCP", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_HVDCP", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_CDP", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_ACA", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_C", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_PD", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_AC},
            {"USB_PD_DRP", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_USB},
            {"Wireless", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_WIRELESS},
            {"Dock", BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_DOCK},
            {NULL, 0},
    };
    std::string buf;

    if (!readFromFile(path, &buf).ok()) {
        return BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;
    }

    auto ret = mapSysfsString(buf.c_str(), supplyTypeMap);
    if (!ret) {
        KLOG_WARNING(LOG_TAG, "Unknown power supply type '%s'\n", buf.c_str());
        *ret = BatteryMonitor::ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;
    }

    return static_cast<BatteryMonitor::PowerSupplyType>(*ret);
}

static BatteryMonitor::PowerSupplyType readPowerSupplyType(String8& path, const char* const name) {
    path.clear();
    path.appendFormat("%s/%s/type", POWER_SUPPLY_SYSFS_PATH, name);
    auto out = readRawPowerSupplyType(path);

    if (out == BatteryMonitor::PowerSupplyType::ANDROID_POWER_SUPPLY_TYPE_UNKNOWN) {
        // An is_dock property can also say that the power supply is a dock,
        // as long as it is not another known type.
        path.clear();
        path.appendFormat("%s/%s/is_dock", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            out = BatteryMonitor::PowerSupplyType::ANDROID_POWER_SUPPLY_TYPE_DOCK;
        }
    }
    return out;
}

bool getBooleanField(const String8& path) {
    std::string buf;

    return readFromFile(path, &buf).ok() && !buf.starts_with('0');
}

template <typename T = int>
static base::Result<T, base::Errno, false> tryGetIntField(const String8& path) {
    std::string buf;
    auto res = readFromFile(path, &buf);
    if (!res.ok()) return res;

    T value;
    if (!android::base::ParseInt(buf, &value)) return base::ErrnoError();
    return value;
}

static base::Result<std::optional<std::string>, base::Errno, false> getPrintableStringField(
        const String8& path) {
    std::string buf;
    auto res = readFromFile(path, &buf);
    if (res.ok()) {
        std::string sanitized_buf;
        for (const auto& c : buf) {
            if (isprint(c)) {
                sanitized_buf += c;
            }
        }
        return std::optional(sanitized_buf);
    }
    if (res.error().code() == ENOENT) {
        return std::nullopt;
    }
    return res.error();
}

String8 sanitizeSerialNumber(const std::string& serial) {
    String8 sanitized;
    for (const auto& c : serial) {
        if (isupper(c) || isdigit(c)) {
            sanitized.appendFormat("%c", c);
        } else if (islower(c)) {
            sanitized.appendFormat("%c", toupper(c));
        } else {
            // Some devices return non-ASCII characters as part of the serial
            // number. Handle these gracefully since VTS requires alphanumeric
            // characters.
            sanitized.appendFormat("%02X", (unsigned int)c);
        }
    }
    return sanitized;
}

static bool isScopedPowerSupply(const char* name) {
    constexpr char kScopeDevice[] = "Device";

    String8 path;
    path.appendFormat("%s/%s/scope", POWER_SUPPLY_SYSFS_PATH, name);
    std::string scope;
    return (readFromFile(path, &scope).ok() && scope == kScopeDevice);
}

static BatteryHealthData* ensureBatteryHealthData(HealthInfo* info) {
    if (!info->batteryHealthData.has_value()) {
        return &info->batteryHealthData.emplace();
    }

    return &info->batteryHealthData.value();
}

void BatteryMonitor::updateValues(void) {
    initHealthInfo(mHealthInfo.get());

    if (!mHealthdConfig->batteryPresentPath.empty())
        mHealthInfo->batteryPresent = getBooleanField(mHealthdConfig->batteryPresentPath);
    else
        mHealthInfo->batteryPresent = mBatteryDevicePresent;

    if (mBatteryFixedCapacity) {
        mHealthInfo->batteryLevel = mBatteryFixedCapacity;
    } else {
        const auto v = tryGetIntField<int32_t>(mHealthdConfig->batteryCapacityPath);
        const auto now = std::chrono::steady_clock::now();
        if (v.ok()) {
            mLastGoodBatteryLevel = {now, v.value()};
        } else if (!mHealthInfo->batteryPresent) {
            // Battery is gone, so any previous value will be invalid but this
            // isn't a noteworthy error.
            mLastGoodBatteryLevel = std::nullopt;
        } else {
            // Error may be transient; retain the last-good value for a short time.
            const auto expiration = mLastGoodBatteryLevel.has_value()
                                            ? std::optional(mLastGoodBatteryLevel->first)
                                            : std::nullopt;
            if (expiration.has_value() && expiration.value() + kMaximumLevelStaleness < now) {
                // Value became stale
                mLastGoodBatteryLevel = std::nullopt;
            }
            KLOG_WARNING(LOG_TAG, "Failed to read battery level (%s): last-known state was %d",
                         strerror(v.error().code()),
                         mLastGoodBatteryLevel.has_value() ? mLastGoodBatteryLevel->second : 0);
        }
        mHealthInfo->batteryLevel =
                mLastGoodBatteryLevel.has_value() ? mLastGoodBatteryLevel->second : 0;
    }

    mHealthInfo->batteryVoltageMillivolts =
            tryGetIntField(mHealthdConfig->batteryVoltagePath).value_or(0) / 1000;

    mHealthInfo->batteryCurrentMicroamps =
            tryGetIntField(mHealthdConfig->batteryCurrentNowPath).value_or(0);

    mHealthInfo->batteryFullChargeUah = getFullChargeUah();

    mHealthInfo->batteryCycleCount =
            tryGetIntField(mHealthdConfig->batteryCycleCountPath).value_or(0);

    mHealthInfo->batteryChargeCounterUah =
            tryGetIntField(mHealthdConfig->batteryChargeCounterPath).value_or(0);

    mHealthInfo->batteryCurrentAverageMicroamps =
            tryGetIntField(mHealthdConfig->batteryCurrentAvgPath).value_or(0);

    auto chargeTime = tryGetIntField<int64_t>(mHealthdConfig->batteryChargeTimeToFullNowPath);
    if (!chargeTime.ok() && chargeTime.error().code() == EINVAL) {
        // Got a non-numeric value
        mHealthInfo->batteryChargeTimeToFullNowSeconds = 0;
    } else {
        mHealthInfo->batteryChargeTimeToFullNowSeconds = chargeTime.value_or(
                HealthInfo::BATTERY_CHARGE_TIME_TO_FULL_NOW_SECONDS_UNSUPPORTED);
    }

    mHealthInfo->batteryFullChargeDesignCapacityUah = getFullChargeDesignCapacityUah();

    mBatteryHealthStatus = tryGetIntField(mHealthdConfig->batteryHealthStatusPath).value_or(0);

    if (auto res = tryGetIntField(mHealthdConfig->batteryStateOfHealthPath);
        res.ok() || res.error().code() != ENOENT)
        ensureBatteryHealthData(mHealthInfo.get())->batteryStateOfHealth = res.value_or(0);

    if (auto res = tryGetIntField<int64_t>(mHealthdConfig->batteryManufacturingDatePath);
        res.ok() || res.error().code() != ENOENT)
        ensureBatteryHealthData(mHealthInfo.get())->batteryManufacturingDateSeconds =
                res.value_or(0);

    if (auto res = tryGetIntField<int64_t>(mHealthdConfig->batteryFirstUsageDatePath);
        res.ok() || res.error().code() != ENOENT)
        ensureBatteryHealthData(mHealthInfo.get())->batteryFirstUsageSeconds = res.value_or(0);

    getSerialNumber(&ensureBatteryHealthData(mHealthInfo.get())->batterySerialNumber);

    mHealthInfo->batteryTemperatureTenthsCelsius =
            mBatteryFixedTemperature
                    ? mBatteryFixedTemperature
                    : tryGetIntField(mHealthdConfig->batteryTemperaturePath).value_or(0);

    std::string buf;

    if (readFromFile(mHealthdConfig->batteryCapacityLevelPath, &buf).ok() && !buf.empty())
        mHealthInfo->batteryCapacityLevel = getBatteryCapacityLevel(buf.c_str());

    if (readFromFile(mHealthdConfig->batteryStatusPath, &buf).ok() && !buf.empty())
        mHealthInfo->batteryStatus = getBatteryStatus(buf.c_str());

    // Backward compatible with android.hardware.health V1
    if (mBatteryHealthStatus < BatteryMonitor::BH_MARGINAL) {
        if (readFromFile(mHealthdConfig->batteryHealthPath, &buf).ok() && !buf.empty())
            mHealthInfo->batteryHealth = getBatteryHealth(buf.c_str());
    } else {
        mHealthInfo->batteryHealth = getBatteryHealthStatus(mBatteryHealthStatus);
    }

    if (readFromFile(mHealthdConfig->batteryTechnologyPath, &buf).ok() && !buf.empty())
        mHealthInfo->batteryTechnology = buf;

    if (readFromFile(mHealthdConfig->chargingPolicyPath, &buf).ok() && !buf.empty())
        mHealthInfo->chargingPolicy = getBatteryChargingPolicy(buf.c_str());

    if (readFromFile(mHealthdConfig->chargingStatePath, &buf).ok() && !buf.empty())
        mHealthInfo->chargingState = getBatteryChargingState(buf.c_str());

    if (auto res = getManufacturer(); res.ok() && res->has_value()) {
        ensureBatteryHealthData(mHealthInfo.get())->batteryManufacturer = **res;
    }

    if (auto res = getModelName(); res.ok() && res->has_value()) {
        ensureBatteryHealthData(mHealthInfo.get())->batteryModelName = **res;
    }

    // Return 0 if voltage_min_design does not exist
    if (auto res = getVoltageMinDesign(); res.ok()) {
        ensureBatteryHealthData(mHealthInfo.get())->batteryVoltageMinDesignUv = *res;
    }

    double MaxPower = 0;

    for (const auto& chargerName : mChargerNames) {
        String8 path;
        path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH, chargerName.c_str());
        if (tryGetIntField(path).value_or(0)) {
            switch (readPowerSupplyType(path, chargerName.c_str())) {
                case ANDROID_POWER_SUPPLY_TYPE_AC:
                    mHealthInfo->chargerAcOnline = true;
                    break;
                case ANDROID_POWER_SUPPLY_TYPE_USB:
                    mHealthInfo->chargerUsbOnline = true;
                    break;
                case ANDROID_POWER_SUPPLY_TYPE_WIRELESS:
                    mHealthInfo->chargerWirelessOnline = true;
                    break;
                case ANDROID_POWER_SUPPLY_TYPE_DOCK:
                    mHealthInfo->chargerDockOnline = true;
                    break;
                default:
                    KLOG_WARNING(LOG_TAG, "%s: Unknown power supply type\n", chargerName.c_str());
            }
            path.clear();
            path.appendFormat("%s/%s/current_max", POWER_SUPPLY_SYSFS_PATH, chargerName.c_str());
            int ChargingCurrent = tryGetIntField(path).value_or(0);

            int ChargingVoltage;
            path.clear();
            path.appendFormat("%s/%s/voltage_max", POWER_SUPPLY_SYSFS_PATH, chargerName.c_str());
            if (auto vmax = tryGetIntField(path); vmax.ok() || vmax.error().code() != ENOENT) {
                ChargingVoltage = vmax.value_or(0);
            } else {
                path.clear();
                path.appendFormat("%s/%s/voltage_max_design", POWER_SUPPLY_SYSFS_PATH,
                                  chargerName.c_str());
                if (auto vmax = tryGetIntField(path); vmax.ok() || vmax.error().code() != ENOENT)
                    ChargingVoltage = vmax.value_or(0);
                else
                    ChargingVoltage = DEFAULT_VBUS_VOLTAGE;
            }

            double power =
                    ((double)ChargingCurrent / MILLION) * ((double)ChargingVoltage / MILLION);
            if (MaxPower < power) {
                mHealthInfo->maxChargingCurrentMicroamps = ChargingCurrent;
                mHealthInfo->maxChargingVoltageMicrovolts = ChargingVoltage;
                MaxPower = power;
            }
        }
    }
}

static void doLogTemperature(const HealthInfo& props, const char* devPath) {
    char tempstate[12] = {0};
    FILE *fp;
    int ret;
    int temp = abs(props.batteryTemperatureTenthsCelsius / 10);

    snprintf(tempstate, sizeof(tempstate), "0x%x 0x%x", CDD_SYSTEM_DEVICE_TEMP,
            props.batteryTemperatureTenthsCelsius < 0 ? (temp | 0xF00) : temp);
    fp = fopen(devPath, "w");
    if (fp != NULL) {
        ret = fputs(tempstate, fp);
        if (ret)
            KLOG_ERROR(LOG_TAG, "record battery temp failed: %d\n", ret);
        fclose(fp);
    } else {
            KLOG_ERROR(LOG_TAG, "Error, failed to open file: %s\n", devPath);
    }
}

static void doLogValues(const HealthInfo& props, const struct healthd_config& healthd_config) {
    char dmesgline[256];
    size_t len;
    if (props.batteryPresent) {
        snprintf(dmesgline, sizeof(dmesgline), "battery l=%d v=%d t=%s%d.%d h=%d st=%d",
                 props.batteryLevel, props.batteryVoltageMillivolts,
                 props.batteryTemperatureTenthsCelsius < 0 ? "-" : "",
                 abs(props.batteryTemperatureTenthsCelsius / 10),
                 abs(props.batteryTemperatureTenthsCelsius % 10), props.batteryHealth,
                 props.batteryStatus);
        if(!healthd_config.devstatusPath.empty())
            doLogTemperature(props, healthd_config.devstatusPath.c_str());
        len = strlen(dmesgline);
        if (!healthd_config.batteryCurrentNowPath.empty()) {
            len += snprintf(dmesgline + len, sizeof(dmesgline) - len, " c=%d",
                            props.batteryCurrentMicroamps);
        }

        if (!healthd_config.batteryFullChargePath.empty()) {
            len += snprintf(dmesgline + len, sizeof(dmesgline) - len, " fc=%d",
                            props.batteryFullChargeUah);
        }

        if (!healthd_config.batteryCycleCountPath.empty()) {
            len += snprintf(dmesgline + len, sizeof(dmesgline) - len, " cc=%d",
                            props.batteryCycleCount);
        }
    } else {
        len = snprintf(dmesgline, sizeof(dmesgline), "battery none");
    }

    snprintf(dmesgline + len, sizeof(dmesgline) - len, " chg=%s%s%s%s",
             props.chargerAcOnline ? "a" : "", props.chargerUsbOnline ? "u" : "",
             props.chargerWirelessOnline ? "w" : "", props.chargerDockOnline ? "d" : "");

    KLOG_WARNING(LOG_TAG, "%s\n", dmesgline);
}

void BatteryMonitor::logValues(const HealthInfo_2_1& health_info,
                               const struct healthd_config& healthd_config) {
    HealthInfo aidl_health_info;
    (void)android::h2a::translate(health_info, &aidl_health_info);
    doLogValues(aidl_health_info, healthd_config);
}

void BatteryMonitor::logValues(void) {
    doLogValues(*mHealthInfo, *mHealthdConfig);
}

bool BatteryMonitor::isChargerOnline() {
    const HealthInfo& props = *mHealthInfo;
    return props.chargerAcOnline | props.chargerUsbOnline | props.chargerWirelessOnline |
           props.chargerDockOnline;
}

int BatteryMonitor::getChargeStatus() {
    BatteryStatus result = BatteryStatus::UNKNOWN;
    std::string buf;
    if (readFromFile(mHealthdConfig->batteryStatusPath, &buf).ok())
        result = getBatteryStatus(buf.c_str());

    return static_cast<int>(result);
}

status_t BatteryMonitor::setChargingPolicy(int value) {
    status_t ret = NAME_NOT_FOUND;
    bool result;
    if (!mHealthdConfig->chargingPolicyPath.empty()) {
        result = writeToFile(mHealthdConfig->chargingPolicyPath, value);
        if (!result) {
            KLOG_WARNING(LOG_TAG, "setChargingPolicy fail\n");
            ret = BAD_VALUE;
        } else {
            ret = OK;
        }
    }
    return ret;
}

int BatteryMonitor::getChargingPolicy() {
    std::string buf;

    BatteryChargingPolicy result = BatteryChargingPolicy::DEFAULT;
    if (readFromFile(mHealthdConfig->chargingPolicyPath, &buf).ok())
        result = getBatteryChargingPolicy(buf.c_str());

    return static_cast<int>(result);
}

int BatteryMonitor::getBatteryHealthData(int id) {
    switch (id) {
        case BATTERY_PROP_MANUFACTURING_DATE:
            return tryGetIntField(mHealthdConfig->batteryManufacturingDatePath).value_or(0);
        case BATTERY_PROP_FIRST_USAGE_DATE:
            return tryGetIntField(mHealthdConfig->batteryFirstUsageDatePath).value_or(0);
        case BATTERY_PROP_STATE_OF_HEALTH:
            return tryGetIntField(mHealthdConfig->batteryStateOfHealthPath).value_or(0);
        case BATTERY_PROP_PART_STATUS:
            return static_cast<int>(BatteryPartStatus::UNSUPPORTED);
        default:
            return 0;
    }
}

status_t BatteryMonitor::getProperty(int id, struct BatteryProperty* val) {
    status_t ret = BAD_VALUE;
    std::string buf;

    val->valueInt64 = LONG_MIN;

    auto readIntProp = [&](const String8& path) {
        auto res = tryGetIntField(path);
        if (res.ok()) {
            val->valueInt64 = res.value_or(0);
            ret = OK;
        } else {
            // If tryGetIntField failed for any reason (e.g., unsupported property, read error),
            // return NAME_NOT_FOUND.
            ret = NAME_NOT_FOUND;
        }
    };

    switch (id) {
        case BATTERY_PROP_CHARGE_COUNTER:
            readIntProp(mHealthdConfig->batteryChargeCounterPath);
            break;

        case BATTERY_PROP_CURRENT_NOW:
            readIntProp(mHealthdConfig->batteryCurrentNowPath);
            break;

        case BATTERY_PROP_CURRENT_AVG:
            readIntProp(mHealthdConfig->batteryCurrentAvgPath);
            break;

        case BATTERY_PROP_CAPACITY:
            readIntProp(mHealthdConfig->batteryCapacityPath);
            break;

        case BATTERY_PROP_ENERGY_COUNTER:
            if (mHealthdConfig->energyCounter) {
                ret = mHealthdConfig->energyCounter(&val->valueInt64);
            } else {
                ret = NAME_NOT_FOUND;
            }
            break;

        case BATTERY_PROP_BATTERY_STATUS:
            val->valueInt64 = getChargeStatus();
            ret = OK;
            break;

        case BATTERY_PROP_CHARGING_POLICY:
            val->valueInt64 = getChargingPolicy();
            ret = OK;
            break;

        case BATTERY_PROP_MANUFACTURING_DATE:
        case BATTERY_PROP_FIRST_USAGE_DATE:
        case BATTERY_PROP_STATE_OF_HEALTH:
        case BATTERY_PROP_PART_STATUS:
            val->valueInt64 = getBatteryHealthData(id);
            ret = OK;
            break;

        default:
            break;
    }

    return ret;
}

status_t BatteryMonitor::getSerialNumber(std::optional<std::string>* out) {
    std::string unsanitized;
    if (auto res = readFromFile(mHealthdConfig->batterySerialPath, &unsanitized); res.ok()) {
        *out = {sanitizeSerialNumber(unsanitized)};
    }
    return OK;
}

base::Result<std::optional<std::string>, base::Errno, false> BatteryMonitor::getManufacturer()
        const {
    return getPrintableStringField(mHealthdConfig->batteryManufacturerPath);
}

base::Result<std::optional<std::string>, base::Errno, false> BatteryMonitor::getModelName() const {
    return getPrintableStringField(mHealthdConfig->batteryModelNamePath);
}

base::Result<int64_t, base::Errno, false> BatteryMonitor::getVoltageMinDesign() const {
    auto res = tryGetIntField<int64_t>(mHealthdConfig->batteryVoltageMinDesignPath);
    if (res.ok()) {
        return *res;
    }
    if (res.error().code() == ENOENT) {
        return 0;
    }
    return res.error();
}

int BatteryMonitor::getFullChargeUah() const {
    return tryGetIntField(mHealthdConfig->batteryFullChargePath).value_or(0);
}

int BatteryMonitor::getFullChargeDesignCapacityUah() const {
    return tryGetIntField(mHealthdConfig->batteryFullChargeDesignCapacityUahPath).value_or(0);
}

void BatteryMonitor::dumpState(int fd) {
    char vs[128];
    const HealthInfo& props = *mHealthInfo;

    snprintf(vs, sizeof(vs), "Cached HealthInfo:\n");
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs),
             "  ac: %d usb: %d wireless: %d dock: %d current_max: %d voltage_max: %d\n",
             props.chargerAcOnline, props.chargerUsbOnline, props.chargerWirelessOnline,
             props.chargerDockOnline, props.maxChargingCurrentMicroamps,
             props.maxChargingVoltageMicrovolts);
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs), "  status: %d health: %d present: %d\n", props.batteryStatus,
             props.batteryHealth, props.batteryPresent);
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs), "  level: %d voltage: %d temp: %d\n", props.batteryLevel,
             props.batteryVoltageMillivolts, props.batteryTemperatureTenthsCelsius);
    write(fd, vs, strlen(vs));

    if (!mHealthdConfig->batteryCurrentNowPath.empty()) {
        snprintf(vs, sizeof(vs), "  current now: %d\n", props.batteryCurrentMicroamps);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCycleCountPath.empty()) {
        snprintf(vs, sizeof(vs), "  cycle count: %d\n", props.batteryCycleCount);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryFullChargePath.empty()) {
        snprintf(vs, sizeof(vs), "  Full charge: %d\n", props.batteryFullChargeUah);
        write(fd, vs, strlen(vs));
    }

    snprintf(vs, sizeof(vs), "Real-time Values:\n");
    write(fd, vs, strlen(vs));

    if (auto v = tryGetIntField(mHealthdConfig->batteryCurrentNowPath); v.ok()) {
        snprintf(vs, sizeof(vs), "  current now: %d\n", *v);
        write(fd, vs, strlen(vs));
    }

    if (auto v = tryGetIntField(mHealthdConfig->batteryCurrentAvgPath); v.ok()) {
        snprintf(vs, sizeof(vs), "  current avg: %d\n", *v);
        write(fd, vs, strlen(vs));
    }

    if (auto v = tryGetIntField(mHealthdConfig->batteryChargeCounterPath); v.ok()) {
        snprintf(vs, sizeof(vs), "  charge counter: %d\n", *v);
        write(fd, vs, strlen(vs));
    }
}

void BatteryMonitor::initWithBatteryDevice(const char* const name) {
    // Some devices expose the battery status of sub-component like
    // stylus. Such a device-scoped battery info needs to be skipped
    // in BatteryMonitor, which is intended to report the status of
    // the battery supplying the power to the whole system.
    if (isScopedPowerSupply(name)) {
        return;
    }
    mBatteryDevicePresent = true;

    String8 path;
    if (mHealthdConfig->batteryStatusPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/status", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryStatusPath = path;
    }

    if (mHealthdConfig->batteryHealthPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/health", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryHealthPath = path;
    }

    if (mHealthdConfig->batteryPresentPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/present", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryPresentPath = path;
    }

    if (mHealthdConfig->batteryCapacityPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/capacity", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryCapacityPath = path;
    }

    if (mHealthdConfig->batteryVoltagePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/voltage_now", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryVoltagePath = path;
        }
    }

    if (mHealthdConfig->batteryFullChargePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/charge_full", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryFullChargePath = path;
    }

    if (mHealthdConfig->batteryCurrentNowPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/current_now", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryCurrentNowPath = path;
    }

    if (mHealthdConfig->batteryCycleCountPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/cycle_count", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryCycleCountPath = path;
    }

    if (mHealthdConfig->batteryCapacityLevelPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/capacity_level", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryCapacityLevelPath = path;
        }
    }

    if (mHealthdConfig->batteryChargeTimeToFullNowPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/time_to_full_now", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryChargeTimeToFullNowPath = path;
    }

    if (mHealthdConfig->batteryFullChargeDesignCapacityUahPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/charge_full_design", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0)
            mHealthdConfig->batteryFullChargeDesignCapacityUahPath = path;
    }

    if (mHealthdConfig->batteryCurrentAvgPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/current_avg", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryCurrentAvgPath = path;
    }

    if (mHealthdConfig->batteryChargeCounterPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/charge_counter", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryChargeCounterPath = path;
    }

    if (mHealthdConfig->batteryTemperaturePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/temp", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryTemperaturePath = path;
        }
    }

    if (mHealthdConfig->batteryTechnologyPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/technology", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryTechnologyPath = path;
    }

    if (mHealthdConfig->batteryStateOfHealthPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/state_of_health", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryStateOfHealthPath = path;
        } else {
            path.clear();
            path.appendFormat("%s/%s/health_index", POWER_SUPPLY_SYSFS_PATH, name);
            if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryStateOfHealthPath = path;
        }
    }

    if (mHealthdConfig->batteryHealthStatusPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/health_status", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryHealthStatusPath = path;
        }
    }

    if (mHealthdConfig->batteryManufacturingDatePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/manufacturing_date", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryManufacturingDatePath = path;
    }

    if (mHealthdConfig->batteryFirstUsageDatePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/first_usage_date", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryFirstUsageDatePath = path;
        }
    }

    if (mHealthdConfig->chargingStatePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/charging_state", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->chargingStatePath = path;
    }

    if (mHealthdConfig->chargingPolicyPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/charging_policy", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->chargingPolicyPath = path;
    }

    if (mHealthdConfig->batterySerialPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/serial_number", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batterySerialPath = path;
    }

    if (mHealthdConfig->batteryManufacturerPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/manufacturer", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) {
            mHealthdConfig->batteryManufacturerPath = path;
        }
    }

    if (mHealthdConfig->batteryModelNamePath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/model_name", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryModelNamePath = path;
    }

    if (mHealthdConfig->batteryVoltageMinDesignPath.empty()) {
        path.clear();
        path.appendFormat("%s/%s/voltage_min_design", POWER_SUPPLY_SYSFS_PATH, name);
        if (access(path.c_str(), R_OK) == 0) mHealthdConfig->batteryVoltageMinDesignPath = path;
    }
}

void BatteryMonitor::init(struct healthd_config* hc) {
    String8 path;
    char pval[PROPERTY_VALUE_MAX];

    mHealthdConfig = hc;
    mHealthdConfig->devstatusPath = mDevPath;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(POWER_SUPPLY_SYSFS_PATH), closedir);
    if (dir == NULL) {
        KLOG_ERROR(LOG_TAG, "Could not open %s\n", POWER_SUPPLY_SYSFS_PATH);
    } else {
        struct dirent* entry;

        while ((entry = readdir(dir.get()))) {
            const char* name = entry->d_name;

            if (!strcmp(name, ".") || !strcmp(name, "..")) continue;

            const PowerSupplyType ty = readPowerSupplyType(path, name);

            // Handle device if it's a charger, otherwise do nothing.
            updateChargerPresence(name, ty);

            // If it's a battery, get whatever battery information is available
            // from it.
            if (ty == ANDROID_POWER_SUPPLY_TYPE_BATTERY) {
                initWithBatteryDevice(name);
            }
        }
    }

    // Typically the case for devices which do not have a battery and
    // and are always plugged into AC mains.
    if (!mBatteryDevicePresent) {
        KLOG_WARNING(LOG_TAG, "No battery devices found\n");
        hc->periodic_chores_interval_fast = -1;
        hc->periodic_chores_interval_slow = -1;
    } else {
        if (mHealthdConfig->batteryStatusPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryStatusPath not found\n");
        if (mHealthdConfig->batteryHealthPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryHealthPath not found\n");
        if (mHealthdConfig->batteryPresentPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryPresentPath not found\n");
        if (mHealthdConfig->batteryCapacityPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryCapacityPath not found\n");
        if (mHealthdConfig->batteryVoltagePath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryVoltagePath not found\n");
        if (mHealthdConfig->batteryTemperaturePath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryTemperaturePath not found\n");
        if (mHealthdConfig->batteryTechnologyPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryTechnologyPath not found\n");
        if (mHealthdConfig->batteryCurrentNowPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryCurrentNowPath not found\n");
        if (mHealthdConfig->batteryFullChargePath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryFullChargePath not found\n");
        if (mHealthdConfig->batteryCycleCountPath.empty())
            KLOG_WARNING(LOG_TAG, "BatteryCycleCountPath not found\n");
        if (mHealthdConfig->batteryCapacityLevelPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryCapacityLevelPath not found\n");
        if (mHealthdConfig->batteryChargeTimeToFullNowPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryChargeTimeToFullNowPath. not found\n");
        if (mHealthdConfig->batteryFullChargeDesignCapacityUahPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryFullChargeDesignCapacityUahPath. not found\n");
        if (mHealthdConfig->batteryStateOfHealthPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryStateOfHealthPath not found\n");
        if (mHealthdConfig->batteryHealthStatusPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryHealthStatusPath not found\n");
        if (mHealthdConfig->batteryManufacturingDatePath.empty())
            KLOG_WARNING(LOG_TAG, "batteryManufacturingDatePath not found\n");
        if (mHealthdConfig->batteryFirstUsageDatePath.empty())
            KLOG_WARNING(LOG_TAG, "batteryFirstUsageDatePath not found\n");
        if (mHealthdConfig->chargingStatePath.empty())
            KLOG_WARNING(LOG_TAG, "chargingStatePath not found\n");
        if (mHealthdConfig->chargingPolicyPath.empty())
            KLOG_WARNING(LOG_TAG, "chargingPolicyPath not found\n");
        if (mHealthdConfig->batterySerialPath.empty())
            KLOG_WARNING(LOG_TAG, "batterySerialPath not found\n");
        if (mHealthdConfig->batteryManufacturerPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryManufacturerPath not found\n");
        if (mHealthdConfig->batteryModelNamePath.empty())
            KLOG_WARNING(LOG_TAG, "batteryModelNamePath not found\n");
        if (mHealthdConfig->batteryVoltageMinDesignPath.empty())
            KLOG_WARNING(LOG_TAG, "batteryVoltageMinDesignPath not found\n");
    }

    if (property_get("ro.boot.fake_battery", pval, NULL) > 0 && strtol(pval, NULL, 10) != 0) {
        mBatteryFixedCapacity = FAKE_BATTERY_CAPACITY;
        mBatteryFixedTemperature = FAKE_BATTERY_TEMPERATURE;
    }
}

void BatteryMonitor::updateChargerPresence(const char* const name,
                                           std::optional<PowerSupplyType> providedType) {
    const auto itIgnoreName = find(mHealthdConfig->ignorePowerSupplyNames.cbegin(),
                                   mHealthdConfig->ignorePowerSupplyNames.cend(), String8(name));
    if (itIgnoreName != mHealthdConfig->ignorePowerSupplyNames.cend()) return;

    String8 path;

    PowerSupplyType ty = ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;
    if (providedType.has_value()) {
        ty = *providedType;
    } else {
        ty = readPowerSupplyType(path, name);
    }

    switch (ty) {
        case ANDROID_POWER_SUPPLY_TYPE_BATTERY:
            // Batteries are not chargers and should never appear to be, so
            // can be ignored completely.
            break;

        case ANDROID_POWER_SUPPLY_TYPE_AC:
        case ANDROID_POWER_SUPPLY_TYPE_USB:
        case ANDROID_POWER_SUPPLY_TYPE_WIRELESS:
        case ANDROID_POWER_SUPPLY_TYPE_DOCK:
            path.clear();
            path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH, name);
            if (access(path.c_str(), R_OK) == 0) {
                const auto [_it, inserted] = mChargerNames.insert(name);
                if (inserted) {
                    KLOG_INFO(LOG_TAG, "Discovered new charger device %s", name);
                }
            }
            break;

        case ANDROID_POWER_SUPPLY_TYPE_UNKNOWN:
            // TYPE_UNKNOWN means either an unrecognized type or the file doesn't exist.
            // In either case, this is definitely not a valid charger if it previously was.
            if (mChargerNames.erase(name) > 0) {
                KLOG_INFO(LOG_TAG, "Charger device %s is gone", name);
            }
            break;
    }
}

};  // namespace android

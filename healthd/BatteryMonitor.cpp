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

#include <healthd/healthd.h>
#include <healthd/BatteryMonitor.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <memory>

#include <android-base/file.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>
#include <cutils/properties.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/Vector.h>
#include <sys/system_properties.h> // MOT, a18273, IKMODS-149

#define POWER_SUPPLY_SUBSYSTEM "power_supply"
#define POWER_SUPPLY_SYSFS_PATH "/sys/class/" POWER_SUPPLY_SUBSYSTEM
#define FAKE_BATTERY_CAPACITY 42
#define FAKE_BATTERY_TEMPERATURE 424
#define ALWAYS_PLUGGED_CAPACITY 100
#define MILLION 1.0e6
#define DEFAULT_VBUS_VOLTAGE 5000000

// BEGIN MOT, a18273, IKMODS-149
#define POWER_SUPPLY_MOD "gb_battery"

#define POWER_SUPPLY_MOD_BATTERY_MODE_PROP "sys.mod.batterymode"

#define POWER_SUPPLY_MOD_TYPE_PATH "/sys/class/power_supply/gb_ptp/internal_send"
#define POWER_SOURCE_MOD_PATH "/sys/class/power_supply/gb_ptp/power_source"
#define POWER_SUPPLY_MOD_RECHRG_START_SOC "/sys/module/qpnp_smbcharger_mmi/parameters/eb_rechrg_start_soc"
#define POWER_SUPPLY_MOD_RECHRG_STOP_SOC "/sys/module/qpnp_smbcharger_mmi/parameters/eb_rechrg_stop_soc"

#define POWER_SUPPLY_MOD_TYPE_UNKNOWN      0
#define POWER_SUPPLY_MOD_TYPE_REMOTE       1
#define POWER_SUPPLY_MOD_TYPE_SUPPLEMENTAL 2
#define POWER_SUPPLY_MOD_TYPE_EMERGENCY    3

// the following defines should be consistent with those defined in:
// motorola/frameworks/base/motomods/service/core/src/com/motorola/modservice/
//   ui/Constants.java
#define POWER_SUPPLY_MOD_BATTERY_MODE_TOPOFF       0
#define POWER_SUPPLY_MOD_BATTERY_MODE_EFFICIENCY   1
// END IKMODS-149

namespace android {

struct sysfsStringEnumMap {
    const char* s;
    int val;
};

static int mapSysfsString(const char* str,
                          struct sysfsStringEnumMap map[]) {
    for (int i = 0; map[i].s; i++)
        if (!strcmp(str, map[i].s))
            return map[i].val;

    return -1;
}

static void initBatteryProperties(BatteryProperties* props) {
    props->chargerAcOnline = false;
    props->chargerUsbOnline = false;
    props->chargerWirelessOnline = false;
    props->maxChargingCurrent = 0;
    props->maxChargingVoltage = 0;
    props->batteryStatus = BATTERY_STATUS_UNKNOWN;
    props->batteryHealth = BATTERY_HEALTH_UNKNOWN;
    props->batteryPresent = false;
    props->batteryLevel = 0;
    props->batteryVoltage = 0;
    props->batteryTemperature = 0;
    props->batteryCurrent = 0;
    props->batteryCycleCount = 0;
    props->batteryFullCharge = 0;
    props->batteryChargeCounter = 0;
    props->batteryTechnology.clear();
}

BatteryMonitor::BatteryMonitor() : mHealthdConfig(nullptr), mBatteryDevicePresent(false),
    mAlwaysPluggedDevice(false), mBatteryFixedCapacity(0), mBatteryFixedTemperature(0) {
    initBatteryProperties(&props);
}

int BatteryMonitor::getBatteryStatus(const char* status) {
    int ret;
    struct sysfsStringEnumMap batteryStatusMap[] = {
        { "Unknown", BATTERY_STATUS_UNKNOWN },
        { "Charging", BATTERY_STATUS_CHARGING },
        { "Discharging", BATTERY_STATUS_DISCHARGING },
        { "Not charging", BATTERY_STATUS_NOT_CHARGING },
        { "Full", BATTERY_STATUS_FULL },
        { NULL, 0 },
    };

    ret = mapSysfsString(status, batteryStatusMap);
    if (ret < 0) {
        KLOG_WARNING(LOG_TAG, "Unknown battery status '%s'\n", status);
        ret = BATTERY_STATUS_UNKNOWN;
    }

    return ret;
}

int BatteryMonitor::getBatteryHealth(const char* status) {
    int ret;
    struct sysfsStringEnumMap batteryHealthMap[] = {
        { "Unknown", BATTERY_HEALTH_UNKNOWN },
        { "Good", BATTERY_HEALTH_GOOD },
        { "Overheat", BATTERY_HEALTH_OVERHEAT },
        { "Dead", BATTERY_HEALTH_DEAD },
        { "Over voltage", BATTERY_HEALTH_OVER_VOLTAGE },
        { "Unspecified failure", BATTERY_HEALTH_UNSPECIFIED_FAILURE },
        { "Cold", BATTERY_HEALTH_COLD },
        { NULL, 0 },
    };

    ret = mapSysfsString(status, batteryHealthMap);
    if (ret < 0) {
        KLOG_WARNING(LOG_TAG, "Unknown battery health '%s'\n", status);
        ret = BATTERY_HEALTH_UNKNOWN;
    }

    return ret;
}

int BatteryMonitor::readFromFile(const String8& path, std::string* buf) {
    if (android::base::ReadFileToString(path.c_str(), buf)) {
        *buf = android::base::Trim(*buf);
    }
    return buf->length();
}

BatteryMonitor::PowerSupplyType BatteryMonitor::readPowerSupplyType(const String8& path) {
    std::string buf;
    BatteryMonitor::PowerSupplyType ret;
    struct sysfsStringEnumMap supplyTypeMap[] = {
            { "Unknown", ANDROID_POWER_SUPPLY_TYPE_UNKNOWN },
            { "Battery", ANDROID_POWER_SUPPLY_TYPE_BATTERY },
            { "UPS", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "Mains", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB", ANDROID_POWER_SUPPLY_TYPE_USB },
            { "USB_DCP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_HVDCP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_CDP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_ACA", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_C", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_PD", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_PD_DRP", ANDROID_POWER_SUPPLY_TYPE_USB },
            { "Wireless", ANDROID_POWER_SUPPLY_TYPE_WIRELESS },
            { "BMS", ANDROID_POWER_SUPPLY_TYPE_BMS }, //Motorola, drmn68, 05/16/2017, IKSWN-51081
            { NULL, 0 },
    };

    if (readFromFile(path, &buf) <= 0)
        return ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;

    ret = (BatteryMonitor::PowerSupplyType)mapSysfsString(buf.c_str(), supplyTypeMap);
    if (ret < 0) {
        KLOG_WARNING(LOG_TAG, "Unknown power supply type '%s'\n", buf.c_str());
        ret = ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;
    }

    return ret;
}

bool BatteryMonitor::getBooleanField(const String8& path) {
    std::string buf;
    bool value = false;

    if (readFromFile(path, &buf) > 0)
        if (buf[0] != '0')
            value = true;

    return value;
}

int BatteryMonitor::getIntField(const String8& path) {
    std::string buf;
    int value = 0;

    if (readFromFile(path, &buf) > 0)
        android::base::ParseInt(buf, &value);

    return value;
}

bool BatteryMonitor::update(void) {
    bool logthis;

    initBatteryProperties(&props);

    if (!mHealthdConfig->batteryPresentPath.isEmpty())
        props.batteryPresent = getBooleanField(mHealthdConfig->batteryPresentPath);
    else
        props.batteryPresent = mBatteryDevicePresent;

    props.batteryLevel = mBatteryFixedCapacity ?
        mBatteryFixedCapacity :
        getIntField(mHealthdConfig->batteryCapacityPath);
    props.batteryVoltage = getIntField(mHealthdConfig->batteryVoltagePath) / 1000;

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty())
        props.batteryCurrent = getIntField(mHealthdConfig->batteryCurrentNowPath) / 1000;

    if (!mHealthdConfig->batteryFullChargePath.isEmpty())
        props.batteryFullCharge = getIntField(mHealthdConfig->batteryFullChargePath);

    if (!mHealthdConfig->batteryCycleCountPath.isEmpty())
        props.batteryCycleCount = getIntField(mHealthdConfig->batteryCycleCountPath);

    if (!mHealthdConfig->batteryChargeCounterPath.isEmpty())
        props.batteryChargeCounter = getIntField(mHealthdConfig->batteryChargeCounterPath);

    props.batteryTemperature = mBatteryFixedTemperature ?
        mBatteryFixedTemperature :
        getIntField(mHealthdConfig->batteryTemperaturePath);

    // For devices which do not have battery and are always plugged
    // into power souce.
    if (mAlwaysPluggedDevice) {
        props.chargerAcOnline = true;
        props.batteryPresent = true;
        props.batteryStatus = BATTERY_STATUS_CHARGING;
        props.batteryHealth = BATTERY_HEALTH_GOOD;
    }

    std::string buf;

    if (readFromFile(mHealthdConfig->batteryStatusPath, &buf) > 0)
        props.batteryStatus = getBatteryStatus(buf.c_str());

    if (readFromFile(mHealthdConfig->batteryHealthPath, &buf) > 0)
        props.batteryHealth = getBatteryHealth(buf.c_str());

    if (readFromFile(mHealthdConfig->batteryTechnologyPath, &buf) > 0)
        props.batteryTechnology = String8(buf.c_str());

    unsigned int i;
    double MaxPower = 0;

    for (i = 0; i < mChargerNames.size(); i++) {
        String8 path;
        path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH,
                          mChargerNames[i].string());
        if (getIntField(path)) {
            path.clear();
            path.appendFormat("%s/%s/type", POWER_SUPPLY_SYSFS_PATH,
                              mChargerNames[i].string());
            switch(readPowerSupplyType(path)) {
            case ANDROID_POWER_SUPPLY_TYPE_AC:
                props.chargerAcOnline = true;
                break;
            case ANDROID_POWER_SUPPLY_TYPE_USB:
                props.chargerUsbOnline = true;
                break;
            case ANDROID_POWER_SUPPLY_TYPE_WIRELESS:
                props.chargerWirelessOnline = true;
                break;
            default:
                KLOG_WARNING(LOG_TAG, "%s: Unknown power supply type\n",
                             mChargerNames[i].string());
            }
            path.clear();
            path.appendFormat("%s/%s/current_max", POWER_SUPPLY_SYSFS_PATH,
                              mChargerNames[i].string());
            int ChargingCurrent =
                    (access(path.string(), R_OK) == 0) ? getIntField(path) : 0;

            path.clear();
            path.appendFormat("%s/%s/voltage_max", POWER_SUPPLY_SYSFS_PATH,
                              mChargerNames[i].string());

            int ChargingVoltage =
                (access(path.string(), R_OK) == 0) ? getIntField(path) :
                DEFAULT_VBUS_VOLTAGE;

            double power = ((double)ChargingCurrent / MILLION) *
                           ((double)ChargingVoltage / MILLION);
            if (MaxPower < power) {
                props.maxChargingCurrent = ChargingCurrent;
                props.maxChargingVoltage = ChargingVoltage;
                MaxPower = power;
            }
        }
    }

    // BEGIN MOT, a18273, IKMODS-149
    props.modLevel = -1;
    props.modStatus = BATTERY_STATUS_UNKNOWN;
    props.modType = POWER_SUPPLY_MOD_TYPE_UNKNOWN;
    props.modPowerSource = 0;
    props.modFlag = 0;

    // get mod battery status
    if (access(mHealthdConfig->modStatusPath.string(), R_OK) == 0) {
        if (readFromFile(mHealthdConfig->modStatusPath, &buf) > 0) {
            props.modStatus = getBatteryStatus(buf.c_str());
        }
    }

    // don't bother to read other mod values when it not attached
    if (props.modStatus != BATTERY_STATUS_UNKNOWN) {
        // get mod battery level
        if (access(mHealthdConfig->modCapacityPath.string(), R_OK) == 0) {
            props.modLevel = getIntField(mHealthdConfig->modCapacityPath);
        }
        // get mod type
        if (access(mHealthdConfig->modTypePath.string(), R_OK) == 0) {
            props.modType = getIntField(mHealthdConfig->modTypePath);
        }

        // get mod powersource
        if (access(mHealthdConfig->modPowerSourcePath.string(), R_OK) == 0) {
            props.modPowerSource = getIntField(mHealthdConfig->modPowerSourcePath);
        }

        // attempt to hack battery level for non-empty supplemental mod
        if ((props.modType == POWER_SUPPLY_MOD_TYPE_SUPPLEMENTAL) &&
            (props.modLevel > 0)) {

            // get battery mode from system properties
            char value[PROP_VALUE_MAX];
            property_get(POWER_SUPPLY_MOD_BATTERY_MODE_PROP, value, "0");
            int batteryMode = atoi(value);

            if (batteryMode == POWER_SUPPLY_MOD_BATTERY_MODE_TOPOFF) {
                if (props.batteryLevel == 99) {
                    props.batteryLevel = 100;
                    props.modFlag = 1;
                }
            } else if (batteryMode == POWER_SUPPLY_MOD_BATTERY_MODE_EFFICIENCY) {
                int startLevel = -1, stopLevel = -1;
                if (access(mHealthdConfig->modRechargeStartLevelPath.string(), R_OK) == 0) {
                    startLevel = getIntField(mHealthdConfig->modRechargeStartLevelPath);
                }
                if (access(mHealthdConfig->modRechargeStopLevelPath.string(), R_OK) == 0) {
                    stopLevel = getIntField(mHealthdConfig->modRechargeStopLevelPath);
                }
                if ((startLevel >= 0) && (stopLevel > 0) && (startLevel < stopLevel)) {
                    if (props.batteryLevel == startLevel) {
                        props.batteryLevel = stopLevel;
                        props.modFlag = stopLevel - startLevel;
                    }
                }
            }
        }
    }
    // mod attach/detach can cause mod sys file ready/destory in different time. Make sure
    // mod value reported consistent
    if (props.modLevel < 0 ||
            props.modStatus == BATTERY_STATUS_UNKNOWN ||
            props.modType == POWER_SUPPLY_MOD_TYPE_UNKNOWN) {
        props.modLevel = -1;
        props.modStatus == BATTERY_STATUS_UNKNOWN;
        props.modType = POWER_SUPPLY_MOD_TYPE_UNKNOWN;
        props.modPowerSource = 0;
        props.modFlag = 0;
    }
    // END IKMODS-149

    logthis = !healthd_board_battery_update(&props);

    if (logthis) {
        char dmesgline[256];
        size_t len;
        if (props.batteryPresent) {
            snprintf(dmesgline, sizeof(dmesgline),
                 "battery l=%d v=%d t=%s%d.%d h=%d st=%d",
                 props.batteryLevel, props.batteryVoltage,
                 props.batteryTemperature < 0 ? "-" : "",
                 abs(props.batteryTemperature / 10),
                 abs(props.batteryTemperature % 10), props.batteryHealth,
                 props.batteryStatus);

            len = strlen(dmesgline);
            if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
                len += snprintf(dmesgline + len, sizeof(dmesgline) - len,
                                " c=%d", props.batteryCurrent);
            }

            if (!mHealthdConfig->batteryFullChargePath.isEmpty()) {
                len += snprintf(dmesgline + len, sizeof(dmesgline) - len,
                                " fc=%d", props.batteryFullCharge);
            }

            if (!mHealthdConfig->batteryCycleCountPath.isEmpty()) {
                len += snprintf(dmesgline + len, sizeof(dmesgline) - len,
                                " cc=%d", props.batteryCycleCount);
            }

            // BEGIN MOT, a18273, IKMODS-149
            char b[20];
            snprintf(b, sizeof(b), " ml=%d", props.modLevel);
            strlcat(dmesgline, b, sizeof(dmesgline));

            snprintf(b, sizeof(b), " mst=%d", props.modStatus);
            strlcat(dmesgline, b, sizeof(dmesgline));

            snprintf(b, sizeof(b), " mf=%d", props.modFlag);
            strlcat(dmesgline, b, sizeof(dmesgline));

            snprintf(b, sizeof(b), " mt=%d", props.modType);
            strlcat(dmesgline, b, sizeof(dmesgline));

            snprintf(b, sizeof(b), " mps=%d", props.modPowerSource);
            strlcat(dmesgline, b, sizeof(dmesgline));
            // END IKMODS-149
        } else {
            len = snprintf(dmesgline, sizeof(dmesgline),
                 "battery none");
        }

        len = strlen(dmesgline);
        snprintf(dmesgline + len, sizeof(dmesgline) - len, " chg=%s%s%s",
                 props.chargerAcOnline ? "a" : "",
                 props.chargerUsbOnline ? "u" : "",
                 props.chargerWirelessOnline ? "w" : "");

        KLOG_WARNING(LOG_TAG, "%s\n", dmesgline);
    }

    healthd_mode_ops->battery_update(&props);
    return props.chargerAcOnline | props.chargerUsbOnline |
            props.chargerWirelessOnline;
}

int BatteryMonitor::getChargeStatus() {
    int result = BATTERY_STATUS_UNKNOWN;
    if (!mHealthdConfig->batteryStatusPath.isEmpty()) {
        std::string buf;
        if (readFromFile(mHealthdConfig->batteryStatusPath, &buf) > 0)
            result = getBatteryStatus(buf.c_str());
    }
    return result;
}

status_t BatteryMonitor::getProperty(int id, struct BatteryProperty *val) {
    status_t ret = BAD_VALUE;
    std::string buf;

    val->valueInt64 = LONG_MIN;

    switch(id) {
    case BATTERY_PROP_CHARGE_COUNTER:
        if (!mHealthdConfig->batteryChargeCounterPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryChargeCounterPath);
            ret = NO_ERROR;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_CURRENT_NOW:
        if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryCurrentNowPath);
            ret = NO_ERROR;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_CURRENT_AVG:
        if (!mHealthdConfig->batteryCurrentAvgPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryCurrentAvgPath);
            ret = NO_ERROR;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_CAPACITY:
        if (!mHealthdConfig->batteryCapacityPath.isEmpty()) {
            val->valueInt64 =
                getIntField(mHealthdConfig->batteryCapacityPath);
            ret = NO_ERROR;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;

    case BATTERY_PROP_ENERGY_COUNTER:
        if (mHealthdConfig->energyCounter) {
            ret = mHealthdConfig->energyCounter(&val->valueInt64);
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;
    // BEGIN MOT, a18273, IKSWM-23739
    case BATTERY_PROP_CHARGE_FULL:
        if (!mHealthdConfig->batteryFullChargePath.isEmpty() &&
            (access(mHealthdConfig->batteryFullChargePath.string(), R_OK) == 0)) {
            val->valueInt64 = getIntField(mHealthdConfig->batteryFullChargePath);
            ret = NO_ERROR;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;
    // END IKSWM-23739
        // BEGIN MOT, a18273, IKMODS-149
    case BATTERY_PROP_MOD_CHARGE_FULL:
        if (!mHealthdConfig->modChargeFullPath.isEmpty() &&
            (access(mHealthdConfig->modChargeFullPath.string(), R_OK) == 0)) {
            val->valueInt64 = getIntField(mHealthdConfig->modChargeFullPath);
            ret = NO_ERROR;
        } else {
            ret = NAME_NOT_FOUND;
        }
        break;
        // END IKMODS-149

    case BATTERY_PROP_BATTERY_STATUS:
        if (mAlwaysPluggedDevice) {
            val->valueInt64 = BATTERY_STATUS_CHARGING;
        } else {
            val->valueInt64 = getChargeStatus();
        }
        ret = NO_ERROR;
        break;

    default:
        break;
    }

    return ret;
}

void BatteryMonitor::dumpState(int fd) {
    int v;
    char vs[128];

    snprintf(vs, sizeof(vs), "ac: %d usb: %d wireless: %d current_max: %d voltage_max: %d\n",
             props.chargerAcOnline, props.chargerUsbOnline,
             props.chargerWirelessOnline, props.maxChargingCurrent,
             props.maxChargingVoltage);
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs), "status: %d health: %d present: %d\n",
             props.batteryStatus, props.batteryHealth, props.batteryPresent);
    write(fd, vs, strlen(vs));
    snprintf(vs, sizeof(vs), "level: %d voltage: %d temp: %d\n",
             props.batteryLevel, props.batteryVoltage,
             props.batteryTemperature);
    write(fd, vs, strlen(vs));

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
        v = getIntField(mHealthdConfig->batteryCurrentNowPath);
        snprintf(vs, sizeof(vs), "current now: %d\n", v);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCurrentAvgPath.isEmpty()) {
        v = getIntField(mHealthdConfig->batteryCurrentAvgPath);
        snprintf(vs, sizeof(vs), "current avg: %d\n", v);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryChargeCounterPath.isEmpty()) {
        v = getIntField(mHealthdConfig->batteryChargeCounterPath);
        snprintf(vs, sizeof(vs), "charge counter: %d\n", v);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
        snprintf(vs, sizeof(vs), "current now: %d\n", props.batteryCurrent);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryCycleCountPath.isEmpty()) {
        snprintf(vs, sizeof(vs), "cycle count: %d\n", props.batteryCycleCount);
        write(fd, vs, strlen(vs));
    }

    if (!mHealthdConfig->batteryFullChargePath.isEmpty()) {
        snprintf(vs, sizeof(vs), "Full charge: %d\n", props.batteryFullCharge);
        write(fd, vs, strlen(vs));
    }
}

void BatteryMonitor::init(struct healthd_config *hc) {
    String8 path;
    char pval[PROPERTY_VALUE_MAX];

    mHealthdConfig = hc;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(POWER_SUPPLY_SYSFS_PATH), closedir);
    if (dir == NULL) {
        KLOG_ERROR(LOG_TAG, "Could not open %s\n", POWER_SUPPLY_SYSFS_PATH);
    } else {
        struct dirent* entry;

        while ((entry = readdir(dir.get()))) {
            const char* name = entry->d_name;

            if (!strcmp(name, ".") || !strcmp(name, ".."))
                continue;

            // MOT, a18273, IKMODS-149
            // ignore gb_battery as we will hardcode path for mod
            if (!strcmp(name, POWER_SUPPLY_MOD)) continue;

            // Look for "type" file in each subdirectory
            path.clear();
            path.appendFormat("%s/%s/type", POWER_SUPPLY_SYSFS_PATH, name);
            switch(readPowerSupplyType(path)) {
            case ANDROID_POWER_SUPPLY_TYPE_AC:
            case ANDROID_POWER_SUPPLY_TYPE_USB:
            case ANDROID_POWER_SUPPLY_TYPE_WIRELESS:
                path.clear();
                path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH, name);
                if (access(path.string(), R_OK) == 0)
                    mChargerNames.add(String8(name));
                break;

            case ANDROID_POWER_SUPPLY_TYPE_BATTERY:
                mBatteryDevicePresent = true;

                if (mHealthdConfig->batteryStatusPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/status", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryStatusPath = path;
                }

                if (mHealthdConfig->batteryHealthPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/health", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryHealthPath = path;
                }

                if (mHealthdConfig->batteryPresentPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/present", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryPresentPath = path;
                }

                if (mHealthdConfig->batteryCapacityPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/capacity", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCapacityPath = path;
                }

                if (mHealthdConfig->batteryVoltagePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/voltage_now",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0) {
                        mHealthdConfig->batteryVoltagePath = path;
                    } else {
                        path.clear();
                        path.appendFormat("%s/%s/batt_vol",
                                          POWER_SUPPLY_SYSFS_PATH, name);
                        if (access(path, R_OK) == 0)
                            mHealthdConfig->batteryVoltagePath = path;
                    }
                }

                if (mHealthdConfig->batteryFullChargePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/charge_full",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryFullChargePath = path;
                }

                if (mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/current_now",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCurrentNowPath = path;
                }

                if (mHealthdConfig->batteryCycleCountPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/cycle_count",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCycleCountPath = path;
                }

                if (mHealthdConfig->batteryCurrentAvgPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/current_avg",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCurrentAvgPath = path;
                }

                if (mHealthdConfig->batteryChargeCounterPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/charge_counter",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryChargeCounterPath = path;
                }

                if (mHealthdConfig->batteryTemperaturePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/temp", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0) {
                        mHealthdConfig->batteryTemperaturePath = path;
                    } else {
                        path.clear();
                        path.appendFormat("%s/%s/batt_temp",
                                          POWER_SUPPLY_SYSFS_PATH, name);
                        if (access(path, R_OK) == 0)
                            mHealthdConfig->batteryTemperaturePath = path;
                    }
                }

                if (mHealthdConfig->batteryTechnologyPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/technology",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryTechnologyPath = path;
                }

                break;

            // Begin Motorola, drmn68, 05/16/2017, IKSWN-51081
            case ANDROID_POWER_SUPPLY_TYPE_BMS:
                if (mHealthdConfig->batteryFullChargePath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/charge_full",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0) {
                        mHealthdConfig->batteryFullChargePath = path;
                    }
                }
                break;
            // End IKSWN-51081
            case ANDROID_POWER_SUPPLY_TYPE_UNKNOWN:
                break;
            }
        }
    }

    // BEGIN MOT, a18273, IKMODS-149
    // mod battery level path
    path.clear();
    path.appendFormat("%s/%s/capacity", POWER_SUPPLY_SYSFS_PATH, POWER_SUPPLY_MOD);
    mHealthdConfig->modCapacityPath = path;

    // mod battery status path
    path.clear();
    path.appendFormat("%s/%s/status", POWER_SUPPLY_SYSFS_PATH, POWER_SUPPLY_MOD);
    mHealthdConfig->modStatusPath = path;

    // mod battery full capacity path
    path.clear();
    path.appendFormat("%s/%s/charge_full_design", POWER_SUPPLY_SYSFS_PATH, POWER_SUPPLY_MOD);
    mHealthdConfig->modChargeFullPath = path;

    // mod type path
    mHealthdConfig->modTypePath = POWER_SUPPLY_MOD_TYPE_PATH;

    // mod Power Source path
    mHealthdConfig->modPowerSourcePath = POWER_SOURCE_MOD_PATH;

    // efficiency mode recharge start path
    mHealthdConfig->modRechargeStartLevelPath = POWER_SUPPLY_MOD_RECHRG_START_SOC;

    // efficiency mode recharge stop path
    mHealthdConfig->modRechargeStopLevelPath = POWER_SUPPLY_MOD_RECHRG_STOP_SOC;
    // END IKMODS-149

    // Typically the case for devices which do not have a battery and
    // and are always plugged into AC mains.
    if (!mBatteryDevicePresent) {
        KLOG_WARNING(LOG_TAG, "No battery devices found\n");
        hc->periodic_chores_interval_fast = -1;
        hc->periodic_chores_interval_slow = -1;
        mBatteryFixedCapacity = ALWAYS_PLUGGED_CAPACITY;
        mBatteryFixedTemperature = FAKE_BATTERY_TEMPERATURE;
        mAlwaysPluggedDevice = true;
    } else {
        if (mHealthdConfig->batteryStatusPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryStatusPath not found\n");
        if (mHealthdConfig->batteryHealthPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryHealthPath not found\n");
        if (mHealthdConfig->batteryPresentPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryPresentPath not found\n");
        if (mHealthdConfig->batteryCapacityPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCapacityPath not found\n");
        if (mHealthdConfig->batteryVoltagePath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryVoltagePath not found\n");
        if (mHealthdConfig->batteryTemperaturePath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryTemperaturePath not found\n");
        if (mHealthdConfig->batteryTechnologyPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryTechnologyPath not found\n");
        if (mHealthdConfig->batteryCurrentNowPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCurrentNowPath not found\n");
        if (mHealthdConfig->batteryFullChargePath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryFullChargePath not found\n");
        if (mHealthdConfig->batteryCycleCountPath.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCycleCountPath not found\n");
    }

    if (property_get("ro.boot.fake_battery", pval, NULL) > 0
                                               && strtol(pval, NULL, 10) != 0) {
        mBatteryFixedCapacity = FAKE_BATTERY_CAPACITY;
        mBatteryFixedTemperature = FAKE_BATTERY_TEMPERATURE;
    }
}

}; // namespace android

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

#include "healthd.h"
#include "BatteryMonitor.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <batteryservice/BatteryService.h>
#include <cutils/klog.h>
#include <cutils/properties.h>
#include <sys/types.h>
#include <utils/Errors.h>
#include <utils/String8.h>
#include <utils/Vector.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>

#define POWER_SUPPLY_SUBSYSTEM "power_supply"
#define POWER_SUPPLY_SYSFS_PATH "/sys/class/" POWER_SUPPLY_SUBSYSTEM
#define FAKE_BATTERY_CAPACITY 42
#define FAKE_BATTERY_TEMPERATURE 424
#define FAKE_BATTERY_CAPACITY_SMB 50
#define BATTERY_SOCKET_NAME "rild-oem"
static int previous_adjust_power = -1;

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

int BatteryMonitor::getBatteryStatus(const char* status) {
    int ret;
    struct sysfsStringEnumMap batteryStatusMap[] = {
        { "Unknown", BATTERY_STATUS_UNKNOWN },
        { "Charging", BATTERY_STATUS_CHARGING },
        { "Discharging", BATTERY_STATUS_DISCHARGING },
        { "Not charging", BATTERY_STATUS_NOT_CHARGING },
        { "Full", BATTERY_STATUS_FULL },
        { "Cmd discharging", BATTERY_STATUS_CMD_DISCHARGING },
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

int BatteryMonitor::readFromFile(const String8& path, char* buf, size_t size) {
    char *cp = NULL;

    if (path.isEmpty())
        return -1;
    int fd = open(path.string(), O_RDONLY, 0);
    if (fd == -1) {
        KLOG_ERROR(LOG_TAG, "Could not open '%s'\n", path.string());
        return -1;
    }

    ssize_t count = TEMP_FAILURE_RETRY(read(fd, buf, size));
    if (count > 0)
            cp = (char *)memrchr(buf, '\n', count);

    if (cp)
        *cp = '\0';
    else
        buf[0] = '\0';

    close(fd);
    return count;
}

BatteryMonitor::PowerSupplyType BatteryMonitor::readPowerSupplyType(const String8& path) {
    const int SIZE = 128;
    char buf[SIZE];
    int length = readFromFile(path, buf, SIZE);
    BatteryMonitor::PowerSupplyType ret;
    struct sysfsStringEnumMap supplyTypeMap[] = {
            { "Unknown", ANDROID_POWER_SUPPLY_TYPE_UNKNOWN },
            { "Battery", ANDROID_POWER_SUPPLY_TYPE_BATTERY },
            { "UPS", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "Mains", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB", ANDROID_POWER_SUPPLY_TYPE_USB },
            { "USB_DCP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_CDP", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "USB_ACA", ANDROID_POWER_SUPPLY_TYPE_AC },
            { "Wireless", ANDROID_POWER_SUPPLY_TYPE_WIRELESS },
            { NULL, 0 },
    };

    if (length <= 0)
        return ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;

    ret = (BatteryMonitor::PowerSupplyType)mapSysfsString(buf, supplyTypeMap);
    if (ret < 0)
        ret = ANDROID_POWER_SUPPLY_TYPE_UNKNOWN;

    return ret;
}

bool BatteryMonitor::getBooleanField(const String8& path) {
    const int SIZE = 16;
    char buf[SIZE];

    bool value = false;
    if (readFromFile(path, buf, SIZE) > 0) {
        if (buf[0] != '0') {
            value = true;
        }
    }

    return value;
}

int BatteryMonitor::getIntField(const String8& path) {
    const int SIZE = 128;
    char buf[SIZE];

    int value = 0;
    if (readFromFile(path, buf, SIZE) > 0) {
        value = strtol(buf, NULL, 0);
    }
    return value;
}

bool BatteryMonitor::update(void) {
    bool logthis;

    props.chargerAcOnline = false;
    props.chargerUsbOnline = false;
    props.chargerWirelessOnline = false;
    props.batteryStatus = BATTERY_STATUS_UNKNOWN;
    props.batteryHealth = BATTERY_HEALTH_UNKNOWN;

    if (!mHealthdConfig->batteryPresentPath.isEmpty())
        props.batteryPresent = getBooleanField(mHealthdConfig->batteryPresentPath);
    else
        props.batteryPresent = mBatteryDevicePresent;

    props.batteryLevel = mBatteryFixedCapacity ?
        mBatteryFixedCapacity :
        getIntField(mHealthdConfig->batteryCapacityPath);
    props.batteryVoltage = getIntField(mHealthdConfig->batteryVoltagePath);

    props.batteryTemperature = mBatteryFixedTemperature ?
        mBatteryFixedTemperature :
        getIntField(mHealthdConfig->batteryTemperaturePath);
    
    update_smb();

    const int SIZE = 128;
    char buf[SIZE];
    String8 btech;

    if (readFromFile(mHealthdConfig->batteryStatusPath, buf, SIZE) > 0)
        props.batteryStatus = getBatteryStatus(buf);

    if (readFromFile(mHealthdConfig->batteryHealthPath, buf, SIZE) > 0)
        props.batteryHealth = getBatteryHealth(buf);

    if (readFromFile(mHealthdConfig->batteryTechnologyPath, buf, SIZE) > 0)
        props.batteryTechnology = String8(buf);

    unsigned int i;

    for (i = 0; i < mChargerNames.size(); i++) {
        String8 path;
        path.appendFormat("%s/%s/online", POWER_SUPPLY_SYSFS_PATH,
                          mChargerNames[i].string());

        if (readFromFile(path, buf, SIZE) > 0) {
            if (buf[0] != '0') {
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
            }
        }
    }

    logthis = !healthd_board_battery_update(&props);

    if (logthis) {
        char dmesgline[256];

        if (props.batteryPresent) {
            snprintf(dmesgline, sizeof(dmesgline),
                 "battery l=%d v=%d t=%s%d.%d h=%d st=%d",
                 props.batteryLevel, props.batteryVoltage,
                 props.batteryTemperature < 0 ? "-" : "",
                 abs(props.batteryTemperature / 10),
                 abs(props.batteryTemperature % 10), props.batteryHealth,
                 props.batteryStatus);

            if (props.batteryPresent_smb) {
                snprintf(dmesgline, sizeof(dmesgline),
                     "battery l2=%d st2=%d ext=%d",
                     props.batteryLevel_smb, 
                     props.batteryStatus_smb,
                     props.batteryPresent_smb);
            }

            if (!mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
                int c = getIntField(mHealthdConfig->batteryCurrentNowPath);
                char b[20];

                snprintf(b, sizeof(b), " c=%d", c / 1000);
                strlcat(dmesgline, b, sizeof(dmesgline));
            }
        } else {
            snprintf(dmesgline, sizeof(dmesgline),
                 "battery none");
        }

        KLOG_INFO(LOG_TAG, "%s chg=%s%s%s\n", dmesgline,
                  props.chargerAcOnline ? "a" : "",
                  props.chargerUsbOnline ? "u" : "",
                  props.chargerWirelessOnline ? "w" : "");
    }
    cmd_send();
    healthd_mode_ops->battery_update(&props);
    return props.chargerAcOnline | props.chargerUsbOnline |
            props.chargerWirelessOnline;
}

status_t BatteryMonitor::getProperty(int id, struct BatteryProperty *val) {
    status_t ret = BAD_VALUE;

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

    default:
        break;
    }

    return ret;
}

void BatteryMonitor::dumpState(int fd) {
    int v;
    char vs[128];

    snprintf(vs, sizeof(vs), "ac: %d usb: %d wireless: %d\n",
             props.chargerAcOnline, props.chargerUsbOnline,
             props.chargerWirelessOnline);
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
}

void BatteryMonitor::init(struct healthd_config *hc) {
    String8 path;
    char pval[PROPERTY_VALUE_MAX];

    mHealthdConfig = hc;
    DIR* dir = opendir(POWER_SUPPLY_SYSFS_PATH);
    if (dir == NULL) {
        KLOG_ERROR(LOG_TAG, "Could not open %s\n", POWER_SUPPLY_SYSFS_PATH);
    } else {
        struct dirent* entry;

        while ((entry = readdir(dir))) {
            const char* name = entry->d_name;

            if (!strcmp(name, ".") || !strcmp(name, ".."))
                continue;

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

                if (mHealthdConfig->batteryCurrentNowPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/current_now",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCurrentNowPath = path;
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

                if (mHealthdConfig->batteryStatusPath_smb.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/status_smb", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryStatusPath_smb = path;
                }

                if (mHealthdConfig->batteryPresentPath_smb.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/present_smb", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryPresentPath_smb = path;
                }

                if (mHealthdConfig->batteryCapacityPath_smb.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/capacity_smb", POWER_SUPPLY_SYSFS_PATH,
                                      name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryCapacityPath_smb = path;
                }

                if (mHealthdConfig->batteryAdjustPowerPath.isEmpty()) {
                    path.clear();
                    path.appendFormat("%s/%s/adjust_power",
                                      POWER_SUPPLY_SYSFS_PATH, name);
                    if (access(path, R_OK) == 0)
                        mHealthdConfig->batteryAdjustPowerPath = path;
                }
                break;

            case ANDROID_POWER_SUPPLY_TYPE_UNKNOWN:
                break;
            }
        }
        closedir(dir);
    }

    if (!mChargerNames.size())
        KLOG_ERROR(LOG_TAG, "No charger supplies found\n");
    if (!mBatteryDevicePresent) {
        KLOG_WARNING(LOG_TAG, "No battery devices found\n");
        hc->periodic_chores_interval_fast = -1;
        hc->periodic_chores_interval_slow = -1;
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
        if (mHealthdConfig->batteryPresentPath_smb.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryPresentPath_smb not found\n");
        if (mHealthdConfig->batteryCapacityPath_smb.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryCapacityPath_smb not found\n");
        if (mHealthdConfig->batteryStatusPath_smb.isEmpty())
            KLOG_WARNING(LOG_TAG, "BatteryStatusPath_smb not found\n");
    }

    if (property_get("ro.boot.fake_battery", pval, NULL) > 0
                                               && strtol(pval, NULL, 10) != 0) {
        mBatteryFixedCapacity = FAKE_BATTERY_CAPACITY;
        mBatteryFixedCapacity_smb = FAKE_BATTERY_CAPACITY_SMB;
        mBatteryFixedTemperature = FAKE_BATTERY_TEMPERATURE;
    }
}

void BatteryMonitor::update_smb(void) {
    const int SIZE = 128;
    char buf[SIZE];

    props.batteryStatus_smb = BATTERY_STATUS_UNKNOWN;

    if (!mHealthdConfig->batteryPresentPath_smb.isEmpty())
        props.batteryPresent_smb = getBooleanField(mHealthdConfig->batteryPresentPath_smb);
    else
        props.batteryPresent_smb = false;

    props.batteryLevel_smb = mBatteryFixedCapacity_smb ?
        mBatteryFixedCapacity_smb :
        getIntField(mHealthdConfig->batteryCapacityPath_smb);

    if (readFromFile(mHealthdConfig->batteryStatusPath_smb, buf, SIZE) > 0)
        props.batteryStatus_smb = getBatteryStatus(buf);  
}

static int connect_socket() {
    int fd = socket_local_client(BATTERY_SOCKET_NAME,
                  ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    
    if(fd < 0) {
        KLOG_ERROR(LOG_TAG, "Fail to connect to socket rild-ocm. return code: %d", fd);
        return -1;
    }

    return fd;
}
static int send_data(int fd, int arg_count, uint32_t data_length, const void *data) {
    
    int ret = 0;
    //Use "rild-oem" communication protocol, you must send data as following rules:
    //First, send the argument count
    //Second, the data length of following data
    //Third, the data by char* format
    //That is, arg. counts(=n)->length of arg[0]->arg[0]->length of arg[1]->arg[1]->...->length of arg[n]->arg[n]
    
    //(send-1)send argCount
    KLOG_INFO(LOG_TAG,"(send-1). arg count: %d", arg_count);
    if(send(fd, (const void*)&arg_count, sizeof(int), 0) != sizeof(int)) {
        ret = -1;
        goto error;    
    }
    
    //(send-2)send data length
    KLOG_INFO(LOG_TAG, "(send-2). data length: %d", data_length);
    if(send(fd, (const void*)&data_length, sizeof(int), 0) != sizeof(int)) {
        ret = -1;
        goto error;  
    }     
    
    //(send-3)send SIM Lock Blob data
    //The operation format is "COMMAND,SIM_ID,[DATA]"
    //COMMAND:
    //        SIMMELOCK_SET      indicates to set sim status
    //        SIMMELOCK_GETKEY   indicates to get key
    //SIM:
    //        0                  sim slot 1
    //        1                  sim slot 2
    //DATA:   
    //        SIM Lock Blob      in case of the COMMAND is SIMMELOCK_SET
    //                           DATA is SIM Lock Blob in hexadecimal format. 
    //                           For example, "3A01FB69520B92104C6A" represents a 10 byte data 3A01FB69520B92104C6A.
    
    //sprintf(strData, "SIMMELOCK_SET,1,%s", data);
    //sprintf(data, "SIMMELOCK_SET,1,3A01FB69520B92104C6A");
    KLOG_INFO(LOG_TAG, "(send-3). data: %s", (char *)data);
    if(send(fd, (const void*)data, data_length, 0) != (int)data_length) {
        ret = -1;
        goto error;
    } 

error:
    KLOG_INFO(LOG_TAG, "[send_data] Ret:%d.", ret);
    return ret;
}

int disconnect_socket(int fd) {
    if(fd < 0) {
        KLOG_ERROR(LOG_TAG, "[disconnect_socket] Invalid fd: %d", fd);
        return -1;
    }
    
    return close(fd);     
}

static int send_to_ril(int adjustPower) {
    int ret = 0;    
    int command_len = strlen("CHARGING_STOP")+ 5;
    
    char *command = NULL;

    int fd = connect_socket();

    if (fd < 0) {
        ret = -1;
        goto error;
    }

    command_len = command_len + 1;
    command = (char *)malloc(sizeof(char) * command_len);
    memset(command, 0, sizeof(char) * command_len);

    if (adjustPower!=-1 && adjustPower != previous_adjust_power) {
        sprintf(command, "CHARGING_STOP,%d", adjustPower);
    } else {
        sprintf(command, "CHARGING_STOP");
    }
    
    ret = send_data(fd, 1, command_len, command);

error:
    if (command != NULL) {
        free(command);
    }
    if (fd >= 0) {
        disconnect_socket(fd);
    }
    return ret;
}

void BatteryMonitor::cmd_send(void) {
    static bool send_already = false;
    props.adjustPower = -1;

    props.adjustPower = getIntField(mHealthdConfig->batteryAdjustPowerPath);
    if ( (props.chargerAcOnline | props.chargerUsbOnline | props.chargerWirelessOnline) 
    		&& ( ( props.batteryStatus == BATTERY_STATUS_CMD_DISCHARGING && send_already == false ) 
    			|| (props.adjustPower != -1 && previous_adjust_power != props.adjustPower) ) ) {
        send_already = true;
        send_to_ril(props.adjustPower);
        previous_adjust_power = props.adjustPower;
    }
    if ( props.batteryStatus != BATTERY_STATUS_CMD_DISCHARGING ) {
    	send_already = false;
    }
    KLOG_INFO(LOG_TAG,"send_already = %d\n", send_already);
}
}; // namespace android

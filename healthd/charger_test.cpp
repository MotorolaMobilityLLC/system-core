/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "charger_test"
#include <android/log.h>

#include <chrono>
#include <condition_variable>
#include <fstream>
#include <iostream>
#include <mutex>
#include <streambuf>
#include <string>
#include <thread>
#include <vector>

#include <healthd/healthd.h>

#define LOG_THIS(fmt, ...)     \
    ALOGE(fmt, ##__VA_ARGS__); \
    printf(fmt "\n", ##__VA_ARGS__);

template <typename T>
class Atomic {
  public:
    Atomic(T&& init) : mValue(std::move(init)) {}
    void set(T&& newVal) {
        {
            std::lock_guard<std::mutex> lock(mMutex);
            mValue = std::move(newVal);
        }
        mChanged.notify_all();
    }
    bool waitFor(long ms, const T& expectVal) {
        std::unique_lock<std::mutex> lock(mMutex);
        return mChanged.wait_for(lock, std::chrono::milliseconds(ms),
                                 [this, &expectVal] { return mValue == expectVal; });
    }
  private:
    std::mutex mMutex;
    std::condition_variable mChanged;
    T mValue;
};

Atomic<bool>& getUpdateNotifier() {
    static Atomic<bool> val(false);
    return val;
}

int energyCounter(int64_t* counter) {
    *counter = 0xEC12345;
    return 0;
}

const char* createFile(const char* path, const char* content) {
    std::ofstream stream(path);
    if (!stream.is_open()) {
        LOG_THIS("Cannot create file %s", path);
        return NULL;
    }
    stream << content << std::endl;
    stream.close();
    return path;
}

std::string openToString(const char* path) {
    std::ifstream stream(path);
    if (!stream.is_open()) {
        LOG_THIS("Cannot open file %s", path);
        return "";
    }
    return std::string(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
}

int expectContains(const std::string& content, const std::vector<std::string>& fields) {
    int status = 0;
    for (const auto& field : fields) {
        auto pos = content.find(field);
        if (pos == std::string::npos) {
            LOG_THIS("Cannot find substr '%s'", field.c_str());
            status = 1;
        }
    }
    return status;
}

void healthd_board_init(struct healthd_config* config) {
    config->periodic_chores_interval_fast = 60;
    config->periodic_chores_interval_slow = 600;

    config->batteryStatusPath = createFile("/data/local/tmp/batteryStatus", "Not charging");
    config->batteryHealthPath = createFile("/data/local/tmp/batteryHealth", "Unspecified failure");
    config->batteryPresentPath = createFile("/data/local/tmp/batteryPresent", "1");
    config->batteryCapacityPath = createFile("/data/local/tmp/batteryCapacity", "47");
    config->batteryVoltagePath = createFile("/data/local/tmp/batteryVoltage", "45000");
    config->batteryTemperaturePath = createFile("/data/local/tmp/batteryTemperature", "987");
    config->batteryTechnologyPath = createFile("/data/local/tmp/batteryTechnology", "NiCd");
    config->batteryCurrentNowPath = createFile("/data/local/tmp/batteryCurrentNow", "99000");
    config->batteryCurrentAvgPath = createFile("/data/local/tmp/batteryCurrentAvg", "98000");
    config->batteryChargeCounterPath = createFile("/data/local/tmp/batteryChargeCounter", "600");
    config->batteryFullChargePath = createFile("/data/local/tmp/batteryFullCharge", "3515547");
    config->batteryCycleCountPath = createFile("/data/local/tmp/batteryCycleCount", "77");

    config->energyCounter = energyCounter;
    config->boot_min_cap = 50;
    config->screen_on = NULL;
}

int healthd_board_battery_update(struct android::BatteryProperties*) {
    getUpdateNotifier().set(true /* updated */);

    // return 0 to log periodic polled battery status to kernel log
    return 0;
}

extern int healthd_charger_main(int argc, char** argv);

int main(int argc, char** argv) {
    const char* dumpFile = "/data/local/tmp/dump.txt";

    std::thread bgThread([=] {
        healthd_charger_main(argc, argv);
    });

    // wait for healthd_init to finish
    if (!getUpdateNotifier().waitFor(1000 /* wait ms */, true /* updated */)) {
        LOG_THIS("Time out.");
        exit(1);
    }

    int fd = creat(dumpFile, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        exit(errno);
    }
    healthd_dump_battery_state(fd);
    close(fd);

    std::string content = openToString(dumpFile);
    int status = expectContains(content, {
        "status: 4",
        "health: 6",
        "present: 1",
        "level: 47",
        "voltage: 45",
        "temp: 987",
        "current now: 99000",
        "current avg: 98000",
        "charge counter: 600",
        "current now: 99",
        "cycle count: 77",
        "Full charge: 3515547"
    });

    if (status == 0) {
        LOG_THIS("Test success.");
    } else {
        LOG_THIS("Actual dump:\n%s", content.c_str());
    }

    exit(status);  // force bgThread to exit
}

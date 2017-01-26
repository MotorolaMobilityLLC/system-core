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

#include <android-base/logging.h>
#include "usb.h"

static bool should_use_libusb() {
    static bool enable = getenv("ADB_LIBUSB") && strcmp(getenv("ADB_LIBUSB"), "1") == 0;
    return enable;
}

void usb_init() {
    if (should_use_libusb()) {
        LOG(INFO) << "using libusb backend";
        libusb::usb_init();
    } else {
        LOG(INFO) << "using native backend";
        native::usb_init();
    }
}

int usb_write(usb_handle* h, const void* data, int len) {
    return should_use_libusb()
               ? libusb::usb_write(reinterpret_cast<libusb::usb_handle*>(h), data, len)
               : native::usb_write(reinterpret_cast<native::usb_handle*>(h), data, len);
}

int usb_read(usb_handle* h, void* data, int len) {
    return should_use_libusb()
               ? libusb::usb_read(reinterpret_cast<libusb::usb_handle*>(h), data, len)
               : native::usb_read(reinterpret_cast<native::usb_handle*>(h), data, len);
}

int usb_close(usb_handle* h) {
    return should_use_libusb() ? libusb::usb_close(reinterpret_cast<libusb::usb_handle*>(h))
                               : native::usb_close(reinterpret_cast<native::usb_handle*>(h));
}

void usb_kick(usb_handle* h) {
    should_use_libusb() ? libusb::usb_kick(reinterpret_cast<libusb::usb_handle*>(h))
                        : native::usb_kick(reinterpret_cast<native::usb_handle*>(h));
}

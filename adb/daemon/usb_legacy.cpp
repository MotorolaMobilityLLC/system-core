/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG USB

#include "sysdeps.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <android-base/logging.h>
#include <android-base/properties.h>

#include "adb.h"
#include "adbd/usb.h"
#include "transport.h"

using namespace std::chrono_literals;

#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

#define USB_FFS_BULK_SIZE 16384

// Number of buffers needed to fit MAX_PAYLOAD, with an extra for ZLPs.
#define USB_FFS_NUM_BUFS ((4 * MAX_PAYLOAD / USB_FFS_BULK_SIZE) + 1)

static unique_fd& dummy_fd = *new unique_fd();

static void aio_block_init(aio_block* aiob, unsigned num_bufs) {
    aiob->iocb.resize(num_bufs);
    aiob->iocbs.resize(num_bufs);
    aiob->events.resize(num_bufs);
    aiob->num_submitted = 0;
    for (unsigned i = 0; i < num_bufs; i++) {
        aiob->iocbs[i] = &aiob->iocb[i];
    }
    memset(&aiob->ctx, 0, sizeof(aiob->ctx));
    if (io_setup(num_bufs, &aiob->ctx)) {
        D("[ aio: got error on io_setup (%d) ]", errno);
    }
}

static int getMaxPacketSize(int ffs_fd) {
    usb_endpoint_descriptor desc;
    if (ioctl(ffs_fd, FUNCTIONFS_ENDPOINT_DESC, reinterpret_cast<unsigned long>(&desc))) {
        D("[ could not get endpoint descriptor! (%d) ]", errno);
        return MAX_PACKET_SIZE_HS;
    } else {
        return desc.wMaxPacketSize;
    }
}

static bool init_functionfs(struct usb_handle* h) {
    LOG(INFO) << "initializing functionfs";
    if (!open_functionfs(&h->control, &h->bulk_out, &h->bulk_in)) {
        return false;
    }

    h->read_aiob.fd = h->bulk_out.get();
    h->write_aiob.fd = h->bulk_in.get();
    h->reads_zero_packets = true;
    return true;
}

static void usb_legacy_ffs_open_thread(usb_handle* usb) {
    adb_thread_setname("usb legacy ffs open");

    while (true) {
        // wait until the USB device needs opening
        std::unique_lock<std::mutex> lock(usb->lock);
        while (!usb->open_new_connection) {
            usb->notify.wait(lock);
        }
        usb->open_new_connection = false;
        lock.unlock();

        while (true) {
            if (init_functionfs(usb)) {
                LOG(INFO) << "functionfs successfully initialized";
                break;
            }
            std::this_thread::sleep_for(1s);
        }

        LOG(INFO) << "registering usb transport";
        register_usb_transport(usb, nullptr, nullptr, 1);
    }

    // never gets here
    abort();
}

static int usb_ffs_write(usb_handle* h, const void* data, int len) {
    D("about to write (fd=%d, len=%d)", h->bulk_in.get(), len);

    const char* buf = static_cast<const char*>(data);
    int orig_len = len;
    while (len > 0) {
        int write_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = adb_write(h->bulk_in, buf, write_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_in.get(), n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
    }

    D("[ done fd=%d ]", h->bulk_in.get());
    return orig_len;
}

static int usb_ffs_read(usb_handle* h, void* data, int len) {
    D("about to read (fd=%d, len=%d)", h->bulk_out.get(), len);

    char* buf = static_cast<char*>(data);
    int orig_len = len;
    while (len > 0) {
        int read_len = std::min(USB_FFS_BULK_SIZE, len);
        int n = adb_read(h->bulk_out, buf, read_len);
        if (n < 0) {
            D("ERROR: fd = %d, n = %d: %s", h->bulk_out.get(), n, strerror(errno));
            return -1;
        }
        buf += n;
        len -= n;
    }

    D("[ done fd=%d ]", h->bulk_out.get());
    return orig_len;
}

static int usb_ffs_do_aio(usb_handle* h, const void* data, int len, bool read) {
    aio_block* aiob = read ? &h->read_aiob : &h->write_aiob;
    bool zero_packet = false;

    int num_bufs = len / h->io_size + (len % h->io_size == 0 ? 0 : 1);
    const char* cur_data = reinterpret_cast<const char*>(data);
    int packet_size = getMaxPacketSize(aiob->fd);

    if (posix_madvise(const_cast<void*>(data), len, POSIX_MADV_SEQUENTIAL | POSIX_MADV_WILLNEED) <
        0) {
        D("[ Failed to madvise: %d ]", errno);
    }

    for (int i = 0; i < num_bufs; i++) {
        int buf_len = std::min(len, static_cast<int>(h->io_size));
        io_prep(&aiob->iocb[i], aiob->fd, cur_data, buf_len, 0, read);

        len -= buf_len;
        cur_data += buf_len;

        if (len == 0 && buf_len % packet_size == 0 && read) {
            // adb does not expect the device to send a zero packet after data transfer,
            // but the host *does* send a zero packet for the device to read.
            zero_packet = h->reads_zero_packets;
        }
    }
    if (zero_packet) {
        io_prep(&aiob->iocb[num_bufs], aiob->fd, reinterpret_cast<const void*>(cur_data),
                packet_size, 0, read);
        num_bufs += 1;
    }

    while (true) {
        if (TEMP_FAILURE_RETRY(io_submit(aiob->ctx, num_bufs, aiob->iocbs.data())) < num_bufs) {
            PLOG(ERROR) << "aio: got error submitting " << (read ? "read" : "write");
            return -1;
        }
        if (TEMP_FAILURE_RETRY(io_getevents(aiob->ctx, num_bufs, num_bufs, aiob->events.data(),
                                            nullptr)) < num_bufs) {
            PLOG(ERROR) << "aio: got error waiting " << (read ? "read" : "write");
            return -1;
        }
        if (num_bufs == 1 && aiob->events[0].res == -EINTR) {
            continue;
        }
        int ret = 0;
        for (int i = 0; i < num_bufs; i++) {
            if (aiob->events[i].res < 0) {
                errno = -aiob->events[i].res;
                PLOG(ERROR) << "aio: got error event on " << (read ? "read" : "write")
                            << " total bufs " << num_bufs;
                return -1;
            }
            ret += aiob->events[i].res;
        }
        return ret;
    }
}

static int usb_ffs_aio_read(usb_handle* h, void* data, int len) {
    return usb_ffs_do_aio(h, data, len, true);
}

static int usb_ffs_aio_write(usb_handle* h, const void* data, int len) {
    return usb_ffs_do_aio(h, data, len, false);
}

static void usb_ffs_kick(usb_handle* h) {
    int err;

    err = ioctl(h->bulk_in.get(), FUNCTIONFS_CLEAR_HALT);
    if (err < 0) {
        D("[ kick: source (fd=%d) clear halt failed (%d) ]", h->bulk_in.get(), errno);
    }

    err = ioctl(h->bulk_out.get(), FUNCTIONFS_CLEAR_HALT);
    if (err < 0) {
        D("[ kick: sink (fd=%d) clear halt failed (%d) ]", h->bulk_out.get(), errno);
    }

    // don't close ep0 here, since we may not need to reinitialize it with
    // the same descriptors again. if however ep1/ep2 fail to re-open in
    // init_functionfs, only then would we close and open ep0 again.
    // Ditto the comment in usb_adb_kick.
    h->kicked = true;
    TEMP_FAILURE_RETRY(dup2(dummy_fd.get(), h->bulk_out.get()));
    TEMP_FAILURE_RETRY(dup2(dummy_fd.get(), h->bulk_in.get()));
}

static void usb_ffs_close(usb_handle* h) {
    LOG(INFO) << "closing functionfs transport";

    h->kicked = false;
    h->bulk_out.reset();
    h->bulk_in.reset();

    // Notify usb_adb_open_thread to open a new connection.
    h->lock.lock();
    h->open_new_connection = true;
    h->lock.unlock();
    h->notify.notify_one();
}

usb_handle* create_usb_handle(unsigned num_bufs, unsigned io_size) {
    usb_handle* h = new usb_handle();

    if (android::base::GetBoolProperty("sys.usb.ffs.aio_compat", false)) {
        // Devices on older kernels (< 3.18) will not have aio support for ffs
        // unless backported. Fall back on the non-aio functions instead.
        h->write = usb_ffs_write;
        h->read = usb_ffs_read;
    } else {
        h->write = usb_ffs_aio_write;
        h->read = usb_ffs_aio_read;
        aio_block_init(&h->read_aiob, num_bufs);
        aio_block_init(&h->write_aiob, num_bufs);
    }
    h->io_size = io_size;
    h->kick = usb_ffs_kick;
    h->close = usb_ffs_close;
    return h;
}

void usb_init_legacy() {
    D("[ usb_init - using legacy FunctionFS ]");
    dummy_fd.reset(adb_open("/dev/null", O_WRONLY | O_CLOEXEC));
    CHECK_NE(-1, dummy_fd.get());

    std::thread(usb_legacy_ffs_open_thread, create_usb_handle(USB_FFS_NUM_BUFS, USB_FFS_BULK_SIZE))
            .detach();
}

int usb_write(usb_handle* h, const void* data, int len) {
    return h->write(h, data, len);
}

int usb_read(usb_handle* h, void* data, int len) {
    return h->read(h, data, len);
}

int usb_close(usb_handle* h) {
    h->close(h);
    return 0;
}

void usb_reset(usb_handle* h) {
    usb_close(h);
}

void usb_kick(usb_handle* h) {
    h->kick(h);
}

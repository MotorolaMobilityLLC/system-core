/*
 * Copyright (C) 2026 The Android Open Source Project
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

#define LOG_TAG "GsaAppLoader"

#include <BufferAllocator/BufferAllocator.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <algorithm>
#include <string>

using android::base::unique_fd;

struct gsa_ioc_load_app_req {
    uint64_t buf;
    uint32_t len;
};

#define GSA_IOC_MAGIC 'g'
#define GSA_IOC_LOAD_APP _IOW(GSA_IOC_MAGIC, 1, struct gsa_ioc_load_app_req)

constexpr const char kGsaDefaultDeviceName[] = "/dev/gsa0";

static std::string dev_name = kGsaDefaultDeviceName;

static const char* _sopts = "hD:";
static const struct option _lopts[] = {
        {"help", no_argument, 0, 'h'},
        {"dev", required_argument, 0, 'D'},
        {0, 0, 0, 0},
};

static const char* usage =
        "Usage: %s [options] package-file\n"
        "\n"
        "options:\n"
        "  -h, --help            prints this message and exit\n"
        "  -D, --dev name        GSA IOCTL device name\n"
        "\n";

static void print_usage_and_exit(const char* prog, int code) {
    fprintf(stderr, usage, prog);
    exit(code);
}

static void parse_options(int argc, char** argv) {
    int c;
    int oidx = 0;

    while (1) {
        c = getopt_long(argc, argv, _sopts, _lopts, &oidx);
        if (c == -1) {
            break; /* done */
        }

        switch (c) {
            case 'h':
                print_usage_and_exit(argv[0], EXIT_SUCCESS);
                break;

            case 'D':
                dev_name = optarg;
                break;

            default:
                print_usage_and_exit(argv[0], EXIT_FAILURE);
        }
    }
}

static int gsa_send_load_message(void* package, uint32_t package_size) {
    unique_fd ioc_fd(TEMP_FAILURE_RETRY(open(dev_name.c_str(), O_RDWR)));
    if (!ioc_fd.ok()) {
        PLOG(ERROR) << "Failed to open gsa ioc device " << dev_name;
        return -1;
    }

    struct gsa_ioc_load_app_req req = {
            .buf = reinterpret_cast<uint64_t>(package),
            .len = package_size,
    };

    int rc = ioctl(ioc_fd, GSA_IOC_LOAD_APP, &req);
    if (rc < 0) {
        PLOG(ERROR) << "Encountered an error sending ioctl";
    }

    return rc;
}

static int send_app_package(const char* package_file_name) {
    /* Read package to dma memory */
    long page_size = sysconf(_SC_PAGESIZE);
    struct stat st;

    unique_fd file_fd(TEMP_FAILURE_RETRY(open(package_file_name, O_RDONLY)));
    if (!file_fd.ok()) {
        PLOG(ERROR) << "Error opening file " << package_file_name;
        return -1;
    }

    int rc = fstat(file_fd, &st);
    if (rc < 0) {
        PLOG(ERROR) << "Error calling stat on file '" << package_file_name << "'";
        return -1;
    }

    if (st.st_size == 0) {
        LOG(ERROR) << "Zero length file '" << package_file_name << "'";
        return -1;
    }

    uint64_t file_size = st.st_size;
    if (file_size > UINT32_MAX) {
        LOG(ERROR) << "File too large: " << file_size;
        return -1;
    }

    /* The dmabuf size needs to be a multiple of the page size */
    uint64_t file_page_size = (file_size + page_size - 1) & ~(page_size - 1);

    BufferAllocator alloc;
    unique_fd dmabuf_fd(alloc.Alloc(kDmabufSystemHeapName, file_page_size));
    if (!dmabuf_fd.ok()) {
        LOG(ERROR) << "Error creating dmabuf for " << file_page_size
                   << " bytes: " << dmabuf_fd.get();
        return -1;
    }

    void* shm = mmap(0, file_page_size, PROT_READ | PROT_WRITE, MAP_SHARED, dmabuf_fd, 0);
    if (shm == MAP_FAILED) {
        PLOG(ERROR) << "Error mapping dmabuf";
        return -1;
    }

    if (!android::base::ReadFully(file_fd, shm, file_size)) {
        PLOG(ERROR) << "Error reading package file '" << package_file_name << "'";
        munmap(shm, file_page_size);
        return -1;
    }

    rc = gsa_send_load_message(shm, static_cast<uint32_t>(file_size));

    munmap(shm, file_page_size);

    return rc;
}

int main(int argc, char** argv) {
    parse_options(argc, argv);
    if (optind + 1 != argc) {
        print_usage_and_exit(argv[0], EXIT_FAILURE);
    }

    int rc = send_app_package(argv[optind]);
    return rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>
#include <getopt.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <bootimg.h>
#include <sparse/sparse.h>
#include <zipfile/zipfile.h>

#include "fastboot.h"
#include "fs.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))

char cur_product[FB_RESPONSE_SZ + 1];

void bootimg_set_cmdline(boot_img_hdr *h, const char *cmdline);

boot_img_hdr *mkbootimg(void *kernel, unsigned kernel_size, unsigned kernel_offset,
                        void *ramdisk, unsigned ramdisk_size, unsigned ramdisk_offset,
                        void *second, unsigned second_size, unsigned second_offset,
                        unsigned page_size, unsigned base, unsigned tags_offset,
                        unsigned *bootimg_size);

static usb_handle *usb = 0;
static const char *serial = 0;
static const char *product = 0;
static const char *cmdline = 0;
static int wipe_data = 0;
static unsigned short vendor_id = 0;
static int long_listing = 0;
static int64_t sparse_limit = -1;
static int64_t target_sparse_limit = -1;

unsigned page_size = 2048;
unsigned base_addr      = 0x10000000;
unsigned kernel_offset  = 0x00008000;
unsigned ramdisk_offset = 0x01000000;
unsigned second_offset  = 0x00f00000;
unsigned tags_offset    = 0x00000100;

enum fb_buffer_type {
    FB_BUFFER,
    FB_BUFFER_SPARSE,
};

struct fastboot_buffer {
    enum fb_buffer_type type;
    size_t sz;
    void *data;
};

static struct {
    char img_name[13];
    char sig_name[13];
    char part_name[9];
    bool is_optional;
} images[4] = {
    {"boot.img", "boot.sig", "boot", false},
    {"recovery.img", "recovery.sig", "recovery", true},
    {"system.img", "system.sig", "system", false},
    {"tos.img", "tos.sig", "tos", true},
};

void get_my_path(char *path);

char *find_item(const char *item, const char *product)
{
    char *dir;
    char *fn;
    char path[PATH_MAX + 128];

    if(!strcmp(item,"boot")) {
        fn = "boot.img";
    } else if(!strcmp(item,"recovery")) {
        fn = "recovery.img";
    } else if(!strcmp(item,"system")) {
        fn = "system.img";
    } else if(!strcmp(item,"tos")) {
        fn = "tos.img";
    } else if(!strcmp(item,"userdata")) {
        fn = "userdata.img";
    } else if(!strcmp(item,"cache")) {
        fn = "cache.img";
    } else if(!strcmp(item,"info")) {
        fn = "android-info.txt";
    } else {
        fprintf(stderr,"unknown partition '%s'\n", item);
        return 0;
    }

    if(product) {
        get_my_path(path);
        sprintf(path + strlen(path),
                "../../../target/product/%s/%s", product, fn);
        return strdup(path);
    }

    dir = getenv("ANDROID_PRODUCT_OUT");
    if((dir == 0) || (dir[0] == 0)) {
        die("neither -p product specified nor ANDROID_PRODUCT_OUT set");
        return 0;
    }

    sprintf(path, "%s/%s", dir, fn);
    return strdup(path);
}

static ssize_t file_size(int fd)
{
    struct stat st;
    int ret;

    ret = fstat(fd, &st);

    return ret ? -1 : st.st_size;
}

static void *load_fd(int fd, size_t *_sz)
{
    char *data = NULL;
    ssize_t sz = file_size(fd);
    int errno_tmp;

    if (sz < 0) {
        goto oops;
    }

    data = (char*) malloc(sz);
    if(data == 0) goto oops;

    if(read(fd, data, sz) != sz) goto oops;
    close(fd);

    if(_sz) *_sz = sz;
    return data;

oops:
    errno_tmp = errno;
    close(fd);
    if(data != 0) free(data);
    errno = errno_tmp;
    return 0;
}

static void *load_file(const char *fn, size_t *_sz)
{
    int fd;

    fd = open(fn, O_RDONLY | O_BINARY);
    if(fd < 0) return 0;

    return load_fd(fd, _sz);
}

int match_fastboot_with_serial(usb_ifc_info *info, const char *local_serial)
{
    if(!(vendor_id && (info->dev_vendor == vendor_id)) &&
       (info->dev_vendor != 0x18d1) &&  // Google
       (info->dev_vendor != 0x8087) &&  // Intel
       (info->dev_vendor != 0x0451) &&
       (info->dev_vendor != 0x0502) &&
       (info->dev_vendor != 0x0fce) &&  // Sony Ericsson
       (info->dev_vendor != 0x05c6) &&  // Qualcomm
       (info->dev_vendor != 0x22b8) &&  // Motorola
       (info->dev_vendor != 0x0955) &&  // Nvidia
       (info->dev_vendor != 0x413c) &&  // DELL
       (info->dev_vendor != 0x2314) &&  // INQ Mobile
       (info->dev_vendor != 0x0b05) &&  // Asus
       (info->dev_vendor != 0x0bb4))    // HTC
            return -1;
    if(info->ifc_class != 0xff) return -1;
    if(info->ifc_subclass != 0x42) return -1;
    if(info->ifc_protocol != 0x03) return -1;
    // require matching serial number or device path if requested
    // at the command line with the -s option.
    if (local_serial && (strcmp(local_serial, info->serial_number) != 0 &&
                   strcmp(local_serial, info->device_path) != 0)) return -1;
    return 0;
}

int match_fastboot(usb_ifc_info *info)
{
    return match_fastboot_with_serial(info, serial);
}

int list_devices_callback(usb_ifc_info *info)
{
    if (match_fastboot_with_serial(info, NULL) == 0) {
        char* serial = info->serial_number;
        if (!info->writable) {
            serial = "no permissions"; // like "adb devices"
        }
        if (!serial[0]) {
            serial = "????????????";
        }
        // output compatible with "adb devices"
        if (!long_listing) {
            printf("%s\tfastboot\n", serial);
        } else if (!info->device_path) {
            printf("%-22s fastboot\n", serial);
        } else {
            printf("%-22s fastboot %s\n", serial, info->device_path);
        }
    }

    return -1;
}

usb_handle *open_device(void)
{
    static usb_handle *usb = 0;
    int announce = 1;

    if(usb) return usb;

    for(;;) {
        usb = usb_open(match_fastboot);
        if(usb) return usb;
        if(announce) {
            announce = 0;
            fprintf(stderr,"< waiting for device >\n");
        }
        sleep(1);
    }
}

void list_devices(void) {
    // We don't actually open a USB device here,
    // just getting our callback called so we can
    // list all the connected devices.
    usb_open(list_devices_callback);
}

void usage(void)
{
    fprintf(stderr,
/*           1234567890123456789012345678901234567890123456789012345678901234567890123456 */
            "usage: fastboot [ <option> ] <command>\n"
            "\n"
            "commands:\n"
            "  update <filename>                        reflash device from update.zip\n"
            "  flashall                                 flash boot, system, and if found,\n"
            "                                           recovery, tos\n"
            "  flash <partition> [ <filename> ]         write a file to a flash partition\n"
            "  erase <partition>                        erase a flash partition\n"
            "  format[:[<fs type>][:[<size>]] <partition> format a flash partition.\n"
            "                                           Can override the fs type and/or\n"
            "                                           size the bootloader reports.\n"
            "  getvar <variable>                        display a bootloader variable\n"
            "  boot <kernel> [ <ramdisk> ]              download and boot kernel\n"
            "  flash:raw boot <kernel> [ <ramdisk> ]    create bootimage and flash it\n"
            "  devices                                  list all connected devices\n"
            "  continue                                 continue with autoboot\n"
            "  reboot                                   reboot device normally\n"
            "  reboot-bootloader                        reboot device into bootloader\n"
            "  help                                     show this help message\n"
            "\n"
            "options:\n"
            "  -w                                       erase userdata and cache (and format\n"
            "                                           if supported by partition type)\n"
            "  -u                                       do not first erase partition before\n"
            "                                           formatting\n"
            "  -s <specific device>                     specify device serial number\n"
            "                                           or path to device port\n"
            "  -l                                       with \"devices\", lists device paths\n"
            "  -p <product>                             specify product name\n"
            "  -c <cmdline>                             override kernel commandline\n"
            "  -i <vendor id>                           specify a custom USB vendor id\n"
            "  -b <base_addr>                           specify a custom kernel base address.\n"
            "                                           default: 0x10000000\n"
            "  -n <page size>                           specify the nand page size.\n"
            "                                           default: 2048\n"
            "  -S <size>[K|M|G]                         automatically sparse files greater\n"
            "                                           than size.  0 to disable\n"
        );
}

void *load_bootable_image(const char *kernel, const char *ramdisk,
                          unsigned *sz, const char *cmdline)
{
    void *kdata = 0, *rdata = 0;
    unsigned ksize = 0, rsize = 0;
    void *bdata;
    unsigned bsize;

    if(kernel == 0) {
        fprintf(stderr, "no image specified\n");
        return 0;
    }

    kdata = load_file(kernel, &ksize);
    if(kdata == 0) {
        fprintf(stderr, "cannot load '%s': %s\n", kernel, strerror(errno));
        return 0;
    }

        /* is this actually a boot image? */
    if(!memcmp(kdata, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
        if(cmdline) bootimg_set_cmdline((boot_img_hdr*) kdata, cmdline);

        if(ramdisk) {
            fprintf(stderr, "cannot boot a boot.img *and* ramdisk\n");
            return 0;
        }

        *sz = ksize;
        return kdata;
    }

    if(ramdisk) {
        rdata = load_file(ramdisk, &rsize);
        if(rdata == 0) {
            fprintf(stderr,"cannot load '%s': %s\n", ramdisk, strerror(errno));
            return  0;
        }
    }

    fprintf(stderr,"creating boot image...\n");
    bdata = mkbootimg(kdata, ksize, kernel_offset,
                      rdata, rsize, ramdisk_offset,
                      0, 0, second_offset,
                      page_size, base_addr, tags_offset, &bsize);
    if(bdata == 0) {
        fprintf(stderr,"failed to create boot.img\n");
        return 0;
    }
    if(cmdline) bootimg_set_cmdline((boot_img_hdr*) bdata, cmdline);
    fprintf(stderr,"creating boot image - %d bytes\n", bsize);
    *sz = bsize;

    return bdata;
}

void *unzip_file(zipfile_t zip, const char *name, size_t *sz)
{
    void *data;
    zipentry_t entry = lookup_zipentry(zip, name);
    size_t zentrysz;
    size_t datasz;

    if (entry == NULL) {
        fprintf(stderr, "archive does not contain '%s'\n", name);
        return NULL;
    }

    zentrysz = get_zipentry_size(entry);

    datasz = zentrysz * 1.001;
    data = malloc(datasz);

    if(data == NULL) {
        fprintf(stderr, "failed to allocate %zu bytes\n", datasz);
        return NULL;
    }

    if (decompress_zipentry(entry, data, datasz)) {
        fprintf(stderr, "failed to unzip '%s' from archive\n", name);
        free(data);
        return NULL;
    }
    *sz = zentrysz;
    return data;
}

static int unzip_to_file(zipfile_t zip, char *name)
{
    int fd;
    char *data;
    size_t sz;

    fd = fileno(tmpfile());
    if (fd < 0) {
        return fd;
    }

    data = unzip_file(zip, name, &sz);
    if (data == NULL) {
        return -1;
    }

    if (write(fd, data, sz) != (ssize_t)sz) {
        fd = -1;
    } else {
        lseek(fd, 0, SEEK_SET);
    }

    free(data);
    return fd;
}

static char *strip(char *s)
{
    int n;
    while(*s && isspace(*s)) s++;
    n = strlen(s);
    while(n-- > 0) {
        if(!isspace(s[n])) break;
        s[n] = 0;
    }
    return s;
}

#define MAX_OPTIONS 32
static int setup_requirement_line(char *name)
{
    char *val[MAX_OPTIONS];
    const char **out;
    char *prod = NULL;
    unsigned n, count;
    char *x;
    int invert = 0;

    if (!strncmp(name, "reject ", 7)) {
        name += 7;
        invert = 1;
    } else if (!strncmp(name, "require ", 8)) {
        name += 8;
        invert = 0;
    } else if (!strncmp(name, "require-for-product:", 20)) {
        // Get the product and point name past it
        prod = name + 20;
        name = strchr(name, ' ');
        if (!name) return -1;
        *name = 0;
        name += 1;
        invert = 0;
    }

    x = strchr(name, '=');
    if (x == 0) return 0;
    *x = 0;
    val[0] = x + 1;

    for(count = 1; count < MAX_OPTIONS; count++) {
        x = strchr(val[count - 1],'|');
        if (x == 0) break;
        *x = 0;
        val[count] = x + 1;
    }

    name = strip(name);
    for(n = 0; n < count; n++) val[n] = strip(val[n]);

    name = strip(name);
    if (name == 0) return -1;

        /* work around an unfortunate name mismatch */
    if (!strcmp(name,"board")) name = "product";

    out = malloc(sizeof(char*) * count);
    if (out == 0) return -1;

    for(n = 0; n < count; n++) {
        out[n] = strdup(strip(val[n]));
        if (out[n] == 0) {
            for(size_t i = 0; i < n; ++i) {
                free((char*) out[i]);
            }
            free(out);
            return -1;
        }
    }

    fb_queue_require(prod, name, invert, n, out);
    return 0;
}

static void setup_requirements(char *data, size_t sz)
{
    char *s = data;

    while (sz-- > 0) {
        if(*s == '\n') {
            *s++ = 0;
            if (setup_requirement_line(data)) {
                die("out of memory");
            }
            data = s;
        } else {
            s++;
        }
    }
}

void queue_info_dump(void)
{
    fb_queue_notice("--------------------------------------------");
    fb_queue_display("version-bootloader", "Bootloader Version...");
    fb_queue_display("version-baseband",   "Baseband Version.....");
    fb_queue_display("serialno",           "Serial Number........");
    fb_queue_notice("--------------------------------------------");
}

static struct sparse_file **load_sparse_files(int fd, int max_size)
{
    struct sparse_file *s;
    int files;
    struct sparse_file **out_s;

    s = sparse_file_import_auto(fd, false);
    if (!s) {
        die("cannot sparse read file\n");
    }

    files = sparse_file_resparse(s, max_size, NULL, 0);
    if (files < 0) {
        die("Failed to resparse\n");
    }

    out_s = calloc(sizeof(struct sparse_file *), files + 1);
    if (!out_s) {
        die("Failed to allocate sparse file array\n");
    }

    files = sparse_file_resparse(s, max_size, out_s, files);
    if (files < 0) {
        die("Failed to resparse\n");
    }

    return out_s;
}

static int64_t get_target_sparse_limit(struct usb_handle *usb)
{
    int64_t limit = 0;
    char response[FB_RESPONSE_SZ + 1];
    int status = fb_getvar(usb, response, "max-download-size");

    if (!status) {
        limit = strtoul(response, NULL, 0);
        if (limit > 0) {
            fprintf(stderr, "target reported max download size of %lld bytes\n",
                    limit);
        }
    }

    return limit;
}

static int64_t get_sparse_limit(struct usb_handle *usb, int64_t size)
{
    int64_t limit;

    if (sparse_limit == 0) {
        return 0;
    } else if (sparse_limit > 0) {
        limit = sparse_limit;
    } else {
        if (target_sparse_limit == -1) {
            target_sparse_limit = get_target_sparse_limit(usb);
        }
        if (target_sparse_limit > 0) {
            limit = target_sparse_limit;
        } else {
            return 0;
        }
    }

    if (size > limit) {
        return limit;
    }

    return 0;
}

/* Until we get lazy inode table init working in make_ext4fs, we need to
 * erase partitions of type ext4 before flashing a filesystem so no stale
 * inodes are left lying around.  Otherwise, e2fsck gets very upset.
 */
static int needs_erase(const char *part)
{
    /* The function fb_format_supported() currently returns the value
     * we want, so just call it.
     */
     return fb_format_supported(usb, part, NULL);
}

static int load_buf_fd(usb_handle *usb, int fd,
        struct fastboot_buffer *buf)
{
    ssize_t f_size = file_size(fd);
    void *data = NULL;
    int64_t limit;
    int64_t sz64;

    if (f_size < 0) {
        return f_size;
    } else {
        sz64 = f_size;
    }

    lseek(fd, 0, SEEK_SET);
    limit = get_sparse_limit(usb, sz64);
    if (limit) {
        struct sparse_file **s = load_sparse_files(fd, limit);
        if (s == NULL) {
            return -1;
        }
        buf->type = FB_BUFFER_SPARSE;
        buf->data = s;
    } else {
        size_t sz;
        data = load_fd(fd, &sz);
        if (data == NULL) return -1;
        buf->type = FB_BUFFER;
        buf->sz = sz;
        buf->data = data;
    }

    return 0;
}

static int load_buf(usb_handle *usb, const char *fname,
        struct fastboot_buffer *buf)
{
    int fd;

    fd = open(fname, O_RDONLY | O_BINARY);
    if (fd < 0) {
        return -1;
    }

    return load_buf_fd(usb, fd, buf);
}

static void flash_buf(const char *pname, struct fastboot_buffer *buf)
{
    struct sparse_file **s;

    switch (buf->type) {
        case FB_BUFFER_SPARSE:
            s = buf->data;
            while (*s) {
                int64_t sz64 = sparse_file_len(*s, true, false);
                fb_queue_flash_sparse(pname, *s++, sz64);
            }
            break;
        case FB_BUFFER:
            fb_queue_flash(pname, buf->data, buf->sz);
            break;
        default:
            die("unknown buffer type: %d", buf->type);
    }
}

void do_flash(usb_handle *usb, const char *pname, const char *fname)
{
    struct fastboot_buffer buf;

    if (load_buf(usb, fname, &buf)) {
        die("cannot load '%s'", fname);
    }
    flash_buf(pname, &buf);
}

void do_update_signature(zipfile_t zip, char *fn)
{
    size_t sz;
    void *data = unzip_file(zip, fn, &sz);
    if (data == NULL) {
        die("can't unzip '%s'", fn);
    }
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

void do_update(usb_handle *usb, char *fn, int erase_first)
{
    void *zdata;
    unsigned zsize;
    void *data;
    size_t sz = 0;
    zipfile_t zip;
    int fd;
    int rc;
    struct fastboot_buffer buf;
    size_t i;

    queue_info_dump();

    fb_queue_query_save("product", cur_product, sizeof(cur_product));

    zdata = load_file(fn, &zsize);
    if (zdata == 0) die("failed to load '%s': %s", fn, strerror(errno));

    zip = init_zipfile(zdata, zsize);
    if(zip == 0) die("failed to access zipdata in '%s'");

    data = unzip_file(zip, "android-info.txt", &sz);
    if (data == NULL) {
        char *tmp;
            /* fallback for older zipfiles */
        data = unzip_file(zip, "android-product.txt", &sz);
        if ((data == NULL) || (sz < 1)) {
            die("update package has no android-info.txt or android-product.txt");
        }
        tmp = malloc(sz + 128);
        if (tmp == 0) die("out of memory");
        sprintf(tmp,"board=%sversion-baseband=0.66.04.19\n",(char*)data);
        data = tmp;
        sz = strlen(tmp);
    }

    setup_requirements(data, sz);

    for (i = 0; i < ARRAY_SIZE(images); i++) {
        fd = unzip_to_file(zip, images[i].img_name);
        if (fd < 0) {
            if (images[i].is_optional)
                continue;
            die("update package missing %s", images[i].img_name);
        }
        rc = load_buf_fd(usb, fd, &buf);
        if (rc) die("cannot load %s from flash", images[i].img_name);
        do_update_signature(zip, images[i].sig_name);
        if (erase_first && needs_erase(images[i].part_name)) {
            fb_queue_erase(images[i].part_name);
        }
        flash_buf(images[i].part_name, &buf);
        /* not closing the fd here since the sparse code keeps the fd around
         * but hasn't mmaped data yet. The tmpfile will get cleaned up when the
         * program exits.
         */
    }
}

void do_send_signature(char *fn)
{
    void *data;
    size_t sz;
    char *xtn;

    xtn = strrchr(fn, '.');
    if (!xtn) return;
    if (strcmp(xtn, ".img")) return;

    strcpy(xtn,".sig");
    data = load_file(fn, &sz);
    strcpy(xtn,".img");
    if (data == 0) return;
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

void do_flashall(usb_handle *usb, int erase_first)
{
    char *fname;
    void *data;
    size_t sz;
    struct fastboot_buffer buf;
    size_t i;

    queue_info_dump();

    fb_queue_query_save("product", cur_product, sizeof(cur_product));

    fname = find_item("info", product);
    if (fname == 0) die("cannot find android-info.txt");
    data = load_file(fname, &sz);
    if (data == 0) die("could not load android-info.txt: %s", strerror(errno));
    setup_requirements(data, sz);

    for (i = 0; i < ARRAY_SIZE(images); i++) {
        fname = find_item(images[i].part_name, product);
        if (load_buf(usb, fname, &buf)) {
            if (images[i].is_optional)
                continue;
            die("could not load %s\n", images[i].img_name);
        }
        do_send_signature(fname);
        if (erase_first && needs_erase(images[i].part_name)) {
            fb_queue_erase(images[i].part_name);
        }
        flash_buf(images[i].part_name, &buf);
    }
}

#define skip(n) do { argc -= (n); argv += (n); } while (0)
#define require(n) do { if (argc < (n)) {usage(); exit(1);}} while (0)

int do_oem_command(int argc, char **argv)
{
    int i;
    char command[256];
    if (argc <= 1) return 0;

    command[0] = 0;
    while(1) {
        strcat(command,*argv);
        skip(1);
        if(argc == 0) break;
        strcat(command," ");
    }

    fb_queue_command(command,"");
    return 0;
}

static int64_t parse_num(const char *arg)
{
    char *endptr;
    unsigned long long num;

    num = strtoull(arg, &endptr, 0);
    if (endptr == arg) {
        return -1;
    }

    if (*endptr == 'k' || *endptr == 'K') {
        if (num >= (-1ULL) / 1024) {
            return -1;
        }
        num *= 1024LL;
        endptr++;
    } else if (*endptr == 'm' || *endptr == 'M') {
        if (num >= (-1ULL) / (1024 * 1024)) {
            return -1;
        }
        num *= 1024LL * 1024LL;
        endptr++;
    } else if (*endptr == 'g' || *endptr == 'G') {
        if (num >= (-1ULL) / (1024 * 1024 * 1024)) {
            return -1;
        }
        num *= 1024LL * 1024LL * 1024LL;
        endptr++;
    }

    if (*endptr != '\0') {
        return -1;
    }

    if (num > INT64_MAX) {
        return -1;
    }

    return num;
}

void fb_perform_format(const char *partition, int skip_if_not_supported,
                       const char *type_override, const char *size_override)
{
    char pTypeBuff[FB_RESPONSE_SZ + 1], pSizeBuff[FB_RESPONSE_SZ + 1];
    char *pType = pTypeBuff;
    char *pSize = pSizeBuff;
    unsigned int limit = INT_MAX;
    struct fastboot_buffer buf;
    const char *errMsg = NULL;
    const struct fs_generator *gen;
    uint64_t pSz;
    int status;
    int fd;

    if (target_sparse_limit > 0 && target_sparse_limit < limit)
        limit = target_sparse_limit;
    if (sparse_limit > 0 && sparse_limit < limit)
        limit = sparse_limit;

    status = fb_getvar(usb, pType, "partition-type:%s", partition);
    if (status) {
        errMsg = "Can't determine partition type.\n";
        goto failed;
    }
    if (type_override) {
        if (strcmp(type_override, pType)) {
            fprintf(stderr,
                    "Warning: %s type is %s, but %s was requested for formating.\n",
                    partition, pType, type_override);
        }
        pType = type_override;
    }

    status = fb_getvar(usb, pSize, "partition-size:%s", partition);
    if (status) {
        errMsg = "Unable to get partition size\n";
        goto failed;
    }
    if (size_override) {
        if (strcmp(size_override, pSize)) {
            fprintf(stderr,
                    "Warning: %s size is %s, but %s was requested for formating.\n",
                    partition, pSize, size_override);
        }
        pSize = size_override;
    }

    gen = fs_get_generator(pType);
    if (!gen) {
        if (skip_if_not_supported) {
            fprintf(stderr, "Erase successful, but not automatically formatting.\n");
            fprintf(stderr, "File system type %s not supported.\n", pType);
            return;
        }
        fprintf(stderr, "Formatting is not supported for filesystem with type '%s'.\n", pType);
        return;
    }

    pSz = strtoll(pSize, (char **)NULL, 16);

    fd = fileno(tmpfile());
    if (fs_generator_generate(gen, fd, pSz)) {
        close(fd);
        fprintf(stderr, "Cannot generate image.\n");
        return;
    }

    if (load_buf_fd(usb, fd, &buf)) {
        fprintf(stderr, "Cannot read image.\n");
        close(fd);
        return;
    }
    flash_buf(partition, &buf);

    return;


failed:
    if (skip_if_not_supported) {
        fprintf(stderr, "Erase successful, but not automatically formatting.\n");
        if (errMsg)
            fprintf(stderr, "%s", errMsg);
    }
    fprintf(stderr,"FAILED (%s)\n", fb_get_error());
}

int main(int argc, char **argv)
{
    int wants_wipe = 0;
    int wants_reboot = 0;
    int wants_reboot_bootloader = 0;
    int erase_first = 1;
    void *data;
    size_t sz;
    int status;
    int c;
    int r;

    const struct option longopts[] = {
        {"base", required_argument, 0, 'b'},
        {"kernel_offset", required_argument, 0, 'k'},
        {"page_size", required_argument, 0, 'n'},
        {"ramdisk_offset", required_argument, 0, 'r'},
        {"tags_offset", required_argument, 0, 't'},
        {"help", 0, 0, 'h'},
        {0, 0, 0, 0}
    };

    serial = getenv("ANDROID_SERIAL");

    while (1) {
        int option_index = 0;
        c = getopt_long(argc, argv, "wub:k:n:r:t:s:S:lp:c:i:m:h", longopts, NULL);
        if (c < 0) {
            break;
        }
        /* Alphabetical cases */
        switch (c) {
        case 'b':
            base_addr = strtoul(optarg, 0, 16);
            break;
        case 'c':
            cmdline = optarg;
            break;
        case 'h':
            usage();
            return 1;
        case 'i': {
                char *endptr = NULL;
                unsigned long val;

                val = strtoul(optarg, &endptr, 0);
                if (!endptr || *endptr != '\0' || (val & ~0xffff))
                    die("invalid vendor id '%s'", optarg);
                vendor_id = (unsigned short)val;
                break;
            }
        case 'k':
            kernel_offset = strtoul(optarg, 0, 16);
            break;
        case 'l':
            long_listing = 1;
            break;
        case 'n':
            page_size = (unsigned)strtoul(optarg, NULL, 0);
            if (!page_size) die("invalid page size");
            break;
        case 'p':
            product = optarg;
            break;
        case 'r':
            ramdisk_offset = strtoul(optarg, 0, 16);
            break;
        case 't':
            tags_offset = strtoul(optarg, 0, 16);
            break;
        case 's':
            serial = optarg;
            break;
        case 'S':
            sparse_limit = parse_num(optarg);
            if (sparse_limit < 0) {
                    die("invalid sparse limit");
            }
            break;
        case 'u':
            erase_first = 0;
            break;
        case 'w':
            wants_wipe = 1;
            break;
        case '?':
            return 1;
        default:
            abort();
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0 && !wants_wipe) {
        usage();
        return 1;
    }

    if (argc > 0 && !strcmp(*argv, "devices")) {
        skip(1);
        list_devices();
        return 0;
    }

    if (argc > 0 && !strcmp(*argv, "help")) {
        usage();
        return 0;
    }

    usb = open_device();

    while (argc > 0) {
        if(!strcmp(*argv, "getvar")) {
            require(2);
            fb_queue_display(argv[1], argv[1]);
            skip(2);
        } else if(!strcmp(*argv, "erase")) {
            require(2);

            if (fb_format_supported(usb, argv[1], NULL)) {
                fprintf(stderr, "******** Did you mean to fastboot format this partition?\n");
            }

            fb_queue_erase(argv[1]);
            skip(2);
        } else if(!strncmp(*argv, "format", strlen("format"))) {
            char *overrides;
            char *type_override = NULL;
            char *size_override = NULL;
            require(2);
            /*
             * Parsing for: "format[:[type][:[size]]]"
             * Some valid things:
             *  - select ontly the size, and leave default fs type:
             *    format::0x4000000 userdata
             *  - default fs type and size:
             *    format userdata
             *    format:: userdata
             */
            overrides = strchr(*argv, ':');
            if (overrides) {
                overrides++;
                size_override = strchr(overrides, ':');
                if (size_override) {
                    size_override[0] = '\0';
                    size_override++;
                }
                type_override = overrides;
            }
            if (type_override && !type_override[0]) type_override = NULL;
            if (size_override && !size_override[0]) size_override = NULL;
            if (erase_first && needs_erase(argv[1])) {
                fb_queue_erase(argv[1]);
            }
            fb_perform_format(argv[1], 0, type_override, size_override);
            skip(2);
        } else if(!strcmp(*argv, "signature")) {
            require(2);
            data = load_file(argv[1], &sz);
            if (data == 0) die("could not load '%s': %s", argv[1], strerror(errno));
            if (sz != 256) die("signature must be 256 bytes");
            fb_queue_download("signature", data, sz);
            fb_queue_command("signature", "installing signature");
            skip(2);
        } else if(!strcmp(*argv, "reboot")) {
            wants_reboot = 1;
            skip(1);
        } else if(!strcmp(*argv, "reboot-bootloader")) {
            wants_reboot_bootloader = 1;
            skip(1);
        } else if (!strcmp(*argv, "continue")) {
            fb_queue_command("continue", "resuming boot");
            skip(1);
        } else if(!strcmp(*argv, "boot")) {
            char *kname = 0;
            char *rname = 0;
            skip(1);
            if (argc > 0) {
                kname = argv[0];
                skip(1);
            }
            if (argc > 0) {
                rname = argv[0];
                skip(1);
            }
            data = load_bootable_image(kname, rname, &sz, cmdline);
            if (data == 0) return 1;
            fb_queue_download("boot.img", data, sz);
            fb_queue_command("boot", "booting");
        } else if(!strcmp(*argv, "flash")) {
            char *pname = argv[1];
            char *fname = 0;
            require(2);
            if (argc > 2) {
                fname = argv[2];
                skip(3);
            } else {
                fname = find_item(pname, product);
                skip(2);
            }
            if (fname == 0) die("cannot determine image filename for '%s'", pname);
            if (erase_first && needs_erase(pname)) {
                fb_queue_erase(pname);
            }
            do_flash(usb, pname, fname);
        } else if(!strcmp(*argv, "flash:raw")) {
            char *pname = argv[1];
            char *kname = argv[2];
            char *rname = 0;
            require(3);
            if(argc > 3) {
                rname = argv[3];
                skip(4);
            } else {
                skip(3);
            }
            data = load_bootable_image(kname, rname, &sz, cmdline);
            if (data == 0) die("cannot load bootable image");
            fb_queue_flash(pname, data, sz);
        } else if(!strcmp(*argv, "flashall")) {
            skip(1);
            do_flashall(usb, erase_first);
            wants_reboot = 1;
        } else if(!strcmp(*argv, "update")) {
            if (argc > 1) {
                do_update(usb, argv[1], erase_first);
                skip(2);
            } else {
                do_update(usb, "update.zip", erase_first);
                skip(1);
            }
            wants_reboot = 1;
        } else if(!strcmp(*argv, "oem")) {
            argc = do_oem_command(argc, argv);
        } else {
            usage();
            return 1;
        }
    }

    if (wants_wipe) {
        fb_queue_erase("userdata");
        fb_perform_format("userdata", 1, NULL, NULL);
        fb_queue_erase("cache");
        fb_perform_format("cache", 1, NULL, NULL);
    }
    if (wants_reboot) {
        fb_queue_reboot();
    } else if (wants_reboot_bootloader) {
        fb_queue_command("reboot-bootloader", "rebooting into bootloader");
        fb_queue_wait_for_disconnect();
    }

    if (fb_queue_is_empty())
        return 0;

    status = fb_execute_queue(usb);
    return (status) ? 1 : 0;
}

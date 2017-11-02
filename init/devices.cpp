/*
 * Copyright (C) 2007-2014 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fts.h>

#include <linux/netlink.h>

#include <memory>
#include <thread>

#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/android.h>
#include <selinux/avc.h>

#include <private/android_filesystem_config.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cutils/list.h>
#include <cutils/uevent.h>

#include "devices.h"
#include "ueventd_parser.h"
#include "util.h"
#include "log.h"
#include "property_service.h"

#define SYSFS_PREFIX    "/sys"
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
static const char *firmware_dirs[] = { "/etc/firmware",
                                       "/vendor/firmware",
                                       "/firmware/image" };

extern struct selabel_handle *sehandle;

extern std::string boot_device;

static android::base::unique_fd device_fd;

struct perms_ {
    char *name;
    char *attr;
    mode_t perm;
    unsigned int uid;
    unsigned int gid;
    unsigned short prefix;
    unsigned short wildcard;
};

struct perm_node {
    struct perms_ dp;
    struct listnode plist;
};

struct platform_node {
    char *name;
    char *path;
    int path_len;
    struct listnode list;
};

static list_declare(sys_perms);
static list_declare(dev_perms);
static list_declare(platform_names);

int add_dev_perms(const char *name, const char *attr,
                  mode_t perm, unsigned int uid, unsigned int gid,
                  unsigned short prefix,
                  unsigned short wildcard) {
    struct perm_node *node = (perm_node*) calloc(1, sizeof(*node));
    if (!node)
        return -ENOMEM;

    node->dp.name = strdup(name);
    if (!node->dp.name) {
        free(node);
        return -ENOMEM;
    }

    if (attr) {
        node->dp.attr = strdup(attr);
        if (!node->dp.attr) {
            free(node->dp.name);
            free(node);
            return -ENOMEM;
        }
    }

    node->dp.perm = perm;
    node->dp.uid = uid;
    node->dp.gid = gid;
    node->dp.prefix = prefix;
    node->dp.wildcard = wildcard;

    if (attr)
        list_add_tail(&sys_perms, &node->plist);
    else
        list_add_tail(&dev_perms, &node->plist);

    return 0;
}

static bool perm_path_matches(const char *path, struct perms_ *dp)
{
    if (dp->prefix) {
        if (strncmp(path, dp->name, strlen(dp->name)) == 0)
            return true;
    } else if (dp->wildcard) {
        if (fnmatch(dp->name, path, FNM_PATHNAME) == 0)
            return true;
    } else {
        if (strcmp(path, dp->name) == 0)
            return true;
    }

    return false;
}

static bool match_subsystem(perms_* dp, const char* pattern,
                            const char* path, const char* subsystem) {
    if (!pattern || !subsystem || strstr(dp->name, subsystem) == NULL) {
        return false;
    }

    std::string subsys_path = android::base::StringPrintf(pattern, subsystem, basename(path));
    return perm_path_matches(subsys_path.c_str(), dp);
}

static void fixup_sys_perms(const char* upath, const char* subsystem) {
    // upaths omit the "/sys" that paths in this list
    // contain, so we prepend it...
    std::string path = std::string(SYSFS_PREFIX) + upath;

    listnode* node;
    list_for_each(node, &sys_perms) {
        struct stat s;
        perms_* dp = &(node_to_item(node, perm_node, plist))->dp;
        if (match_subsystem(dp, SYSFS_PREFIX "/class/%s/%s", path.c_str(), subsystem)) {
            ; // matched
        } else if (match_subsystem(dp, SYSFS_PREFIX "/bus/%s/devices/%s", path.c_str(), subsystem)) {
            ; // matched
        } else if (!perm_path_matches(path.c_str(), dp)) {
            continue;
        }

        if (strchr(dp->attr, '*') || strchr(dp->attr, '?')) {
            FTS *ftsp;
            FTSENT *entp;

            char * const dirs[] = { const_cast<char *>(path.c_str()), NULL };

            int fts_options = FTS_COMFOLLOW | FTS_LOGICAL | FTS_NOCHDIR | FTS_NOSTAT;
            if ((ftsp = fts_open(dirs, fts_options, NULL)) == NULL) {
                continue;
            }

            while ((entp = fts_read(ftsp)) != NULL) {
                switch (entp->fts_info) {
                case FTS_D:
                case FTS_F:
                    if (fnmatch(dp->attr, entp->fts_path + path.length() + 1, FNM_PATHNAME) == 0) {
                        if (stat(entp->fts_path, &s) == 0) {
                            if ((s.st_uid != dp->uid) || (s.st_gid != dp->gid)
                                || ((s.st_mode & 0xFFF) != dp->perm)) {
                                LOG(INFO) << "fixup " << entp->fts_path
                                          << " " << dp->uid << " " << dp->gid << " " << std::oct << dp->perm;
                                chown(entp->fts_path, dp->uid, dp->gid);
                                chmod(entp->fts_path, dp->perm);
                            }
                        }
                    }
                    break;
                default:
                    break;
                }
            }
            fts_close(ftsp);

        } else {
            std::string attr_file = path + "/" + dp->attr;

            if (stat(attr_file.c_str(), &s) == 0) {
                if ((s.st_uid != dp->uid) || (s.st_gid != dp->gid)
                    || ((s.st_mode & 0xFFF) != dp->perm)) {
                        LOG(INFO) << "fixup " << attr_file
                                  << " " << dp->uid << " " << dp->gid << " " << std::oct << dp->perm;
                        chown(attr_file.c_str(), dp->uid, dp->gid);
                        chmod(attr_file.c_str(), dp->perm);
               }
            }
        }
    }

    if (access(path.c_str(), F_OK) == 0) {
        LOG(VERBOSE) << "restorecon_recursive: " << path;
        restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE);
    }
}

static mode_t get_device_perm(const char *path, const char **links,
                unsigned *uid, unsigned *gid)
{
    struct listnode *node;
    struct perm_node *perm_node;
    struct perms_ *dp;

    /* search the perms list in reverse so that ueventd.$hardware can
     * override ueventd.rc
     */
    list_for_each_reverse(node, &dev_perms) {
        bool match = false;

        perm_node = node_to_item(node, struct perm_node, plist);
        dp = &perm_node->dp;

        if (perm_path_matches(path, dp)) {
            match = true;
        } else {
            if (links) {
                int i;
                for (i = 0; links[i]; i++) {
                    if (perm_path_matches(links[i], dp)) {
                        match = true;
                        break;
                    }
                }
            }
        }

        if (match) {
            *uid = dp->uid;
            *gid = dp->gid;
            return dp->perm;
        }
    }
    /* Default if nothing found. */
    *uid = 0;
    *gid = 0;
    return 0600;
}

static void make_device(const char *path,
                        const char */*upath*/,
                        int block, int major, int minor,
                        const char **links)
{
    unsigned uid;
    unsigned gid;
    mode_t mode;
    dev_t dev;
    char *secontext = NULL;

    mode = get_device_perm(path, links, &uid, &gid) | (block ? S_IFBLK : S_IFCHR);

    if (sehandle) {
        if (selabel_lookup_best_match(sehandle, &secontext, path, links, mode)) {
            PLOG(ERROR) << "Device '" << path << "' not created; cannot find SELinux label";
            return;
        }
        setfscreatecon(secontext);
    }

    dev = makedev(major, minor);
    /* Temporarily change egid to avoid race condition setting the gid of the
     * device node. Unforunately changing the euid would prevent creation of
     * some device nodes, so the uid has to be set with chown() and is still
     * racy. Fixing the gid race at least fixed the issue with system_server
     * opening dynamic input devices under the AID_INPUT gid. */
    if (setegid(gid)) {
        PLOG(ERROR) << "setegid(" << gid << ") for " << path << " device failed";
        goto out;
    }
    /* If the node already exists update its SELinux label to handle cases when
     * it was created with the wrong context during coldboot procedure. */
    if (mknod(path, mode, dev) && (errno == EEXIST) && secontext) {

        char* fcon = nullptr;
        int rc = lgetfilecon(path, &fcon);
        if (rc < 0) {
            PLOG(ERROR) << "Cannot get SELinux label on '" << path << "' device";
            goto out;
        }

        bool different = strcmp(fcon, secontext) != 0;
        freecon(fcon);

        if (different && lsetfilecon(path, secontext)) {
            PLOG(ERROR) << "Cannot set '" << secontext << "' SELinux label on '" << path << "' device";
        }
    }

out:
    chown(path, uid, -1);
    if (setegid(AID_ROOT)) {
        PLOG(FATAL) << "setegid(AID_ROOT) failed";
    }

    if (secontext) {
        freecon(secontext);
        setfscreatecon(NULL);
    }
}

static void add_platform_device(const char *path)
{
    int path_len = strlen(path);
    struct platform_node *bus;
    const char *name = path;

    if (!strncmp(path, "/devices/", 9)) {
        name += 9;
        if (!strncmp(name, "platform/", 9))
            name += 9;
    }

    LOG(VERBOSE) << "adding platform device " << name << " (" << path << ")";

    bus = (platform_node*) calloc(1, sizeof(struct platform_node));
    if (!bus)
        return;

    bus->path = strdup(path);
    bus->path_len = path_len;
    bus->name = bus->path + (name - path);
    list_add_tail(&platform_names, &bus->list);
}

/*
 * given a path that may start with a platform device, find the length of the
 * platform device prefix.  If it doesn't start with a platform device, return
 * 0.
 */
static struct platform_node *find_platform_device(const char *path)
{
    int path_len = strlen(path);
    struct listnode *node;
    struct platform_node *bus;

    list_for_each_reverse(node, &platform_names) {
        bus = node_to_item(node, struct platform_node, list);
        if ((bus->path_len < path_len) &&
                (path[bus->path_len] == '/') &&
                !strncmp(path, bus->path, bus->path_len))
            return bus;
    }

    return NULL;
}

static void remove_platform_device(const char *path)
{
    struct listnode *node;
    struct platform_node *bus;

    list_for_each_reverse(node, &platform_names) {
        bus = node_to_item(node, struct platform_node, list);
        if (!strcmp(path, bus->path)) {
            LOG(INFO) << "removing platform device " << bus->name;
            free(bus->path);
            list_remove(node);
            free(bus);
            return;
        }
    }
}

static void destroy_platform_devices() {
    struct listnode* node;
    struct listnode* n;
    struct platform_node* bus;

    list_for_each_safe(node, n, &platform_names) {
        list_remove(node);
        bus = node_to_item(node, struct platform_node, list);
        free(bus->path);
        free(bus);
    }
}

/* Given a path that may start with a PCI device, populate the supplied buffer
 * with the PCI domain/bus number and the peripheral ID and return 0.
 * If it doesn't start with a PCI device, or there is some error, return -1 */
static int find_pci_device_prefix(const char *path, char *buf, ssize_t buf_sz)
{
    const char *start, *end;

    if (strncmp(path, "/devices/pci", 12))
        return -1;

    /* Beginning of the prefix is the initial "pci" after "/devices/" */
    start = path + 9;

    /* End of the prefix is two path '/' later, capturing the domain/bus number
     * and the peripheral ID. Example: pci0000:00/0000:00:1f.2 */
    end = strchr(start, '/');
    if (!end)
        return -1;
    end = strchr(end + 1, '/');
    if (!end)
        return -1;

    /* Make sure we have enough room for the string plus null terminator */
    if (end - start + 1 > buf_sz)
        return -1;

    strncpy(buf, start, end - start);
    buf[end - start] = '\0';
    return 0;
}

/* Given a path that may start with a virtual block device, populate
 * the supplied buffer with the virtual block device ID and return 0.
 * If it doesn't start with a virtual block device, or there is some
 * error, return -1 */
static int find_vbd_device_prefix(const char *path, char *buf, ssize_t buf_sz)
{
    const char *start, *end;

    /* Beginning of the prefix is the initial "vbd-" after "/devices/" */
    if (strncmp(path, "/devices/vbd-", 13))
        return -1;

    /* End of the prefix is one path '/' later, capturing the
       virtual block device ID. Example: 768 */
    start = path + 13;
    end = strchr(start, '/');
    if (!end)
        return -1;

    /* Make sure we have enough room for the string plus null terminator */
    if (end - start + 1 > buf_sz)
        return -1;

    strncpy(buf, start, end - start);
    buf[end - start] = '\0';
    return 0;
}

static int find_bootdevice_prefix(const char *path, char *buf, ssize_t buf_sz)
{
    if (!boot_device.empty() && strstr(path, boot_device.c_str())) {
       strlcpy(buf, boot_device.c_str(), buf_sz);
       return 0;
    }
    return -1;
}

static void parse_event(const char *msg, struct uevent *uevent)
{
    uevent->action = "";
    uevent->path = "";
    uevent->subsystem = "";
    uevent->firmware = "";
    uevent->major = -1;
    uevent->minor = -1;
    uevent->partition_name = NULL;
    uevent->partition_num = -1;
    uevent->device_name = NULL;

        /* currently ignoring SEQNUM */
    while(*msg) {
        if(!strncmp(msg, "ACTION=", 7)) {
            msg += 7;
            uevent->action = msg;
        } else if(!strncmp(msg, "DEVPATH=", 8)) {
            msg += 8;
            uevent->path = msg;
        } else if(!strncmp(msg, "SUBSYSTEM=", 10)) {
            msg += 10;
            uevent->subsystem = msg;
        } else if(!strncmp(msg, "FIRMWARE=", 9)) {
            msg += 9;
            uevent->firmware = msg;
        } else if(!strncmp(msg, "MAJOR=", 6)) {
            msg += 6;
            uevent->major = atoi(msg);
        } else if(!strncmp(msg, "MINOR=", 6)) {
            msg += 6;
            uevent->minor = atoi(msg);
        } else if(!strncmp(msg, "PARTN=", 6)) {
            msg += 6;
            uevent->partition_num = atoi(msg);
        } else if(!strncmp(msg, "PARTNAME=", 9)) {
            msg += 9;
            uevent->partition_name = msg;
        } else if(!strncmp(msg, "DEVNAME=", 8)) {
            msg += 8;
            uevent->device_name = msg;
        }

        /* advance to after the next \0 */
        while(*msg++)
            ;
    }

    if (LOG_UEVENTS) {
        LOG(INFO) << android::base::StringPrintf("event { '%s', '%s', '%s', '%s', %d, %d }",
                                                 uevent->action, uevent->path, uevent->subsystem,
                                                 uevent->firmware, uevent->major, uevent->minor);
    }
}

static char **get_v4l_device_symlinks(struct uevent *uevent)
{
    char **links;
    int fd = -1;
    int nr;
    char link_name_path[256];
    char link_name[64];

    if (strncmp(uevent->path, "/devices/virtual/video4linux/video", 34))
        return NULL;

    links = (char**) malloc(sizeof(char *) * 2);
    if (!links)
        return NULL;
    memset(links, 0, sizeof(char *) * 2);

    snprintf(link_name_path, sizeof(link_name_path), "%s%s%s",
            SYSFS_PREFIX, uevent->path, "/link_name");
    fd = open(link_name_path, O_RDONLY);
    if (fd < 0)
        goto err;
    nr = read(fd, link_name, sizeof(link_name) - 1);
    close(fd);
    if (nr <= 0)
        goto err;
    link_name[nr] = '\0';
    if (asprintf(&links[0], "/dev/video/%s", link_name) <= 0)
        links[0] = NULL;

    return links;
err:
    free(links);
    return NULL;
}

static char **get_character_device_symlinks(struct uevent *uevent)
{
    const char *parent;
    const char *slash;
    char **links;
    int link_num = 0;
    int width;
    struct platform_node *pdev;

    pdev = find_platform_device(uevent->path);
    if (!pdev)
        return NULL;

    links = (char**) malloc(sizeof(char *) * 2);
    if (!links)
        return NULL;
    memset(links, 0, sizeof(char *) * 2);

    /* skip "/devices/platform/<driver>" */
    parent = strchr(uevent->path + pdev->path_len, '/');
    if (!parent)
        goto err;

    if (!strncmp(parent, "/usb", 4)) {
        /* skip root hub name and device. use device interface */
        while (*++parent && *parent != '/');
        if (*parent)
            while (*++parent && *parent != '/');
        if (!*parent)
            goto err;
        slash = strchr(++parent, '/');
        if (!slash)
            goto err;
        width = slash - parent;
        if (width <= 0)
            goto err;

        if (asprintf(&links[link_num], "/dev/usb/%s%.*s", uevent->subsystem, width, parent) > 0)
            link_num++;
        else
            links[link_num] = NULL;
        mkdir("/dev/usb", 0755);
    }
    else {
        goto err;
    }

    return links;
err:
    free(links);
    return NULL;
}

static void make_link_init(const char* oldpath, const char* newpath) {
  const char* slash = strrchr(newpath, '/');
  if (!slash) return;

  if (mkdir_recursive(dirname(newpath), 0755)) {
    PLOG(ERROR) << "Failed to create directory " << dirname(newpath);
  }

  if (symlink(oldpath, newpath) && errno != EEXIST) {
    PLOG(ERROR) << "Failed to symlink " << oldpath << " to " << newpath;
  }
}

char** get_block_device_symlinks(struct uevent* uevent) {
    const char *device;
    struct platform_node *pdev;
    const char *slash;
    const char *type;
    char buf[256];
    char link_path[256];
    int link_num = 0;
    char *p;
    static int is_bootdevice_linked = 0;

    pdev = find_platform_device(uevent->path);
    if (pdev) {
        device = pdev->name;
        type = "platform";
    } else if (!find_pci_device_prefix(uevent->path, buf, sizeof(buf))) {
        device = buf;
        type = "pci";
    } else if (!find_vbd_device_prefix(uevent->path, buf, sizeof(buf))) {
        device = buf;
        type = "vbd";
    } else if (!find_bootdevice_prefix(uevent->path, buf, sizeof(buf))) {
        device = buf;
        type = "platform";
    } else {
        return NULL;
    }

    char **links = (char**) malloc(sizeof(char *) * 6);
    if (!links)
        return NULL;
    memset(links, 0, sizeof(char *) * 6);

    LOG(VERBOSE) << "found " << type << " device " << device;

    snprintf(link_path, sizeof(link_path), "/dev/block/%s/%s", type, device);

    if (uevent->partition_name) {
        p = strdup(uevent->partition_name);
        sanitize(p);
        if (strcmp(uevent->partition_name, p)) {
            LOG(VERBOSE) << "Linking partition '" << uevent->partition_name << "' as '" << p << "'";
        }
        if (asprintf(&links[link_num], "%s/by-name/%s", link_path, p) > 0)
            link_num++;
        else
            links[link_num] = NULL;
        if (is_bootdevice_linked && !boot_device.empty() && strstr(device, boot_device.c_str())) {
            if (asprintf(&links[link_num], "/dev/block/bootdevice/by-name/%s", p) > 0)
                link_num++;
            else
                links[link_num] = NULL;
        }

        free(p);
    }

    if (uevent->partition_num >= 0) {
        if (asprintf(&links[link_num], "%s/by-num/p%d", link_path, uevent->partition_num) > 0)
            link_num++;
        else
            links[link_num] = NULL;

        if (is_bootdevice_linked && !boot_device.empty() && strstr(device, boot_device.c_str())) {
            if (asprintf(&links[link_num], "/dev/block/bootdevice/by-num/p%d", uevent->partition_num) > 0)
                link_num++;
            else
                links[link_num] = NULL;
        }
    }

    slash = strrchr(uevent->path, '/');
    if (asprintf(&links[link_num], "%s/%s", link_path, slash + 1) > 0)
        link_num++;
    else
        links[link_num] = NULL;

    if (pdev && !boot_device.empty() && strstr(device, boot_device.c_str())) {
        /* Create bootdevice symlink for platform boot stroage device */
        make_link_init(link_path, "/dev/block/bootdevice");
        is_bootdevice_linked = 1;
    }

    return links;
}

static void remove_link(const char* oldpath, const char* newpath) {
  std::string path;
  if (android::base::Readlink(newpath, &path) && path == oldpath) unlink(newpath);
}

static void handle_device(const char *action, const char *devpath,
        const char *path, int block, int major, int minor, char **links)
{
    if(!strcmp(action, "add")) {
        make_device(devpath, path, block, major, minor, (const char **)links);
        if (links) {
            for (int i = 0; links[i]; i++) {
                make_link_init(devpath, links[i]);
            }
        }
    }

    if(!strcmp(action, "remove")) {
        if (links) {
            for (int i = 0; links[i]; i++) {
                remove_link(devpath, links[i]);
            }
        }
        unlink(devpath);
    }

    if (links) {
        for (int i = 0; links[i]; i++) {
            free(links[i]);
        }
        free(links);
    }
}

static void handle_platform_device_event(struct uevent *uevent)
{
    const char *path = uevent->path;

    if (!strcmp(uevent->action, "add"))
        add_platform_device(path);
    else if (!strcmp(uevent->action, "remove"))
        remove_platform_device(path);
}

static const char *parse_device_name(struct uevent *uevent, unsigned int len)
{
    const char *name;

    /* if it's not a /dev device, nothing else to do */
    if((uevent->major < 0) || (uevent->minor < 0))
        return NULL;

    /* do we have a name? */
    name = strrchr(uevent->path, '/');
    if(!name)
        return NULL;
    name++;

    /* too-long names would overrun our buffer */
    if(strlen(name) > len) {
        LOG(ERROR) << "DEVPATH=" << name << " exceeds " << len << "-character limit on filename; ignoring event";
        return NULL;
    }

    return name;
}

#define DEVPATH_LEN 96
#define MAX_DEV_NAME 64

static void handle_block_device_event(struct uevent *uevent)
{
    const char *base = "/dev/block/";
    const char *name;
    char devpath[DEVPATH_LEN];
    char **links = NULL;

    name = parse_device_name(uevent, MAX_DEV_NAME);
    if (!name)
        return;

    snprintf(devpath, sizeof(devpath), "%s%s", base, name);
    make_dir(base, 0755);

    if (!strncmp(uevent->path, "/devices/", 9))
        links = get_block_device_symlinks(uevent);

    handle_device(uevent->action, devpath, uevent->path, 1,
            uevent->major, uevent->minor, links);
}

static bool assemble_devpath(char *devpath, const char *dirname,
        const char *devname)
{
    int s = snprintf(devpath, DEVPATH_LEN, "%s/%s", dirname, devname);
    if (s < 0) {
        PLOG(ERROR) << "failed to assemble device path; ignoring event";
        return false;
    } else if (s >= DEVPATH_LEN) {
        LOG(ERROR) << dirname << "/" << devname
                   << " exceeds " << DEVPATH_LEN << "-character limit on path; ignoring event";
        return false;
    }
    return true;
}

static void mkdir_recursive_for_devpath(const char *devpath)
{
    char dir[DEVPATH_LEN];
    char *slash;

    strcpy(dir, devpath);
    slash = strrchr(dir, '/');
    *slash = '\0';
    mkdir_recursive(dir, 0755);
}

static void handle_generic_device_event(struct uevent *uevent)
{
    const char *base;
    const char *name;
    char devpath[DEVPATH_LEN] = {0};
    char **links = NULL;

    name = parse_device_name(uevent, MAX_DEV_NAME);
    if (!name)
        return;

    struct ueventd_subsystem *subsystem =
            ueventd_subsystem_find_by_name(uevent->subsystem);

    if (subsystem) {
        const char *devname;

        switch (subsystem->devname_src) {
        case DEVNAME_UEVENT_DEVNAME:
            devname = uevent->device_name;
            break;

        case DEVNAME_UEVENT_DEVPATH:
            devname = name;
            break;

        default:
            LOG(ERROR) << uevent->subsystem << " subsystem's devpath option is not set; ignoring event";
            return;
        }

        if (!assemble_devpath(devpath, subsystem->dirname, devname))
            return;
        mkdir_recursive_for_devpath(devpath);
    } else if (!strncmp(uevent->subsystem, "usb", 3)) {
         if (!strcmp(uevent->subsystem, "usb")) {
            if (uevent->device_name) {
                if (!assemble_devpath(devpath, "/dev", uevent->device_name))
                    return;
                mkdir_recursive_for_devpath(devpath);
             }
             else {
                 /* This imitates the file system that would be created
                  * if we were using devfs instead.
                  * Minors are broken up into groups of 128, starting at "001"
                  */
                 int bus_id = uevent->minor / 128 + 1;
                 int device_id = uevent->minor % 128 + 1;
                 /* build directories */
                 make_dir("/dev/bus", 0755);
                 make_dir("/dev/bus/usb", 0755);
                 snprintf(devpath, sizeof(devpath), "/dev/bus/usb/%03d", bus_id);
                 make_dir(devpath, 0755);
                 snprintf(devpath, sizeof(devpath), "/dev/bus/usb/%03d/%03d", bus_id, device_id);
             }
         } else {
             /* ignore other USB events */
             return;
         }
     } else if (!strncmp(uevent->subsystem, "graphics", 8)) {
         base = "/dev/graphics/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "drm", 3)) {
         base = "/dev/dri/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "oncrpc", 6)) {
         base = "/dev/oncrpc/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "adsp", 4)) {
         base = "/dev/adsp/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "msm_camera", 10)) {
         base = "/dev/msm_camera/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "input", 5)) {
         base = "/dev/input/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "mtd", 3)) {
         base = "/dev/mtd/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "sound", 5)) {
         base = "/dev/snd/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "misc", 4) && !strncmp(name, "log_", 4)) {
         LOG(INFO) << "kernel logger is deprecated";
         base = "/dev/log/";
         make_dir(base, 0755);
         name += 4;
     } else if (!strncmp(uevent->subsystem, "dvb", 3)) {
         /* This imitates the file system that would be created
          * if we were using devfs instead to preserve backward compatibility
          * for users of dvb devices
          */
         int adapter_id;
         char dev_name[20] = {0};

         sscanf(name, "dvb%d.%s", &adapter_id, dev_name);

         /* build dvb directory */
         base = "/dev/dvb";
         mkdir(base, 0755);

         /* build adapter directory */
         snprintf(devpath, sizeof(devpath), "/dev/dvb/adapter%d", adapter_id);
         mkdir(devpath, 0755);

         /* build actual device directory */
         snprintf(devpath, sizeof(devpath), "/dev/dvb/adapter%d/%s",
                  adapter_id, dev_name);
     } else
         base = "/dev/";
     links = get_character_device_symlinks(uevent);
     if (!links)
         links = get_v4l_device_symlinks(uevent);

     if (!devpath[0])
         snprintf(devpath, sizeof(devpath), "%s%s", base, name);

     handle_device(uevent->action, devpath, uevent->path, 0,
             uevent->major, uevent->minor, links);
}

static void handle_device_event(struct uevent *uevent)
{
    if (!strcmp(uevent->action,"add") || !strcmp(uevent->action, "change") || !strcmp(uevent->action, "online"))
        fixup_sys_perms(uevent->path, uevent->subsystem);

    /* specially handle uevent of "mods_interface" to fix race with ModManager */
    if (!strcmp(uevent->subsystem,"mods_interfaces") && !strcmp(uevent->action, "online")) {
        std::string uevent_path = android::base::StringPrintf("%s/%s/uevent", SYSFS_PREFIX, uevent->path);
        int fd = open(uevent_path.c_str(), O_WRONLY);
        if (fd >= 0) {
            write(fd, "add\n", 4);
            close(fd);
            LOG(INFO) << "sent uevent \"add\" by " << uevent_path;
        } else
            LOG(ERROR) << "failed to open " << uevent_path;
        return;
    }

    if (!strncmp(uevent->subsystem, "block", 5)) {
        handle_block_device_event(uevent);
    } else if (!strncmp(uevent->subsystem, "platform", 8)) {
        handle_platform_device_event(uevent);
    } else {
        handle_generic_device_event(uevent);
    }
}

static void load_firmware(uevent* uevent, const std::string& root,
                          int fw_fd, size_t fw_size,
                          int loading_fd, int data_fd) {
    // Start transfer.
    android::base::WriteFully(loading_fd, "1", 1);

    // Copy the firmware.
    int rc = sendfile(data_fd, fw_fd, nullptr, fw_size);
    if (rc == -1) {
        PLOG(ERROR) << "firmware: sendfile failed { '" << root << "', '" << uevent->firmware << "' }";
    }

    // Tell the firmware whether to abort or commit.
    const char* response = (rc != -1) ? "0" : "-1";
    android::base::WriteFully(loading_fd, response, strlen(response));
}

static int is_booting() {
    return access("/dev/.booting", F_OK) == 0;
}

/*
   Special firmware look-up functionality intended for non-system media firmware (ie.
   downloaded firmware). The folders provided must be protected via SELinux policy.
*/
struct extended_fw_path {
    const char *fw_substring;
    const char *fw_path;
};

const struct extended_fw_path extended_paths[] = {
#ifdef MOTO_AOV_WITH_XMCS
    {
        .fw_substring = "-aov-",
        .fw_path = "/data/adspd",
    },
    {
        .fw_substring = "-ultrasound",
        .fw_path = "/data/adspd",
    },
#endif
#ifdef MOTO_GREYBUS_FIRMWARE
    {
        .fw_substring = "upd-",
        .fw_path = "/data/gbfirmware",
    },
#endif
};

static int is_hard_link(const char *path)
{
    int rv = 1;
    struct stat sb;

    if(stat(path, &sb) == 0) {
        if((S_ISDIR(sb.st_mode)) || (sb.st_nlink == 1))
            rv = 0;
        else
            LOG(ERROR) << "Invalid hard link (" << path << "), nlink=" << sb.st_nlink << " ignoring!";
    } else if (errno == ENOENT)
        rv = 0;
    return(rv);
}

static int load_one_extended(uevent* uevent, int loading_fd, int data_fd, size_t index)
{
    int ret = 0;
    std::string root = android::base::StringPrintf("/sys%s", uevent->path);

    /* look for naming convention for the target firmware */
    if (strstr(uevent->firmware, extended_paths[index].fw_substring) == NULL) {
        return 0;
    }

    std::string file = android::base::StringPrintf("%s/%s", extended_paths[index].fw_path, uevent->firmware);

    if (is_hard_link(file.c_str())) {
        return 0;
    }

    /* Do not consider the case /data folder is still encrypted. It is assumed
       userspace apps needing these files are started only after data partition
       is decrypted. */
    android::base::unique_fd fw_fd(open(file.c_str(), O_RDONLY|O_NOFOLLOW));
    struct stat sb;
    if (fw_fd != -1 && fstat(fw_fd, &sb) != -1) {
        load_firmware(uevent, root, fw_fd, sb.st_size, loading_fd, data_fd);
        ret = -1;
    } else {
        return 0;
    }

    return ret;
}

/*
    -   The function returns the following values:
    -   -1 - Firmware loading was either success or failure. No need to look for further folders.
    -    0 - Firmware was not loaded. Further folders need to be looked up.
*/
static int load_from_extended(uevent* uevent, int loading_fd, int data_fd)
{
    size_t i;

    /* Loop through all possible extended folders unless we find a firmware */
    for (i = 0; i < ARRAY_SIZE(extended_paths); i++)
        if (load_one_extended(uevent, loading_fd, data_fd, i) == -1)
            return -1;

    return 0;
}

static void process_firmware_event(uevent* uevent) {
    int booting = is_booting();

    LOG(INFO) << "firmware: loading '" << uevent->firmware << "' for '" << uevent->path << "'";

    std::string root = android::base::StringPrintf("/sys%s", uevent->path);
    std::string loading = root + "/loading";
    std::string data = root + "/data";

    android::base::unique_fd loading_fd(open(loading.c_str(), O_WRONLY|O_CLOEXEC));
    if (loading_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware loading fd for " << uevent->firmware;
        return;
    }

    android::base::unique_fd data_fd(open(data.c_str(), O_WRONLY|O_CLOEXEC));
    if (data_fd == -1) {
        PLOG(ERROR) << "couldn't open firmware data fd for " << uevent->firmware;
        return;
    }

    if (load_from_extended(uevent, loading_fd, data_fd) < 0) {
        return;
    }

try_loading_again:
    for (size_t i = 0; i < arraysize(firmware_dirs); i++) {
        std::string file = android::base::StringPrintf("%s/%s", firmware_dirs[i], uevent->firmware);
        android::base::unique_fd fw_fd(open(file.c_str(), O_RDONLY|O_CLOEXEC));
        struct stat sb;
        if (fw_fd != -1 && fstat(fw_fd, &sb) != -1) {
            load_firmware(uevent, root, fw_fd, sb.st_size, loading_fd, data_fd);
            return;
        }
    }

    if (booting) {
        // If we're not fully booted, we may be missing
        // filesystems needed for firmware, wait and retry.
        std::this_thread::sleep_for(100ms);
        booting = is_booting();
        goto try_loading_again;
    }

    LOG(ERROR) << "firmware: could not find firmware for " << uevent->firmware;

    // Write "-1" as our response to the kernel's firmware request, since we have nothing for it.
    write(loading_fd, "-1", 2);
}

static void handle_firmware_event(uevent* uevent) {
    if (strcmp(uevent->subsystem, "firmware")) return;
    if (strcmp(uevent->action, "add")) return;

    // Loading the firmware in a child means we can do that in parallel...
    // (We ignore SIGCHLD rather than wait for our children.)
    pid_t pid = fork();
    if (pid == 0) {
        Timer t;
        process_firmware_event(uevent);
        LOG(INFO) << "loading " << uevent->path << " took " << t;
        _exit(EXIT_SUCCESS);
    } else if (pid == -1) {
        PLOG(ERROR) << "could not fork to process firmware event for " << uevent->firmware;
    }
}

static bool inline should_stop_coldboot(coldboot_action_t act)
{
    return (act == COLDBOOT_STOP || act == COLDBOOT_FINISH);
}

#define UEVENT_MSG_LEN  2048

static inline coldboot_action_t handle_device_fd_with(
        std::function<coldboot_action_t(uevent* uevent)> handle_uevent)
{
    char msg[UEVENT_MSG_LEN+2];
    int n;
    while ((n = uevent_kernel_multicast_recv(device_fd, msg, UEVENT_MSG_LEN)) > 0) {
        if(n >= UEVENT_MSG_LEN)   /* overflow -- discard */
            continue;

        msg[n] = '\0';
        msg[n+1] = '\0';

        struct uevent uevent;
        parse_event(msg, &uevent);
        coldboot_action_t act = handle_uevent(&uevent);
        if (should_stop_coldboot(act))
            return act;
    }

    return COLDBOOT_CONTINUE;
}

coldboot_action_t handle_device_fd(coldboot_callback fn)
{
    coldboot_action_t ret = handle_device_fd_with(
        [&](uevent* uevent) -> coldboot_action_t {
            if (selinux_status_updated() > 0) {
                struct selabel_handle *sehandle2;
                sehandle2 = selinux_android_file_context_handle();
                if (sehandle2) {
                    selabel_close(sehandle);
                    sehandle = sehandle2;
                }
            }

            // default is to always create the devices
            coldboot_action_t act = COLDBOOT_CREATE;
            if (fn) {
                act = fn(uevent);
            }

            if (act == COLDBOOT_CREATE || act == COLDBOOT_STOP) {
                handle_device_event(uevent);
                handle_firmware_event(uevent);
            }

            return act;
        });

    return ret;
}

/* Coldboot walks parts of the /sys tree and pokes the uevent files
** to cause the kernel to regenerate device add events that happened
** before init's device manager was started
**
** We drain any pending events from the netlink socket every time
** we poke another uevent file to make sure we don't overrun the
** socket's buffer.
*/

static coldboot_action_t do_coldboot(DIR *d, coldboot_callback fn)
{
    struct dirent *de;
    int dfd, fd;
    coldboot_action_t act = COLDBOOT_CONTINUE;

    dfd = dirfd(d);

    fd = openat(dfd, "uevent", O_WRONLY);
    if (fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);
        act = handle_device_fd(fn);
        if (should_stop_coldboot(act))
            return act;
    }

    while (!should_stop_coldboot(act) && (de = readdir(d))) {
        DIR *d2;

        if(de->d_type != DT_DIR || de->d_name[0] == '.')
            continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if(fd < 0)
            continue;

        d2 = fdopendir(fd);
        if(d2 == 0)
            close(fd);
        else {
            act = do_coldboot(d2, fn);
            closedir(d2);
        }
    }

    // default is always to continue looking for uevents
    return act;
}

static coldboot_action_t coldboot(const char *path, coldboot_callback fn)
{
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir(path), closedir);
    if (d) {
        return do_coldboot(d.get(), fn);
    }

    return COLDBOOT_CONTINUE;
}

void device_init(const char* path, coldboot_callback fn) {
    if (!sehandle) {
        sehandle = selinux_android_file_context_handle();
    }
    // open uevent socket and selinux status only if it hasn't been
    // done before
    if (device_fd == -1) {
        /* is 256K enough? udev uses 16MB! */
        device_fd.reset(uevent_open_socket(256 * 1024, true));
        if (device_fd == -1) {
            return;
        }
        fcntl(device_fd, F_SETFL, O_NONBLOCK);
        selinux_status_open(true);
    }

    if (access(COLDBOOT_DONE, F_OK) == 0) {
        LOG(VERBOSE) << "Skipping coldboot, already done!";
        return;
    }

    Timer t;
    coldboot_action_t act;
    if (!path) {
        act = coldboot("/sys/class", fn);
        if (!should_stop_coldboot(act)) {
            act = coldboot("/sys/block", fn);
            if (!should_stop_coldboot(act)) {
                act = coldboot("/sys/devices", fn);
            }
        }
    } else {
        act = coldboot(path, fn);
    }

    // If we have a callback, then do as it says. If no, then the default is
    // to always create COLDBOOT_DONE file.
    if (!fn || (act == COLDBOOT_FINISH)) {
        close(open(COLDBOOT_DONE, O_WRONLY|O_CREAT|O_CLOEXEC, 0000));
    }

    LOG(INFO) << "Coldboot took " << t;
}

void device_close() {
    destroy_platform_devices();
    device_fd.reset();
    selinux_status_close();
}

int get_device_fd() {
    return device_fd;
}

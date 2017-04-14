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
#include <linux/netlink.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/list.h>
#include <cutils/uevent.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>
#include <selinux/avc.h>
#include <selinux/label.h>
#include <selinux/selinux.h>

#include "devices.h"
#include "ueventd_parser.h"
#include "util.h"

#define SYSFS_PREFIX    "/sys"

extern struct selabel_handle *sehandle;

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

static list_declare(sys_perms);
static list_declare(dev_perms);

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

static void fixup_sys_perms(const std::string& upath, const std::string& subsystem) {
    // upaths omit the "/sys" that paths in this list
    // contain, so we prepend it...
    std::string path = SYSFS_PREFIX + upath;

    listnode* node;
    list_for_each(node, &sys_perms) {
        perms_* dp = &(node_to_item(node, perm_node, plist))->dp;
        if (match_subsystem(dp, SYSFS_PREFIX "/class/%s/%s", path.c_str(), subsystem.c_str())) {
            ; // matched
        } else if (match_subsystem(dp, SYSFS_PREFIX "/bus/%s/devices/%s", path.c_str(),
                                   subsystem.c_str())) {
            ; // matched
        } else if (!perm_path_matches(path.c_str(), dp)) {
            continue;
        }

        std::string attr_file = path + "/" + dp->attr;
        LOG(INFO) << "fixup " << attr_file
                  << " " << dp->uid << " " << dp->gid << " " << std::oct << dp->perm;
        chown(attr_file.c_str(), dp->uid, dp->gid);
        chmod(attr_file.c_str(), dp->perm);
    }

    if (access(path.c_str(), F_OK) == 0) {
        LOG(VERBOSE) << "restorecon_recursive: " << path;
        restorecon(path.c_str(), SELINUX_ANDROID_RESTORECON_RECURSE);
    }
}

static mode_t get_device_perm(const char* path, const std::vector<std::string>& links,
                              unsigned* uid, unsigned* gid) {
    struct listnode *node;
    struct perm_node *perm_node;
    struct perms_ *dp;

    /* search the perms list in reverse so that ueventd.$hardware can
     * override ueventd.rc
     */
    list_for_each_reverse(node, &dev_perms) {
        perm_node = node_to_item(node, struct perm_node, plist);
        dp = &perm_node->dp;

        if (perm_path_matches(path, dp) ||
            std::any_of(links.begin(), links.end(),
                        [dp](const auto& link) { return perm_path_matches(link.c_str(), dp); })) {
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

static void make_device(const std::string& path, int block, int major, int minor,
                        const std::vector<std::string>& links) {
    unsigned uid;
    unsigned gid;
    mode_t mode;
    dev_t dev;
    char *secontext = NULL;

    mode = get_device_perm(path.c_str(), links, &uid, &gid) | (block ? S_IFBLK : S_IFCHR);

    if (sehandle) {
        std::vector<const char*> c_links;
        for (const auto& link : links) {
            c_links.emplace_back(link.c_str());
        }
        c_links.emplace_back(nullptr);
        if (selabel_lookup_best_match(sehandle, &secontext, path.c_str(), &c_links[0], mode)) {
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
    if (mknod(path.c_str(), mode, dev) && (errno == EEXIST) && secontext) {
        char* fcon = nullptr;
        int rc = lgetfilecon(path.c_str(), &fcon);
        if (rc < 0) {
            PLOG(ERROR) << "Cannot get SELinux label on '" << path << "' device";
            goto out;
        }

        bool different = strcmp(fcon, secontext) != 0;
        freecon(fcon);

        if (different && lsetfilecon(path.c_str(), secontext)) {
            PLOG(ERROR) << "Cannot set '" << secontext << "' SELinux label on '" << path << "' device";
        }
    }

out:
    chown(path.c_str(), uid, -1);
    if (setegid(AID_ROOT)) {
        PLOG(FATAL) << "setegid(AID_ROOT) failed";
    }

    if (secontext) {
        freecon(secontext);
        setfscreatecon(NULL);
    }
}

// TODO: Move this to be a member variable of a future devices class.
std::vector<std::string> platform_devices;

// Given a path that may start with a platform device, find the length of the
// platform device prefix.  If it doesn't start with a platform device, return false
bool find_platform_device(const std::string& path, std::string* out_path) {
    out_path->clear();
    // platform_devices is searched backwards, since parents are added before their children,
    // and we want to match as deep of a child as we can.
    for (auto it = platform_devices.rbegin(); it != platform_devices.rend(); ++it) {
        auto platform_device_path_length = it->length();
        if (platform_device_path_length < path.length() &&
            path[platform_device_path_length] == '/' &&
            android::base::StartsWith(path, it->c_str())) {
            *out_path = *it;
            return true;
        }
    }
    return false;
}

/* Given a path that may start with a PCI device, populate the supplied buffer
 * with the PCI domain/bus number and the peripheral ID and return 0.
 * If it doesn't start with a PCI device, or there is some error, return -1 */
static bool find_pci_device_prefix(const std::string& path, std::string* result) {
    result->clear();

    if (!android::base::StartsWith(path, "/devices/pci")) return false;

    /* Beginning of the prefix is the initial "pci" after "/devices/" */
    std::string::size_type start = 9;

    /* End of the prefix is two path '/' later, capturing the domain/bus number
     * and the peripheral ID. Example: pci0000:00/0000:00:1f.2 */
    auto end = path.find('/', start);
    if (end == std::string::npos) return false;

    end = path.find('/', end + 1);
    if (end == std::string::npos) return false;

    auto length = end - start;
    if (length <= 4) {
        // The minimum string that will get to this check is 'pci/', which is malformed,
        // so return false
        return false;
    }

    *result = path.substr(start, length);
    return true;
}

/* Given a path that may start with a virtual block device, populate
 * the supplied buffer with the virtual block device ID and return 0.
 * If it doesn't start with a virtual block device, or there is some
 * error, return -1 */
static bool find_vbd_device_prefix(const std::string& path, std::string* result) {
    result->clear();

    if (!android::base::StartsWith(path, "/devices/vbd-")) return false;

    /* Beginning of the prefix is the initial "vbd-" after "/devices/" */
    std::string::size_type start = 13;

    /* End of the prefix is one path '/' later, capturing the
       virtual block device ID. Example: 768 */
    auto end = path.find('/', start);
    if (end == std::string::npos) return false;

    auto length = end - start;
    if (length == 0) return false;

    *result = path.substr(start, length);
    return true;
}

void parse_event(const char* msg, uevent* uevent) {
    uevent->partition_num = -1;
    uevent->major = -1;
    uevent->minor = -1;
    // currently ignoring SEQNUM
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

        // advance to after the next \0
        while(*msg++)
            ;
    }

    if (LOG_UEVENTS) {
        LOG(INFO) << "event { '" << uevent->action << "', '" << uevent->path << "', '"
                  << uevent->subsystem << "', '" << uevent->firmware << "', " << uevent->major
                  << ", " << uevent->minor << " }";
    }
}

std::vector<std::string> get_character_device_symlinks(uevent* uevent) {
    std::string parent_device;
    if (!find_platform_device(uevent->path, &parent_device)) return {};

    // skip path to the parent driver
    std::string path = uevent->path.substr(parent_device.length());

    if (!android::base::StartsWith(path, "/usb")) return {};

    // skip root hub name and device. use device interface
    // skip 3 slashes, including the first / by starting the search at the 1st character, not 0th.
    // then extract what comes between the 3rd and 4th slash
    // e.g. "/usb/usb_device/name/tty2-1:1.0" -> "name"

    std::string::size_type start = 0;
    start = path.find('/', start + 1);
    if (start == std::string::npos) return {};

    start = path.find('/', start + 1);
    if (start == std::string::npos) return {};

    auto end = path.find('/', start + 1);
    if (end == std::string::npos) return {};

    start++;  // Skip the first '/'

    auto length = end - start;
    if (length == 0) return {};

    auto name_string = path.substr(start, length);

    std::vector<std::string> links;
    links.emplace_back("/dev/usb/" + uevent->subsystem + name_string);

    mkdir("/dev/usb", 0755);

    return links;
}

// replaces any unacceptable characters with '_', the
// length of the resulting string is equal to the input string
void sanitize_partition_name(std::string* string) {
    const char* accept =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        "_-.";

    if (!string) return;

    std::string::size_type pos = 0;
    while ((pos = string->find_first_not_of(accept, pos)) != std::string::npos) {
        (*string)[pos] = '_';
    }
}

std::vector<std::string> get_block_device_symlinks(uevent* uevent) {
    std::string device;
    std::string type;

    if (find_platform_device(uevent->path, &device)) {
        // Skip /devices/platform or /devices/ if present
        static const std::string devices_platform_prefix = "/devices/platform/";
        static const std::string devices_prefix = "/devices/";

        if (android::base::StartsWith(device, devices_platform_prefix.c_str())) {
            device = device.substr(devices_platform_prefix.length());
        } else if (android::base::StartsWith(device, devices_prefix.c_str())) {
            device = device.substr(devices_prefix.length());
        }

        type = "platform";
    } else if (find_pci_device_prefix(uevent->path, &device)) {
        type = "pci";
    } else if (find_vbd_device_prefix(uevent->path, &device)) {
        type = "vbd";
    } else {
        return {};
    }

    std::vector<std::string> links;

    LOG(VERBOSE) << "found " << type << " device " << device;

    auto link_path = "/dev/block/" + type + "/" + device;

    if (!uevent->partition_name.empty()) {
        std::string partition_name_sanitized(uevent->partition_name);
        sanitize_partition_name(&partition_name_sanitized);
        if (partition_name_sanitized != uevent->partition_name) {
            LOG(VERBOSE) << "Linking partition '" << uevent->partition_name << "' as '"
                         << partition_name_sanitized << "'";
        }
        links.emplace_back(link_path + "/by-name/" + partition_name_sanitized);
    }

    if (uevent->partition_num >= 0) {
        links.emplace_back(link_path + "/by-num/p" + std::to_string(uevent->partition_num));
    }

    auto last_slash = uevent->path.rfind('/');
    links.emplace_back(link_path + "/" + uevent->path.substr(last_slash + 1));

    return links;
}

static void make_link_init(const std::string& oldpath, const std::string& newpath) {
    if (mkdir_recursive(dirname(newpath.c_str()), 0755)) {
        PLOG(ERROR) << "Failed to create directory " << dirname(newpath.c_str());
    }

    if (symlink(oldpath.c_str(), newpath.c_str()) && errno != EEXIST) {
        PLOG(ERROR) << "Failed to symlink " << oldpath << " to " << newpath;
    }
}

static void remove_link(const std::string& oldpath, const std::string& newpath) {
    std::string path;
    if (android::base::Readlink(newpath, &path) && path == oldpath) unlink(newpath.c_str());
}

static void handle_device(const std::string& action, const std::string& devpath, int block,
                          int major, int minor, const std::vector<std::string>& links) {
    if (action == "add") {
        make_device(devpath, block, major, minor, links);
        for (const auto& link : links) {
            make_link_init(devpath, link);
        }
    }

    if (action == "remove") {
        for (const auto& link : links) {
            remove_link(devpath, link);
        }
        unlink(devpath.c_str());
    }
}

void handle_platform_device_event(uevent* uevent) {
    if (uevent->action == "add") {
        platform_devices.emplace_back(uevent->path);
    } else if (uevent->action == "remove") {
        auto it = std::find(platform_devices.begin(), platform_devices.end(), uevent->path);
        if (it != platform_devices.end()) platform_devices.erase(it);
    }
}

static void handle_block_device_event(uevent* uevent) {
    // if it's not a /dev device, nothing to do
    if (uevent->major < 0 || uevent->minor < 0) return;

    const char* base = "/dev/block/";
    make_dir(base, 0755);

    std::string name = android::base::Basename(uevent->path);
    std::string devpath = base + name;

    std::vector<std::string> links;
    if (android::base::StartsWith(uevent->path, "/devices")) {
        links = get_block_device_symlinks(uevent);
    }

    handle_device(uevent->action, devpath, 1, uevent->major, uevent->minor, links);
}

static void handle_generic_device_event(uevent* uevent) {
    // if it's not a /dev device, nothing to do
    if (uevent->major < 0 || uevent->minor < 0) return;

    std::string name = android::base::Basename(uevent->path);
    ueventd_subsystem* subsystem = ueventd_subsystem_find_by_name(uevent->subsystem.c_str());

    std::string devpath;

    if (subsystem) {
        std::string devname;

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

        // TODO: Remove std::string()
        devpath = std::string(subsystem->dirname) + "/" + devname;
        mkdir_recursive(android::base::Dirname(devpath), 0755);
    } else if (android::base::StartsWith(uevent->subsystem, "usb")) {
        if (uevent->subsystem == "usb") {
            if (!uevent->device_name.empty()) {
                devpath = "/dev/" + uevent->device_name;
            } else {
                // This imitates the file system that would be created
                // if we were using devfs instead.
                // Minors are broken up into groups of 128, starting at "001"
                int bus_id = uevent->minor / 128 + 1;
                int device_id = uevent->minor % 128 + 1;
                devpath = android::base::StringPrintf("/dev/bus/usb/%03d/%03d", bus_id, device_id);
            }
            mkdir_recursive(android::base::Dirname(devpath), 0755);
        } else {
            // ignore other USB events
            return;
        }
    } else {
        devpath = "/dev/" + name;
    }

    auto links = get_character_device_symlinks(uevent);

    handle_device(uevent->action, devpath, 0, uevent->major, uevent->minor, links);
}

static void handle_device_event(struct uevent *uevent)
{
    if (uevent->action == "add" || uevent->action == "change" || uevent->action == "online") {
        fixup_sys_perms(uevent->path, uevent->subsystem);
    }

    if (uevent->subsystem == "block") {
        handle_block_device_event(uevent);
    } else if (uevent->subsystem == "platform") {
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

static void process_firmware_event(uevent* uevent) {
    int booting = is_booting();

    LOG(INFO) << "firmware: loading '" << uevent->firmware << "' for '" << uevent->path << "'";

    std::string root = "/sys" + uevent->path;
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

    static const char* firmware_dirs[] = {"/etc/firmware/", "/vendor/firmware/",
                                          "/firmware/image/"};

try_loading_again:
    for (size_t i = 0; i < arraysize(firmware_dirs); i++) {
        std::string file = firmware_dirs[i] + uevent->firmware;
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
    if (uevent->subsystem != "firmware" || uevent->action != "add") return;

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

        uevent uevent;
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
    platform_devices.clear();
    device_fd.reset();
    selinux_status_close();
}

int get_device_fd() {
    return device_fd;
}

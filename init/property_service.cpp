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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <sys/poll.h>

#include <memory>

#include <cutils/misc.h>
#include <cutils/sockets.h>
#include <cutils/multiuser.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <private/android_filesystem_config.h>

#include <selinux/selinux.h>
#include <selinux/label.h>

#include <fs_mgr.h>
#include <android-base/file.h>
#include "bootimg.h"

#include "property_service.h"
#include "init.h"
#include "util.h"
#include "log.h"

#ifdef MTK_INIT
#include <sys/system_properties.h>
#include <cutils/android_reboot.h>
#endif
#define PERSISTENT_PROPERTY_DIR  "/data/property"
#define FSTAB_PREFIX "/fstab."
#define RECOVERY_MOUNT_POINT "/recovery"

static int persistent_properties_loaded = 0;

static int property_set_fd = -1;

/* efuse struct */
typedef struct {
    unsigned int entry_num;
    unsigned int data[100];
}DEVINFO_S;

void property_init() {
    if (__system_property_area_init()) {
        ERROR("Failed to initialize property area\n");
        exit(1);
    }
}

static int check_mac_perms(const char *name, char *sctx, struct ucred *cr)
{
    char *tctx = NULL;
    int result = 0;
    property_audit_data audit_data;

    if (!sctx)
        goto err;

    if (!sehandle_prop)
        goto err;

    if (selabel_lookup(sehandle_prop, &tctx, name, 1) != 0)
        goto err;

    audit_data.name = name;
    audit_data.cr = cr;

    if (selinux_check_access(sctx, tctx, "property_service", "set", reinterpret_cast<void*>(&audit_data)) == 0)
        result = 1;

    freecon(tctx);
 err:
    return result;
}

static int check_control_mac_perms(const char *name, char *sctx, struct ucred *cr)
{
    /*
     *  Create a name prefix out of ctl.<service name>
     *  The new prefix allows the use of the existing
     *  property service backend labeling while avoiding
     *  mislabels based on true property prefixes.
     */
    char ctl_name[PROP_VALUE_MAX+4];
    int ret = snprintf(ctl_name, sizeof(ctl_name), "ctl.%s", name);

    if (ret < 0 || (size_t) ret >= sizeof(ctl_name))
        return 0;

    return check_mac_perms(ctl_name, sctx, cr);
}

std::string property_get(const char* name) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(name, value);
    return value;
}

static void write_persistent_property(const char *name, const char *value)
{
    char tempPath[PATH_MAX];
    char path[PATH_MAX];
    int fd;

    snprintf(tempPath, sizeof(tempPath), "%s/.temp.XXXXXX", PERSISTENT_PROPERTY_DIR);
    fd = mkstemp(tempPath);
    if (fd < 0) {
        ERROR("Unable to write persistent property to temp file %s: %s\n", tempPath, strerror(errno));
        return;
    }
    write(fd, value, strlen(value));
    fsync(fd);
    close(fd);

    snprintf(path, sizeof(path), "%s/%s", PERSISTENT_PROPERTY_DIR, name);
    if (rename(tempPath, path)) {
        unlink(tempPath);
        ERROR("Unable to rename persistent property file %s to %s\n", tempPath, path);
    }
}

static bool is_legal_property_name(const char* name, size_t namelen)
{
    size_t i;
    if (namelen >= PROP_NAME_MAX) return false;
    if (namelen < 1) return false;
    if (name[0] == '.') return false;
    if (name[namelen - 1] == '.') return false;

    /* Only allow alphanumeric, plus '.', '-', or '_' */
    /* Don't allow ".." to appear in a property name */
    for (i = 0; i < namelen; i++) {
        if (name[i] == '.') {
            // i=0 is guaranteed to never have a dot. See above.
            if (name[i-1] == '.') return false;
            continue;
        }
        if (name[i] == '_' || name[i] == '-') continue;
        if (name[i] >= 'a' && name[i] <= 'z') continue;
        if (name[i] >= 'A' && name[i] <= 'Z') continue;
        if (name[i] >= '0' && name[i] <= '9') continue;
        return false;
    }

    return true;
}

static int property_set_impl(const char* name, const char* value) {
    size_t namelen = strlen(name);
    size_t valuelen = strlen(value);

    if (!is_legal_property_name(name, namelen)) return -1;
    if (valuelen >= PROP_VALUE_MAX) return -1;

    if (strcmp("selinux.reload_policy", name) == 0 && strcmp("1", value) == 0) {
        if (selinux_reload_policy() != 0) {
            ERROR("Failed to reload policy\n");
        }
    } else if (strcmp("selinux.restorecon_recursive", name) == 0 && valuelen > 0) {
        if (restorecon_recursive(value) != 0) {
            ERROR("Failed to restorecon_recursive %s\n", value);
        }
    }

    prop_info* pi = (prop_info*) __system_property_find(name);

    if(pi != 0) {
        /* ro.* properties may NEVER be modified once set */
        if(!strncmp(name, "ro.", 3)) {
#ifdef MTK_INIT
            ERROR("PropSet Error:[%s:%s]  ro.* properties may NEVER be modified once set\n", name, value);
#endif
            return -1;
        }
        __system_property_update(pi, value, valuelen);
    } else {
        int rc = __system_property_add(name, namelen, value, valuelen);
        if (rc < 0) {
#ifdef MTK_INIT
            ERROR("Failed to set '%s'='%s'\n", name, value);
#endif
            return rc;
        }
    }
    /* If name starts with "net." treat as a DNS property. */
    if (strncmp("net.", name, strlen("net.")) == 0)  {
        if (strcmp("net.change", name) == 0) {
#ifdef MTK_INIT
            INFO("PropSet [%s:%s] Done\n", name, value);
#endif
            return 0;
        }
       /*
        * The 'net.change' property is a special property used track when any
        * 'net.*' property name is updated. It is _ONLY_ updated here. Its value
        * contains the last updated 'net.*' property.
        */
        property_set("net.change", name);
    } else if (persistent_properties_loaded &&
            strncmp("persist.", name, strlen("persist.")) == 0) {
        /*
         * Don't write properties to disk until after we have read all default properties
         * to prevent them from being overwritten by default values.
         */
        write_persistent_property(name, value);
    }
    property_changed(name, value);
#ifdef MTK_INIT
    INFO("PropSet [%s:%s] Done\n", name, value);
#endif
    return 0;
}

#ifdef MTK_INIT
int reboot_pid(int pid) {
    int fd = open("/proc/mtprof/reboot_pid", O_RDWR);
    char buf[100];
    int cnt;

    cnt = sprintf(buf, "%d", pid);

    fprintf(stderr, "reboot  pid is %d, %s.\n", pid, buf);
    if(fd < 0) {
        fprintf(stderr, "open /proc/mtprof/reboot_pid error");
        return 0;
    }

    write(fd, buf, cnt);
    close(fd);
    return 1;
}
#endif

int property_set(const char* name, const char* value) {
    int rc = property_set_impl(name, value);
    if (rc == -1) {
        ERROR("property_set(\"%s\", \"%s\") failed\n", name, value);
    }
    return rc;
}

static void handle_property_set_fd()
{
    prop_msg msg;
    int s;
    int r;
    struct ucred cr;
    struct sockaddr_un addr;
    socklen_t addr_size = sizeof(addr);
    socklen_t cr_size = sizeof(cr);
    char * source_ctx = NULL;
    struct pollfd ufds[1];
    const int timeout_ms = 2 * 1000;  /* Default 2 sec timeout for caller to send property. */
    int nr;

    if ((s = accept(property_set_fd, (struct sockaddr *) &addr, &addr_size)) < 0) {
        return;
    }

    /* Check socket options here */
    if (getsockopt(s, SOL_SOCKET, SO_PEERCRED, &cr, &cr_size) < 0) {
        close(s);
        ERROR("Unable to receive socket options\n");
        return;
    }

    ufds[0].fd = s;
    ufds[0].events = POLLIN;
    ufds[0].revents = 0;
    nr = TEMP_FAILURE_RETRY(poll(ufds, 1, timeout_ms));
    if (nr == 0) {
        ERROR("sys_prop: timeout waiting for uid=%d to send property message.\n", cr.uid);
        close(s);
        return;
    } else if (nr < 0) {
        ERROR("sys_prop: error waiting for uid=%d to send property message: %s\n", cr.uid, strerror(errno));
        close(s);
        return;
    }

    r = TEMP_FAILURE_RETRY(recv(s, &msg, sizeof(msg), MSG_DONTWAIT));
    if(r != sizeof(prop_msg)) {
        ERROR("sys_prop: mis-match msg size received: %d expected: %zu: %s\n",
              r, sizeof(prop_msg), strerror(errno));
        close(s);
        return;
    }

    switch(msg.cmd) {
    case PROP_MSG_SETPROP:
        msg.name[PROP_NAME_MAX-1] = 0;
        msg.value[PROP_VALUE_MAX-1] = 0;

        if (!is_legal_property_name(msg.name, strlen(msg.name))) {
            ERROR("sys_prop: illegal property name. Got: \"%s\"\n", msg.name);
            close(s);
            return;
        }

        getpeercon(s, &source_ctx);

        if(memcmp(msg.name,"ctl.",4) == 0) {
            // Keep the old close-socket-early behavior when handling
            // ctl.* properties.
            close(s);
            if (check_control_mac_perms(msg.value, source_ctx, &cr)) {
#ifdef MTK_INIT
                INFO("[PropSet]: pid:%u uid:%u gid:%u %s %s\n", cr.pid, cr.uid, cr.gid, msg.name, msg.value);
#endif
                handle_control_message((char*) msg.name + 4, (char*) msg.value);
            } else {
                ERROR("sys_prop: Unable to %s service ctl [%s] uid:%d gid:%d pid:%d\n",
                        msg.name + 4, msg.value, cr.uid, cr.gid, cr.pid);
            }
        } else {
            if (check_mac_perms(msg.name, source_ctx, &cr)) {
#ifdef MTK_INIT
                INFO("[PropSet]: pid:%u uid:%u gid:%u set %s=%s\n", cr.pid, cr.uid, cr.gid, msg.name, msg.value);
                if(strcmp(msg.name, ANDROID_RB_PROPERTY) == 0) {
                    INFO("pid %d set %s=%s\n", cr.pid, msg.name, msg.value);
                    reboot_pid(cr.pid);
                }
#endif
                property_set((char*) msg.name, (char*) msg.value);
            } else {
                ERROR("sys_prop: permission denied uid:%d  name:%s\n",
                      cr.uid, msg.name);
            }

            // Note: bionic's property client code assumes that the
            // property server will not close the socket until *AFTER*
            // the property is written to memory.
            close(s);
        }
        freecon(source_ctx);
        break;

    default:
        close(s);
        break;
    }
}

static void load_properties_from_file(const char *, const char *);

static void set_chip_cond_prop() {
    int fd = 0;
    int ret = 0;
    unsigned int devinfo_data = 0;
    DEVINFO_S devinfo;

    fd = open("/sys/bus/platform/drivers/dev_info/dev_info", O_RDONLY);
    if(fd < 0) {
        ERROR("v1 device node is removed\n");
        fd = open("/proc/device-tree/chosen/atag,devinfo", O_RDONLY);
        if(fd < 0) {
            ERROR("v2 device node is removed\n");
            ERROR("efuse dev open fail \n");
            return;
        }
    }

    ret = read(fd, (void*)&devinfo, sizeof(DEVINFO_S));
    if(ret > 0) {
        devinfo_data = devinfo.data[25]; /* devinfo index = 25 */
        NOTICE("devinfo info data is %x.\n", devinfo_data);
        if(((devinfo_data >> 27) & 0x7) == 0x0) {
            NOTICE("For 3G only chip.\n");
            ret = property_set("persist.radio.lte.chip", "2");
            if(ret < 0)
                ERROR("[PropSet] set persist.radio.lte.chip.condition fail!! \n");
        } else {
            NOTICE("For LTE capable chip.\n");
            ret = property_set("persist.radio.lte.chip", "1");
            if(ret < 0)
                ERROR("[PropSet] set persist.radio.lte.chip.condition fail!! \n");
        }
    } else
        ERROR("Read efuse fail, ret: %d\n", ret);
    close(fd);
}

/*
 * Filter is used to decide which properties to load: NULL loads all keys,
 * "ro.foo.*" is a prefix match, and "ro.foo.bar" is an exact match.
 */
static void load_properties(char *data, const char *filter)
{
    char *key, *value, *eol, *sol, *tmp, *fn;
    size_t flen = 0;

    if (filter) {
        flen = strlen(filter);
    }

    sol = data;
    while ((eol = strchr(sol, '\n'))) {
        key = sol;
        *eol++ = 0;
        sol = eol;

        while (isspace(*key)) key++;
        if (*key == '#') continue;

        tmp = eol - 2;
        while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

        if (!strncmp(key, "import ", 7) && flen == 0) {
            fn = key + 7;
            while (isspace(*fn)) fn++;

            key = strchr(fn, ' ');
            if (key) {
                *key++ = 0;
                while (isspace(*key)) key++;
            }

            load_properties_from_file(fn, key);

        } else {
            value = strchr(key, '=');
            if (!value) continue;
            *value++ = 0;

            tmp = value - 2;
            while ((tmp > key) && isspace(*tmp)) *tmp-- = 0;

            while (isspace(*value)) value++;

            if (flen > 0) {
                if (filter[flen - 1] == '*') {
                    if (strncmp(key, filter, flen - 1)) continue;
                } else {
                    if (strcmp(key, filter)) continue;
                }
            }
#ifdef LCT_SIM_SINGLE_CHECK
          //add by yangchao for single sim &dual sim,start
            if (strcmp("ro.longcheer.simsum", key) == 0 && is_single_sim_card_device()) {
                NOTICE("songgy--load_properties-{ro.longcheer.simsum}, value=%s, Modify_value=1)\n", value);
                property_set(key, "1");
            } 
          //add by yangchao for single sim &dual sim,end
#endif

            property_set(key, value);
        }
    }
}

#ifdef LCT_SIM_SINGLE_CHECK
//add by yangchao for single sim &dual sim,start
/*private String projectinfo[][]={
                         {"0","EVT2","AP"}
                        ,{"1","EVT2","EMEA Dual SIM"}
                        ,{"2","EVT2","EMEA Single SIM"}
                        ,{"3","EVT2","LATAM Dual SIM"}
                        ,{"4","EVT2","LATAM Single SIM"}

                        ,{"5","DVT1","AP"}
                        ,{"6","DVT1","EMEA Dual SIM"}
                        ,{"7","DVT1","EMEA Single SIM"}
                        ,{"8","DVT1","LATAM Dual SIM"}
                        ,{"9","DVT1","LATAM Single SIM"}


                        ,{"10","DVT2","AP"}
                        ,{"11","DVT2","EMEA Dual SIM"}
                        ,{"12","DVT2","EMEA Single SIM"}
                        ,{"13","DVT2","LATAM Dual SIM"}
                        ,{"14","DVT2","LATAM Single SIM"}

                        ,{"15","PVT","AP"}
                        ,{"16","PVT","EMEA Dual SIM"}
                        ,{"17","PVT","EMEA Single SIM"}
                        ,{"18","PVT","LATAM Dual SIM"}
                        ,{"19","PVT","LATAM Single SIM"}

                        ,{"20","MP","AP"}
                        ,{"21","MP","EMEA Dual SIM"}
                        ,{"22","MP","EMEA Single SIM"}
                        ,{"23","MP","LATAM Dual SIM"}
                        ,{"24","MP","LATAM Single SIM"}

         }; 
*/
bool is_single_sim_card_device()
{

    char buffer[2];
    int  skuid;
    FILE *fp = fopen("/sys/devices/simcheck/sku_check", "r");
    if (!fp) {
        ERROR("yangchao - Cannot open file /sys/devices/simcheck/sku_check\n");
    }

    char *cp = fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    if (!cp) {
        ERROR("yangchao - Error while reading file /sys/sim_card/single_or_dual\n");
    }

    
    NOTICE("yangchao - buffer = %s\n", buffer);
    skuid =atoi(buffer);
    NOTICE("yangchao - skuid = %d\n", skuid);
    if((skuid%5) == 2|| (skuid%5) == 4)
    {
     NOTICE("yangchao - is_single_sim_card_device - true\n");
     return true;
    }else {
        NOTICE("yangchao - is_single_sim_card_device - false\n");
        return false;
    }

}
//add by yangchao for single sim &dual sim,end
#endif


/*
 * Filter is used to decide which properties to load: NULL loads all keys,
 * "ro.foo.*" is a prefix match, and "ro.foo.bar" is an exact match.
 */
static void load_properties_from_file(const char* filename, const char* filter) {
    Timer t;
    std::string data;
    if (read_file(filename, &data)) {
        data.push_back('\n');
        load_properties(&data[0], filter);
    }
#ifdef MTK_INIT
    else
        NOTICE("can not load properties %s from %s\n", filter, filename);
#endif
    NOTICE("(Loading properties from %s took %.2fs.)\n", filename, t.duration());
}

static void load_persistent_properties() {
    persistent_properties_loaded = 1;

    std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir(PERSISTENT_PROPERTY_DIR), closedir);
    if (!dir) {
        ERROR("Unable to open persistent property directory \"%s\": %s\n",
              PERSISTENT_PROPERTY_DIR, strerror(errno));
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir.get())) != NULL) {
        if (strncmp("persist.", entry->d_name, strlen("persist."))) {
            continue;
        }
        if (entry->d_type != DT_REG) {
            continue;
        }

        // Open the file and read the property value.
        int fd = openat(dirfd(dir.get()), entry->d_name, O_RDONLY | O_NOFOLLOW);
        if (fd == -1) {
            ERROR("Unable to open persistent property file \"%s\": %s\n",
                  entry->d_name, strerror(errno));
            continue;
        }

        struct stat sb;
        if (fstat(fd, &sb) == -1) {
            ERROR("fstat on property file \"%s\" failed: %s\n", entry->d_name, strerror(errno));
            close(fd);
            continue;
        }

        // File must not be accessible to others, be owned by root/root, and
        // not be a hard link to any other file.
        if (((sb.st_mode & (S_IRWXG | S_IRWXO)) != 0) || (sb.st_uid != 0) || (sb.st_gid != 0) ||
                (sb.st_nlink != 1)) {
            ERROR("skipping insecure property file %s (uid=%u gid=%u nlink=%u mode=%o)\n",
                  entry->d_name, (unsigned int)sb.st_uid, (unsigned int)sb.st_gid,
                  (unsigned int)sb.st_nlink, sb.st_mode);
            close(fd);
            continue;
        }

        char value[PROP_VALUE_MAX];
        int length = read(fd, value, sizeof(value) - 1);
        if (length >= 0) {
            value[length] = 0;
            property_set(entry->d_name, value);
        } else {
            ERROR("Unable to read persistent property file %s: %s\n",
                  entry->d_name, strerror(errno));
        }
        close(fd);
    }
}

void property_load_boot_defaults() {
    load_properties_from_file(PROP_PATH_RAMDISK_DEFAULT, NULL);
}

static void load_override_properties() {
    if (ALLOW_LOCAL_PROP_OVERRIDE) {
        std::string debuggable = property_get("ro.debuggable");
        if (debuggable == "1") {
            load_properties_from_file(PROP_PATH_LOCAL_OVERRIDE, NULL);
        }
    }
}

unsigned int mt_get_chip_hw_ver(void) {
    int fd = 0;
    int ret = 0;
    char ver[32];

    fd = open("/proc/chip/hw_ver", O_RDONLY);
    if(fd < 0) {
        ERROR("Can not open hw version dev\n");
        return 0;
    }

    ret = read(fd, ver, 32);
    close(fd);
    if(ret > 0) {
        NOTICE("hw version is %s\n", ver);
        if(strncmp(ver, "CA01", 4) == 0)
            return 1;
        return 0;
    }
    ERROR("read hw version fail, ret: %d\n", ret);
    return 0;
}

/* When booting an encrypted system, /data is not mounted when the
 * property service is started, so any properties stored there are
 * not loaded.  Vold triggers init to load these properties once it
 * has mounted /data.
 */
void load_persist_props(void) {
    int ret = 0;
    std::string ro_hardware = property_get("ro.hardware");
    NOTICE("ro.hardware: %s.\n", ro_hardware.c_str());
    load_override_properties();
    /* Read persistent properties after all default values have been loaded. */
    load_persistent_properties();
    /* read efuse to check die condition */
    if (ro_hardware == "mt6757") {
        if(mt_get_chip_hw_ver() == 1) {
            NOTICE("For LTE capable chip.\n");
            ret = property_set("persist.radio.lte.chip", "1");
            if(ret < 0)
                ERROR("[PropSet] set persist.radio.lte.chip.condition fail!! \n");
        }
        else set_chip_cond_prop();
    }
}

void load_recovery_id_prop() {
    std::string ro_hardware = property_get("ro.hardware");
    if (ro_hardware.empty()) {
        ERROR("ro.hardware not set - unable to load recovery id\n");
        return;
    }
    std::string fstab_filename = FSTAB_PREFIX + ro_hardware;

    std::unique_ptr<fstab, void(*)(fstab*)> tab(fs_mgr_read_fstab(fstab_filename.c_str()),
            fs_mgr_free_fstab);
    if (!tab) {
        ERROR("unable to read fstab %s: %s\n", fstab_filename.c_str(), strerror(errno));
        return;
    }

    fstab_rec* rec = fs_mgr_get_entry_for_mount_point(tab.get(), RECOVERY_MOUNT_POINT);
    if (rec == NULL) {
        ERROR("/recovery not specified in fstab\n");
        return;
    }

    int fd = open(rec->blk_device, O_RDONLY);
    if (fd == -1) {
        ERROR("error opening block device %s: %s\n", rec->blk_device, strerror(errno));
        return;
    }

    boot_img_hdr hdr;
    if (android::base::ReadFully(fd, &hdr, sizeof(hdr))) {
        std::string hex = bytes_to_hex(reinterpret_cast<uint8_t*>(hdr.id), sizeof(hdr.id));
        property_set("ro.recovery_id", hex.c_str());
    } else {
        ERROR("error reading /recovery: %s\n", strerror(errno));
    }

    close(fd);
}

void load_system_props() {
    load_properties_from_file(PROP_PATH_SYSTEM_BUILD, NULL);
    load_properties_from_file(PROP_PATH_VENDOR_BUILD, NULL);
    load_properties_from_file(PROP_PATH_FACTORY, "ro.*");
    load_recovery_id_prop();
}

void start_property_service() {
    property_set_fd = create_socket(PROP_SERVICE_NAME, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                    0666, 0, 0, NULL);
    if (property_set_fd == -1) {
        ERROR("start_property_service socket creation failed: %s\n", strerror(errno));
        exit(1);
    }

    listen(property_set_fd, 8);

    register_epoll_handler(property_set_fd, handle_property_set_fd);
}

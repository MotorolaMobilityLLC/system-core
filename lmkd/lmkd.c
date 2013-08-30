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

#define LOG_TAG "lowmemorykiller"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <cutils/log.h>
#include <cutils/sockets.h>

#define MEMCG_SYSFS_PATH "/dev/memcg/"
#define MEMPRESSURE_WATCH_LEVEL "medium"
#define ZONEINFO_PATH "/proc/zoneinfo"
#define LINE_MAX 128

#define INKERNEL_MINFREE_PATH "/sys/module/lowmemorykiller/parameters/minfree"
#define INKERNEL_ADJ_PATH "/sys/module/lowmemorykiller/parameters/adj"

#define ARRAY_SIZE(x)   (sizeof(x) / sizeof(*(x)))

enum lmk_cmd {
    LMK_TARGET,
    LMK_PROCPRIO,
    LMK_PROCREMOVE,
};

#define MAX_TARGETS 6
/*
 * longest is LMK_TARGET followed by MAX_TARGETS each minfree and minkillprio
 * values
 */
#define CTRL_PACKET_MAX (sizeof(int) * (MAX_TARGETS * 2 + 1))

/* default to old in-kernel interface if no memory pressure events */
static int use_inkernel_interface = 1;

/* memory pressure level medium event */
static int mpevfd;

/* control socket listen and data */
static int ctrl_lfd;
static int ctrl_dfd = -1;
static int ctrl_dfd_reopened; /* did we reopen ctrl conn on this loop? */

/* 1 memory pressure level, 1 ctrl listen socket, 1 ctrl data socket */
#define MAX_EPOLL_EVENTS 3
static int epollfd;
static int maxevents;

#define OOM_DISABLE (-17)
/* inclusive */
#define OOM_ADJUST_MIN (-16)
#define OOM_ADJUST_MAX 15

static int lowmem_adj[MAX_TARGETS];
static int lowmem_minfree[MAX_TARGETS];
static int lowmem_targets_size;

struct sysmeminfo {
    int nr_free_pages;
    int nr_file_pages;
    int nr_shmem;
    int totalreserve_pages;
};

struct adjslot_list {
    struct adjslot_list *next;
    struct adjslot_list *prev;
};

struct proc {
    struct adjslot_list asl;
    int pid;
    int oomadj;
    struct proc *pidhash_next;
};

#define PIDHASH_SZ 1024
static struct proc *pidhash[PIDHASH_SZ];
#define pid_hashfn(x) ((((x) >> 8) ^ (x)) & (PIDHASH_SZ - 1))

#define ADJTOSLOT(adj) (adj + -OOM_ADJUST_MIN)
static struct adjslot_list procadjslot_list[ADJTOSLOT(OOM_ADJUST_MAX) + 1];

/*
 * Wait 1-2 seconds for the death report of a killed process prior to
 * considering killing more processes.
 */
#define KILL_TIMEOUT 2
/* Time of last process kill we initiated, stop me before I kill again */
static time_t kill_lasttime;

/* PAGE_SIZE / 1024 */
static long page_k;

static struct proc *pid_lookup(int pid) {
    struct proc *procp;

    for (procp = pidhash[pid_hashfn(pid)]; procp && procp->pid != pid;
         procp = procp->pidhash_next)
            ;

    return procp;
}

static void adjslot_insert(struct adjslot_list *head, struct adjslot_list *new)
{
    struct adjslot_list *next = head->next;
    new->prev = head;
    new->next = next;
    next->prev = new;
    head->next = new;
}

static void adjslot_remove(struct adjslot_list *old)
{
    struct adjslot_list *prev = old->prev;
    struct adjslot_list *next = old->next;
    next->prev = prev;
    prev->next = next;
}

static struct adjslot_list *adjslot_tail(struct adjslot_list *head) {
    struct adjslot_list *asl = head->prev;

    return asl == head ? NULL : asl;
}

static void proc_slot(struct proc *procp) {
    int adjslot = ADJTOSLOT(procp->oomadj);

    adjslot_insert(&procadjslot_list[adjslot], &procp->asl);
}

static void proc_unslot(struct proc *procp) {
    adjslot_remove(&procp->asl);
}

static void proc_insert(struct proc *procp) {
    int hval = pid_hashfn(procp->pid);

    procp->pidhash_next = pidhash[hval];
    pidhash[hval] = procp;
    proc_slot(procp);
}

static int pid_remove(int pid) {
    int hval = pid_hashfn(pid);
    struct proc *procp;
    struct proc *prevp;

    for (procp = pidhash[hval], prevp = NULL; procp && procp->pid != pid;
         procp = procp->pidhash_next)
            prevp = procp;

    if (!procp)
        return -1;

    if (!prevp)
        pidhash[hval] = procp->pidhash_next;
    else
        prevp->pidhash_next = procp->pidhash_next;

    proc_unslot(procp);
    free(procp);
    return 0;
}

static void writefilestring(char *path, char *s) {
    int fd = open(path, O_WRONLY);
    int len = strlen(s);
    int ret;

    if (fd < 0) {
        ALOGE("Error opening %s; errno=%d", path, errno);
        return;
    }

    ret = write(fd, s, len);
    if (ret < 0) {
        ALOGE("Error writing %s; errno=%d", path, errno);
    } else if (ret < len) {
        ALOGE("Short write on %s; length=%d", path, ret);
    }

    close(fd);
}

static void cmd_procprio(int pid, int oomadj) {
    struct proc *procp;
    char path[80];
    char val[20];

    if (oomadj < OOM_DISABLE || oomadj > OOM_ADJUST_MAX) {
        ALOGE("Invalid PROCPRIO oomadj argument %d", oomadj);
        return;
    }

    snprintf(path, sizeof(path), "/proc/%d/oom_adj", pid);
    snprintf(val, sizeof(val), "%d", oomadj);
    writefilestring(path, val);

    if (use_inkernel_interface)
        return;

    procp = pid_lookup(pid);
    if (!procp) {
            procp = malloc(sizeof(struct proc));
            if (!procp) {
                // Oh, the irony.  May need to rebuild our state.
                return;
            }

            procp->pid = pid;
            procp->oomadj = oomadj;
            proc_insert(procp);
    } else {
        proc_unslot(procp);
        procp->oomadj = oomadj;
        proc_slot(procp);
    }
}

static void cmd_procremove(int pid) {
    struct proc *procp;

    if (use_inkernel_interface)
        return;

    pid_remove(pid);
    kill_lasttime = 0;
}

static void cmd_target(int ntargets, int *params) {
    int i;

    if (ntargets > (int)ARRAY_SIZE(lowmem_adj))
        return;

    for (i = 0; i < ntargets; i++) {
        lowmem_minfree[i] = ntohl(*params++);
        lowmem_adj[i] = ntohl(*params++);
    }

    lowmem_targets_size = ntargets;

    if (use_inkernel_interface) {
        char minfreestr[128];
        char killpriostr[128];

        minfreestr[0] = '\0';
        killpriostr[0] = '\0';

        for (i = 0; i < lowmem_targets_size; i++) {
            char val[40];

            if (i) {
                strlcat(minfreestr, ",", sizeof(minfreestr));
                strlcat(killpriostr, ",", sizeof(killpriostr));
            }

            snprintf(val, sizeof(val), "%d", lowmem_minfree[i]);
            strlcat(minfreestr, val, sizeof(minfreestr));
            snprintf(val, sizeof(val), "%d", lowmem_adj[i]);
            strlcat(killpriostr, val, sizeof(killpriostr));
        }

        writefilestring(INKERNEL_MINFREE_PATH, minfreestr);
        writefilestring(INKERNEL_ADJ_PATH, killpriostr);
    }
}

static void ctrl_data_close(void) {
    ALOGI("Closing Activity Manager data connection");
    close(ctrl_dfd);
    ctrl_dfd = -1;
    maxevents--;
}

static int ctrl_data_read(char *buf, size_t bufsz) {
    int ret = 0;

    ret = read(ctrl_dfd, buf, bufsz);

    if (ret == -1) {
        ALOGE("control data socket read failed; errno=%d", errno);
    } else if (ret == 0) {
        ALOGE("Got EOF on control data socket");
        ret = -1;
    }

    return ret;
}

static void ctrl_command_handler(void) {
    int ibuf[CTRL_PACKET_MAX / sizeof(int)];
    int len;
    int cmd = -1;
    int nargs;
    int targets;

    len = ctrl_data_read((char *)ibuf, CTRL_PACKET_MAX);
    if (len <= 0)
        return;

    nargs = len / sizeof(int) - 1;
    if (nargs < 0)
        goto wronglen;

    cmd = ntohl(ibuf[0]);

    switch(cmd) {
    case LMK_TARGET:
        targets = nargs / 2;
        if (nargs & 0x1 || targets > (int)ARRAY_SIZE(lowmem_adj))
            goto wronglen;
        cmd_target(targets, &ibuf[1]);
        break;
    case LMK_PROCPRIO:
        if (nargs != 2)
            goto wronglen;
        cmd_procprio(ntohl(ibuf[1]), ntohl(ibuf[2]));
        break;
    case LMK_PROCREMOVE:
        if (nargs != 1)
            goto wronglen;
        cmd_procremove(ntohl(ibuf[1]));
        break;
    default:
        ALOGE("Received unknown command code %d", cmd);
        return;
    }

    return;

wronglen:
    ALOGE("Wrong control socket read length cmd=%d len=%d", cmd, len);
}

static void ctrl_data_handler(uint32_t events) {
    if (events & EPOLLHUP) {
        ALOGI("ActivityManager disconnected");
        if (!ctrl_dfd_reopened)
            ctrl_data_close();
    } else if (events & EPOLLIN) {
        ctrl_command_handler();
    }
}

static void ctrl_connect_handler(uint32_t events) {
    struct sockaddr addr;
    socklen_t alen;
    struct epoll_event epev;

    if (ctrl_dfd >= 0) {
        ctrl_data_close();
        ctrl_dfd_reopened = 1;
    }

    alen = sizeof(addr);
    ctrl_dfd = accept(ctrl_lfd, &addr, &alen);

    if (ctrl_dfd < 0) {
        ALOGE("lmkd control socket accept failed; errno=%d", errno);
        return;
    }

    ALOGI("ActivityManager connected");
    maxevents++;
    epev.events = EPOLLIN;
    epev.data.ptr = (void *)ctrl_data_handler;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctrl_dfd, &epev) == -1) {
        ALOGE("epoll_ctl for data connection socket failed; errno=%d", errno);
        ctrl_data_close();
        return;
    }
}

static int zoneinfo_parse_protection(char *cp) {
    int max = 0;
    int zoneval;

    if (*cp++ != '(')
        return 0;

    do {
        zoneval = strtol(cp, &cp, 0);
        if ((*cp != ',') && (*cp != ')'))
            return 0;
        if (zoneval > max)
            max = zoneval;
    } while (cp = strtok(NULL, " "));

    return max;
}

static void zoneinfo_parse_line(char *line, struct sysmeminfo *mip) {
    char *cp = line;
    char *ap;

    cp = strtok(line, " ");
    if (!cp)
        return;

    ap = strtok(NULL, " ");
    if (!ap)
        return;

    if (!strcmp(cp, "nr_free_pages"))
        mip->nr_free_pages += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "nr_file_pages"))
        mip->nr_file_pages += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "nr_shmem"))
        mip->nr_shmem += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "high"))
        mip->totalreserve_pages += strtol(ap, NULL, 0);
    else if (!strcmp(cp, "protection:"))
        mip->totalreserve_pages += zoneinfo_parse_protection(ap);
}

static int zoneinfo_parse(struct sysmeminfo *mip) {
    FILE *f;
    char *cp;
    char line[LINE_MAX];

    memset(mip, 0, sizeof(struct sysmeminfo));
    f = fopen(ZONEINFO_PATH, "r");
    if (!f) {
        ALOGE("%s open: errno=%d", ZONEINFO_PATH, errno);
        return -1;
    }

    while (fgets(line, LINE_MAX, f))
            zoneinfo_parse_line(line, mip);

    fclose(f);
    return 0;
}

static int proc_get_size(int pid) {
    char path[PATH_MAX];
    char line[LINE_MAX];
    FILE *f;
    int rss = 0;
    int total;

    snprintf(path, PATH_MAX, "/proc/%d/statm", pid);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (!fgets(line, LINE_MAX, f)) {
        fclose(f);
        return -1;
    }

    sscanf(line, "%d %d ", &total, &rss);
    fclose(f);
    return rss;
}

static char *proc_get_name(int pid) {
    char path[PATH_MAX];
    static char line[LINE_MAX];
    FILE *f;
    char *cp;

    snprintf(path, PATH_MAX, "/proc/%d/cmdline", pid);
    f = fopen(path, "r");
    if (!f)
        return NULL;
    if (!fgets(line, LINE_MAX, f)) {
        fclose(f);
        return NULL;
    }

    cp = strchr(line, ' ');
    if (cp)
        *cp = '\0';

    return line;
}

static struct proc *proc_adj_lru(int oomadj) {
    return (struct proc *)adjslot_tail(&procadjslot_list[ADJTOSLOT(oomadj)]);
}

static void mp_event(uint32_t events) {
    int i;
    int ret;
    unsigned long long evcount;
    struct sysmeminfo mi;
    int other_free;
    int other_file;
    int minfree = 0;
    int min_score_adj = OOM_ADJUST_MAX + 1;

    ret = read(mpevfd, &evcount, sizeof(evcount));
    if (ret < 0)
        ALOGE("Error reading memory pressure event fd; errno=%d",
              errno);

    if (time(NULL) - kill_lasttime < KILL_TIMEOUT)
        return;

    if (zoneinfo_parse(&mi) < 0)
        return;

    other_free = mi.nr_free_pages - mi.totalreserve_pages;
    other_file = mi.nr_file_pages - mi.nr_shmem;

    for (i = 0; i < lowmem_targets_size; i++) {
        minfree = lowmem_minfree[i];
        if (other_free < minfree && other_file < minfree) {
            min_score_adj = lowmem_adj[i];
            break;
        }
    }

    if (min_score_adj == OOM_ADJUST_MAX + 1)
        return;

    for (i = OOM_ADJUST_MAX; i >= min_score_adj; i--) {
        struct proc *procp;

    retry:
        procp = proc_adj_lru(i);

        if (procp) {
            int pid = procp->pid;
            char *taskname;
            int tasksize;
            int r;

            taskname = proc_get_name(pid);
            if (!taskname) {
                pid_remove(pid);
                goto retry;
            }

            tasksize = proc_get_size(pid);
            if (tasksize < 0) {
                pid_remove(pid);
                goto retry;
            }

            ALOGI("Killing '%s' (%d), adj %d\n"
                  "   to free %ldkB because cache %ldkB is below limit %ldkB for oom_adj %d\n"
                  "   Free memory is %ldkB %s reserved",
                  taskname, pid, procp->oomadj, tasksize * page_k,
                  other_file * page_k, minfree * page_k, min_score_adj,
                  other_free * page_k, other_free >= 0 ? "above" : "below");
            r = kill(pid, SIGKILL);
            pid_remove(pid);

            if (r) {
                ALOGE("kill(%d): errno=%d", procp->pid, errno);
                goto retry;
            } else {
                time(&kill_lasttime);
                break;
            }
        }
    }
}

static int init_mp(char *levelstr, void *event_handler)
{
    int mpfd;
    int evfd;
    int evctlfd;
    char buf[256];
    struct epoll_event epev;
    int ret;

    mpfd = open(MEMCG_SYSFS_PATH "memory.pressure_level", O_RDONLY);
    if (mpfd < 0) {
        ALOGI("No kernel memory.pressure_level support (errno=%d)", errno);
        goto err_open_mpfd;
    }

    evctlfd = open(MEMCG_SYSFS_PATH "cgroup.event_control", O_WRONLY);
    if (evctlfd < 0) {
        ALOGI("No kernel memory cgroup event control (errno=%d)", errno);
        goto err_open_evctlfd;
    }

    evfd = eventfd(0, EFD_NONBLOCK);
    if (evfd < 0) {
        ALOGE("eventfd failed for level %s; errno=%d", levelstr, errno);
        goto err_eventfd;
    }

    ret = snprintf(buf, sizeof(buf), "%d %d %s", evfd, mpfd, levelstr);
    if (ret >= (ssize_t)sizeof(buf)) {
        ALOGE("cgroup.event_control line overflow for level %s", levelstr);
        goto err;
    }

    ret = write(evctlfd, buf, strlen(buf) + 1);
    if (ret == -1) {
        ALOGE("cgroup.event_control write failed for level %s; errno=%d",
              levelstr, errno);
        goto err;
    }

    epev.events = EPOLLIN;
    epev.data.ptr = event_handler;
    ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, evfd, &epev);
    if (ret == -1) {
        ALOGE("epoll_ctl for level %s failed; errno=%d", levelstr, errno);
        goto err;
    }
    maxevents++;
    mpevfd = evfd;
    return 0;

err:
    close(evfd);
err_eventfd:
    close(evctlfd);
err_open_evctlfd:
    close(mpfd);
err_open_mpfd:
    return -1;
}

static int init(void) {
    struct epoll_event epev;
    int i;
    int ret;

    page_k = sysconf(_SC_PAGESIZE);
    if (page_k == -1)
        page_k = PAGE_SIZE;
    page_k /= 1024;

    epollfd = epoll_create(MAX_EPOLL_EVENTS);
    if (epollfd == -1) {
        ALOGE("epoll_create failed (errno=%d)", errno);
        return -1;
    }

    ctrl_lfd = android_get_control_socket("lmkd");
    if (ctrl_lfd < 0) {
        ALOGE("get lmkd control socket failed");
        return -1;
    }

    ret = listen(ctrl_lfd, 1);
    if (ret < 0) {
        ALOGE("lmkd control socket listen failed (errno=%d)", errno);
        return -1;
    }

    epev.events = EPOLLIN;
    epev.data.ptr = (void *)ctrl_connect_handler;
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ctrl_lfd, &epev) == -1) {
        ALOGE("epoll_ctl for lmkd control socket failed (errno=%d)", errno);
        return -1;
    }
    maxevents++;

    use_inkernel_interface = !access(INKERNEL_MINFREE_PATH, W_OK);

    if (use_inkernel_interface) {
        ALOGI("Using in-kernel low memory killer interface");
    } else {
        ret = init_mp(MEMPRESSURE_WATCH_LEVEL, (void *)&mp_event);
        if (ret)
            ALOGE("Kernel does not support memory pressure events or in-kernel low memory killer");
    }

    for (i = 0; i <= ADJTOSLOT(OOM_ADJUST_MAX); i++) {
        procadjslot_list[i].next = &procadjslot_list[i];
        procadjslot_list[i].prev = &procadjslot_list[i];
    }

    return 0;
}

static void mainloop(void) {
    while (1) {
        struct epoll_event events[maxevents];
        int nevents;
        int i;

        ctrl_dfd_reopened = 0;
        nevents = epoll_wait(epollfd, events, maxevents, -1);

        if (nevents == -1) {
            if (errno == EINTR)
                continue;
            ALOGE("epoll_wait failed (errno=%d)", errno);
            continue;
        }

        for (i = 0; i < nevents; ++i) {
            if (events[i].events & EPOLLERR)
                ALOGD("EPOLLERR on event #%d", i);
            if (events[i].data.ptr)
                (*(void (*)(uint32_t))events[i].data.ptr)(events[i].events);
        }
    }
}

int main(int argc, char **argv) {
    if (!init())
        mainloop();

    ALOGI("exiting");
    return 0;
}

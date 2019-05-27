#define LOG_TAG "lowmemorykiller"
#define LOG_NDEBUG 0

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/netlink.h>

#include <utils/Timers.h>
#include <cutils/properties.h>
#include <cutils/sockets.h>
#include <cutils/log.h>

#define LMFS_NETLINK_PROTO NETLINK_USERSOCK
#define LMFS_NETLINK_GROUP 21
#define LMFS_NETLINK_MAX_NAME_LENGTH 100
#define MEMINFO_PATH "/proc/meminfo"
#define MAX_SWAPUSAGE_MEDIEM 60
#define MAX_SWAPUSAGE_CRITIAL 70
#define SWAP_KILL_ADJ 800
#define VMPRESSURE_INTERVAL  1000

extern void find_and_kill_process_adj(int adj, bool critial);
extern ssize_t read_all(int fd, char *buf, size_t max_len);

struct meminfo{
    int free;
    int cached;
    int mapped;
    int swaptotal;
    int swapfree;
};

struct killed_app_info{
    int uid;
    int pid;
    int adj;
};

struct usr_msg {
    int what;
    union {
        struct killed_app_info app;
        int vmpressure;
    };
};

static int lmfs_netlink_socket;
static int lmfs_unix_socket;
static int lmfs_vmpressure_socket;
static int lmfs_vmpressure_client_socket;
static int lmfs_epoll_fd;
static int lmfs_unix_client_socket;
static int lmfs_swap_kill_adj;
static int lmfs_max_swap_usage;
static int vmpressure_enhanced;
static int64_t vmpressure_last_notify_time = -1;

static void handle_lmfs_unix_socket_connect(){
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    if(lmfs_unix_client_socket > 0){
        close(lmfs_unix_client_socket);
    }
    lmfs_unix_client_socket = accept(lmfs_unix_socket,&addr,&len);

    if(lmfs_unix_client_socket < 0) {
        ALOGE("lmfs control socket can't accept,err=%d",errno);
        lmfs_unix_client_socket = 0;
        return;
    }
    ALOGD("unix socket is connected:%d",lmfs_unix_client_socket);
}
void notify_lmfs_process_killed(int pid) {
    char buffer[10];

    memset(buffer,0,sizeof(buffer));
    int nameLen = 0;

    if(lmfs_unix_client_socket > 0) {
        nameLen = snprintf(buffer,9,"%d", pid);
        if (nameLen < 0) {
            return;
        }
        buffer[nameLen]='\n';
        write(lmfs_unix_client_socket,buffer,nameLen+1);
        ALOGD("handle notify_lmfs_process_killed done for %d", pid);
    }

}
static void handle_killing(struct killed_app_info* app_info){
    char buffer[10];

    memset(buffer,0,sizeof(buffer));
    int nameLen = 0;

    if(lmfs_unix_client_socket > 0) {
        nameLen = snprintf(buffer,9,"%d",app_info->pid);
        if (nameLen < 0) {
            return;
        }
        buffer[nameLen]='\n';
        write(lmfs_unix_client_socket,buffer,nameLen+1);
    }
    ALOGD("handle killing  %d done", app_info->pid);
}

static void meminfo_parse_line(char *line, struct meminfo *mip) {
    char *cp = line;
    char *ap;
    char *save_ptr;

    cp = strtok_r(line, " ", &save_ptr);
    if (!cp)
        return;

    ap = strtok_r(NULL, " ", &save_ptr);
    if (!ap)
        return;

    if (!strcmp(cp, "MemFree:"))
        mip->free = strtol(ap, NULL, 0);
    else if (!strcmp(cp, "Cached:"))
        mip->cached = strtol(ap, NULL, 0);
    else if (!strcmp(cp, "SwapTotal:"))
        mip->swaptotal = strtol(ap, NULL, 0);
    else if (!strcmp(cp, "SwapFree:"))
        mip->swapfree = strtol(ap, NULL, 0);
    else if (!strcmp(cp, "Mapped:"))
        mip->mapped = strtol(ap, NULL, 0);
}

static int meminfo_parse(struct meminfo *mip) {
    int fd;
    ssize_t size;
    char buf[PAGE_SIZE];
    char *save_ptr;
    char *line;

    memset(mip, 0, sizeof(struct meminfo));

    fd = open(MEMINFO_PATH, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        ALOGE("%s open: errno=%d", MEMINFO_PATH, errno);
        return -1;
    }

    size = read_all(fd, buf, sizeof(buf) - 1);
    if (size < 0) {
        ALOGE("%s read: errno=%d", MEMINFO_PATH, errno);
        close(fd);
        return -1;
    }
    ALOG_ASSERT((size_t)size < sizeof(buf) - 1, "/proc/meminfo too large");
    buf[size] = 0;

    for (line = strtok_r(buf, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr))
            meminfo_parse_line(line, mip);

    close(fd);
    return 0;
}

void handle_vmpressure(int vmpressure) {
    struct meminfo mi;
    int swapusage;
    int nameLen = 0;
    char buffer[10];
    if (vmpressure < 70 || meminfo_parse(&mi) < 0) {
        return;
    }
    int64_t now = (int64_t) nanoseconds_to_milliseconds(systemTime(SYSTEM_TIME_MONOTONIC));
    if (vmpressure_last_notify_time != -1 && (now - vmpressure_last_notify_time) < VMPRESSURE_INTERVAL) {
        return;
    }
    vmpressure_last_notify_time = now;
    if (mi.swaptotal != 0) {
        swapusage = ((mi.swaptotal - mi.swapfree) * 100) /mi.swaptotal;
        if (swapusage > lmfs_max_swap_usage) {
            //we add this to avoid situation that swapusage almost 100,but cached > adj_900
            // kill adj 800
            ALOGD("handle_vmpressure %d current cache %d  swapfree  %d",
            vmpressure, mi.cached, mi.swapfree);
            //use force-stop lru instead of  killing adj_800 by default:
            memset(buffer, 0, sizeof(buffer));
            if (lmfs_vmpressure_client_socket > 0) {
                nameLen = snprintf(buffer, 9, "%d %d", swapusage, vmpressure);
                if (nameLen < 0) {
                    return;
                }
                buffer[nameLen]='\n';
                write(lmfs_vmpressure_client_socket, buffer, nameLen+1);
            } else {
                find_and_kill_process_adj(lmfs_swap_kill_adj, true);
            }
        }
    }
}

static void handle_lmfs_netlink_socket_action(){
    struct sockaddr_nl addr;
    struct msghdr msg;
    struct iovec vec;
    char buff[200];
    int ret;
    struct killed_app_info app_info;
    struct usr_msg* usr_msg;

    vec.iov_base=(void*)buff;
    vec.iov_len=sizeof(buff);
    msg.msg_name=(void*)&addr;
    msg.msg_namelen=sizeof(addr);
    msg.msg_iov=&vec;
    msg.msg_iovlen=1;

    ret=recvmsg(lmfs_netlink_socket,&msg,0);
    if(ret < 0){
        ALOGE("lmfs netlink recv error,err=%d",errno);
    }else{
        //app_info=(struct killed_app_info*)NLMSG_DATA((struct nlmsghdr*)buff);
        usr_msg = (struct usr_msg *)NLMSG_DATA((struct nlmsghdr*)buff);
        switch (usr_msg->what) {
            case 0:
                app_info = usr_msg->app;
                ALOGD("received lmk:%d,%d,%d\n", app_info.uid,app_info.pid,app_info.adj);
                handle_killing(&app_info);
                break;
            case 1:
                handle_vmpressure(usr_msg->vmpressure);
                break;
            default:
                break;
        }

    }
}

static int lmfs_init_netlink_socket(){
    struct sockaddr_nl addr;
    int group = LMFS_NETLINK_GROUP;
    struct epoll_event event;

    lmfs_netlink_socket = socket(AF_NETLINK,SOCK_RAW,LMFS_NETLINK_PROTO);
    if(lmfs_netlink_socket < 0){
        ALOGE("can't create lmfs netlink socket,err=%d",errno);
        return 0;
    }

    memset(&addr,0,sizeof(struct sockaddr_nl));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();

    if(bind(lmfs_netlink_socket,(struct sockaddr*)&addr,sizeof(addr)) < 0){
        ALOGE("can't bind lmfs netlink socket,err=%d",errno);
        return 0;
    }

    if(setsockopt(lmfs_netlink_socket,270,NETLINK_ADD_MEMBERSHIP,&group,sizeof(group)) < 0){
        ALOGE("can't add lmfs netlink socket to group,err=%d",errno);
        return 0;
    }

    event.events = EPOLLIN;
    event.data.ptr = (void*)handle_lmfs_netlink_socket_action;

    if(epoll_ctl(lmfs_epoll_fd,EPOLL_CTL_ADD,lmfs_netlink_socket,&event) < 0){
        ALOGE("can't add lmfs netlink socket to epoll,err=%d",errno);
        return 0;
    }
    return 1;
}

static int lmfs_init_unix_socket(){
    int rv = 0;
    struct epoll_event event;
    lmfs_unix_socket = android_get_control_socket("lmfs");
    if(lmfs_unix_socket < 0){
        ALOGE("can't get lmfs socket");
        return 0;
    }

    rv = listen(lmfs_unix_socket,1);
    if(rv < -1){
        ALOGE("lmfs can't listen,err=%d",errno);
        return 0;
    }

    event.events = EPOLLIN;
    event.data.ptr = (void*)handle_lmfs_unix_socket_connect;
    if(epoll_ctl(lmfs_epoll_fd,EPOLL_CTL_ADD,lmfs_unix_socket,&event) < 0){
        ALOGE("can't add lmfs to epoll,err=%d",errno);
        return 0;
    }
    return 1;
}

static void handle_lmfs_vmpressure_socket_connect() {
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    if(lmfs_vmpressure_client_socket > 0){
        close(lmfs_vmpressure_client_socket);
    }
    lmfs_vmpressure_client_socket = accept(lmfs_vmpressure_socket, &addr, &len);

    if(lmfs_vmpressure_client_socket < 0) {
        ALOGE("lmfs control socket can't accept vmpressure ,err=%d",errno);
        lmfs_vmpressure_client_socket = 0;
        return;
    }
    ALOGD("vmpressure socket is connected:%d", lmfs_vmpressure_client_socket);
}

static int lmfs_init_vmpressure_socket() {
    int rv = 0;
    struct epoll_event event;
    lmfs_vmpressure_socket = android_get_control_socket("vmpressure");
    if(lmfs_vmpressure_socket < 0) {
        ALOGE("can't get lmfs vmpressure socket");
        return 0;
    }

    rv = listen(lmfs_vmpressure_socket, 1);
    if(rv < -1){
        ALOGE("lmfs can't listen,err=%d", errno);
        return 0;
    }

    event.events = EPOLLIN;
    event.data.ptr = (void*)handle_lmfs_vmpressure_socket_connect;
    if(epoll_ctl(lmfs_epoll_fd, EPOLL_CTL_ADD, lmfs_vmpressure_socket, &event) < 0){
        ALOGE("can't add lmfs vmpressure to epoll,err=%s", strerror(errno));
        return 0;
    }
    return 1;
}

static int lmfs_init_epoll(){
    lmfs_epoll_fd = epoll_create(2);
    if (lmfs_epoll_fd == -1) {
        ALOGE("epoll create failed (errno=%d)\n",errno);
        return 0;
    }
    return 1;
}

static int lmfs_init(){
    int ret = 1;
    lmfs_max_swap_usage = property_get_int32("ro.lmk.swapusage", MAX_SWAPUSAGE_CRITIAL);
    lmfs_swap_kill_adj = property_get_int32("ro.lmk.swapkilladj", SWAP_KILL_ADJ);
    vmpressure_enhanced = property_get_bool("ro.lmk.vmpressurenhanced", false);
    ALOGD("lmfs_init lmfs_max_swap_usage=  %d, lmfs_swap_kill_adj = %d, vmpressure_enhanced = %d ",
       lmfs_max_swap_usage, lmfs_swap_kill_adj, vmpressure_enhanced);
    ret = lmfs_init_epoll();
    ret &= lmfs_init_netlink_socket();
    ret &= lmfs_init_unix_socket();
    ret &= lmfs_init_vmpressure_socket();
    return ret;
}

static void lmfs_loop(){
    while(1){
        struct epoll_event events[2];
        int nr_events;
        int i;
        nr_events = epoll_wait(lmfs_epoll_fd,events,2,-1);

        if(nr_events == -1) continue;

        for(i=0;i<nr_events;i++){
            if(events[i].events & EPOLLERR){
                ALOGE("epoll error on event #%d",i);
            }

            if(events[i].data.ptr){
                (*(void(*)())events[i].data.ptr)();
            }
        }

    }
}

void lmfs_main(){
    mlockall(MCL_FUTURE);
    lmfs_init();
    lmfs_loop();
    ALOGE("quit lmfs");
}
//on go devices,lmkd ----->lmfs---->ams
//on MR1 devices kernel ---->lmfs---->ams
void start_lmfs(void) {
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, (void*)lmfs_main, NULL) < 0) {
        ALOGE("Failed to create lmfs thread!");
    }
}
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <fcntl.h>

#include <string.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>

#include <pwd.h>

#include <cutils/sched_policy.h>

static char *nexttoksep(char **strp, char *sep)
{
    char *p = strsep(strp,sep);
    return (p == 0) ? "" : p;
}
static char *nexttok(char **strp)
{
    return nexttoksep(strp, " ");
}

#define SHOW_PRIO 1
#define SHOW_TIME 2
#define SHOW_POLICY 4
#define SHOW_CPU  8
#define SHOW_MACLABEL 16
#define SHOW_ABI 32

static int display_flags = 0;

static void print_exe_abi(int pid);

static int ps_line(int pid, int tid, char *namefilter)
{
    char statline[1024];
    char cmdline[1024];
    char macline[1024];
    char user[32];
    struct stat stats;
    int fd, r;
    char *ptr, *name, *state;
    int ppid, tty;
    unsigned wchan, rss, vss, eip;
    unsigned utime, stime;
    int prio, nice, rtprio, sched, psr;
    struct passwd *pw;
    
    sprintf(statline, "/proc/%d", pid);
    stat(statline, &stats);

    if(tid) {
        sprintf(statline, "/proc/%d/task/%d/stat", pid, tid);
        cmdline[0] = 0;
        snprintf(macline, sizeof(macline), "/proc/%d/task/%d/attr/current", pid, tid);
    } else {
        sprintf(statline, "/proc/%d/stat", pid);
        sprintf(cmdline, "/proc/%d/cmdline", pid);
        snprintf(macline, sizeof(macline), "/proc/%d/attr/current", pid);
        fd = open(cmdline, O_RDONLY);
        if(fd == 0) {
            r = 0;
        } else {
            r = read(fd, cmdline, 1023);
            close(fd);
            if(r < 0) r = 0;
        }
        cmdline[r] = 0;
    }
    
    fd = open(statline, O_RDONLY);
    if(fd == 0) return -1;
    r = read(fd, statline, 1023);
    close(fd);
    if(r < 0) return -1;
    statline[r] = 0;

    ptr = statline;
    nexttok(&ptr); // skip pid
    ptr++;          // skip "("

    name = ptr;
    ptr = strrchr(ptr, ')'); // Skip to *last* occurence of ')',
    *ptr++ = '\0';           // and null-terminate name.

    ptr++;          // skip " "
    state = nexttok(&ptr);
    ppid = atoi(nexttok(&ptr));
    nexttok(&ptr); // pgrp
    nexttok(&ptr); // sid
    tty = atoi(nexttok(&ptr));
    
    nexttok(&ptr); // tpgid
    nexttok(&ptr); // flags
    nexttok(&ptr); // minflt
    nexttok(&ptr); // cminflt
    nexttok(&ptr); // majflt
    nexttok(&ptr); // cmajflt
#if 1
    utime = atoi(nexttok(&ptr));
    stime = atoi(nexttok(&ptr));
#else
    nexttok(&ptr); // utime
    nexttok(&ptr); // stime
#endif
    nexttok(&ptr); // cutime
    nexttok(&ptr); // cstime
    prio = atoi(nexttok(&ptr));
    nice = atoi(nexttok(&ptr));
    nexttok(&ptr); // threads
    nexttok(&ptr); // itrealvalue
    nexttok(&ptr); // starttime
    vss = strtoul(nexttok(&ptr), 0, 10); // vsize
    rss = strtoul(nexttok(&ptr), 0, 10); // rss
    nexttok(&ptr); // rlim
    nexttok(&ptr); // startcode
    nexttok(&ptr); // endcode
    nexttok(&ptr); // startstack
    nexttok(&ptr); // kstkesp
    eip = strtoul(nexttok(&ptr), 0, 10); // kstkeip
    nexttok(&ptr); // signal
    nexttok(&ptr); // blocked
    nexttok(&ptr); // sigignore
    nexttok(&ptr); // sigcatch
    wchan = strtoul(nexttok(&ptr), 0, 10); // wchan
    nexttok(&ptr); // nswap
    nexttok(&ptr); // cnswap
    nexttok(&ptr); // exit signal
    psr = atoi(nexttok(&ptr)); // processor
    rtprio = atoi(nexttok(&ptr)); // rt_priority
    sched = atoi(nexttok(&ptr)); // scheduling policy
    
    tty = atoi(nexttok(&ptr));
    
    if(tid != 0) {
        ppid = pid;
        pid = tid;
    }

    pw = getpwuid(stats.st_uid);
    if(pw == 0) {
        sprintf(user,"%d",(int)stats.st_uid);
    } else {
        strcpy(user,pw->pw_name);
    }
    
    if(!namefilter || !strncmp(name, namefilter, strlen(namefilter))) {
        if (display_flags & SHOW_MACLABEL) {
            fd = open(macline, O_RDONLY);
            strcpy(macline, "-");
            if (fd >= 0) {
                r = read(fd, macline, sizeof(macline)-1);
                close(fd);
                if (r > 0)
                    macline[r] = 0;
            }
            printf("%-30s %-9s %-5d %-5d %s\n", macline, user, pid, ppid, cmdline[0] ? cmdline : name);
            return 0;
        }

        printf("%-9s %-5d %-5d %-6d %-5d", user, pid, ppid, vss / 1024, rss * 4);
        if (display_flags & SHOW_CPU)
            printf(" %-2d", psr);
        if (display_flags & SHOW_PRIO)
            printf(" %-5d %-5d %-5d %-5d", prio, nice, rtprio, sched);
        if (display_flags & SHOW_POLICY) {
            SchedPolicy p;
            if (get_sched_policy(pid, &p) < 0)
                printf(" un ");
            else
                printf(" %.2s ", get_sched_policy_name(p));
        }
        printf(" %08x %08x %s ", wchan, eip, state);
        if (display_flags & SHOW_ABI) {
            print_exe_abi(pid);
        }
        printf("%s", cmdline[0] ? cmdline : name);
        if(display_flags&SHOW_TIME)
            printf(" (u:%d, s:%d)", utime, stime);

        printf("\n");
    }
    return 0;
}

static void print_exe_abi(int pid)
{
    int fd, r;
    char exeline[1024];

    sprintf(exeline, "/proc/%d/exe", pid);
    fd = open(exeline, O_RDONLY);
    if(fd == 0) {
        printf("    ");
        return;
    }
    r = read(fd, exeline, 5 /* 4 byte ELFMAG + 1 byte EI_CLASS */);
    close(fd);
    if(r < 0) {
        printf("    ");
        return;
    }
    if (memcmp("\177ELF", exeline, 4) != 0) {
        printf("??  ");
        return;
    }
    switch (exeline[4]) {
        case 1:
            printf("32  ");
            return;
        case 2:
            printf("64  ");
            return;
        default:
            printf("??  ");
            return;
    }
}

void ps_threads(int pid, char *namefilter)
{
    char tmp[128];
    DIR *d;
    struct dirent *de;

    sprintf(tmp,"/proc/%d/task",pid);
    d = opendir(tmp);
    if(d == 0) return;
    
    while((de = readdir(d)) != 0){
        if(isdigit(de->d_name[0])){
            int tid = atoi(de->d_name);
            if(tid == pid) continue;
            ps_line(pid, tid, namefilter);
        }
    }
    closedir(d);    
}

int ps_main(int argc, char **argv)
{
    DIR *d;
    struct dirent *de;
    char *namefilter = 0;
    int pidfilter = 0;
    int threads = 0;
    
    d = opendir("/proc");
    if(d == 0) return -1;

    while(argc > 1){
        if(!strcmp(argv[1],"-t")) {
            threads = 1;
        } else if(!strcmp(argv[1],"-x")) {
            display_flags |= SHOW_TIME;
        } else if(!strcmp(argv[1], "-Z")) {
            display_flags |= SHOW_MACLABEL;
        } else if(!strcmp(argv[1],"-P")) {
            display_flags |= SHOW_POLICY;
        } else if(!strcmp(argv[1],"-p")) {
            display_flags |= SHOW_PRIO;
        } else if(!strcmp(argv[1],"-c")) {
            display_flags |= SHOW_CPU;
        } else if(!strcmp(argv[1],"--abi")) {
            display_flags |= SHOW_ABI;
        } else if(isdigit(argv[1][0])){
            pidfilter = atoi(argv[1]);
        } else {
            namefilter = argv[1];
        }
        argc--;
        argv++;
    }

    if (display_flags & SHOW_MACLABEL) {
        printf("LABEL                          USER     PID   PPID  NAME\n");
    } else {
        printf("USER     PID   PPID  VSIZE  RSS   %s%s %s WCHAN    PC        %sNAME\n",
               (display_flags&SHOW_CPU)?"CPU ":"",
               (display_flags&SHOW_PRIO)?"PRIO  NICE  RTPRI SCHED ":"",
               (display_flags&SHOW_POLICY)?"PCY " : "",
               (display_flags&SHOW_ABI)?"ABI " : "");
    }
    while((de = readdir(d)) != 0){
        if(isdigit(de->d_name[0])){
            int pid = atoi(de->d_name);
            if(!pidfilter || (pidfilter == pid)) {
                ps_line(pid, 0, namefilter);
                if(threads) ps_threads(pid, namefilter);
            }
        }
    }
    closedir(d);
    return 0;
}


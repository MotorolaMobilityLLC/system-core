/*
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <errno.h>
#include <dirent.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netutils/dhcp.h>
#include <netutils/ifc.h>
#include <stdio.h>
#include <stdlib.h>

void die(const char *reason)
{
    perror(reason);
    exit(1);
}

const char *ipaddr(in_addr_t addr)
{
    struct in_addr in_addr;

    in_addr.s_addr = addr;
    return inet_ntoa(in_addr);
}

void usage(void)
{
    fprintf(stderr,"usage: netcfg [<interface> {dhcp|up|down}]\n");
    exit(1);
}

int dump_interface(const char *name)
{
    unsigned addr, flags;
    unsigned char hwbuf[ETH_ALEN];
    int prefixLength;

    if(ifc_get_info(name, &addr, &prefixLength, &flags)) {
        return 0;
    }

    printf("%-8s %s  ", name, flags & 1 ? "UP  " : "DOWN");
    printf("%40s", ipaddr(addr));
    printf("/%-4d", prefixLength);
    printf("0x%08x ", flags);
    if (!ifc_get_hwaddr(name, hwbuf)) {
        int i;
        for(i=0; i < (ETH_ALEN-1); i++)
            printf("%02x:", hwbuf[i]);
        printf("%02x\n", hwbuf[i]);
    } else {
        printf("\n");
    }
    return 0;
}

int dump_interfaces(void)
{
    DIR *d;
    struct dirent *de;

    d = opendir("/sys/class/net");
    if(d == 0) return -1;

    while((de = readdir(d))) {
        if(de->d_name[0] == '.') continue;
        dump_interface(de->d_name);
    }
    closedir(d);
    return 0;
}

int set_hwaddr(const char *name, const char *asc) {
    struct ether_addr *addr = ether_aton(asc);
    if (!addr) {
        printf("Failed to parse '%s'\n", asc);
        return -1;
    }
    return ifc_set_hwaddr(name, addr->ether_addr_octet);
}

struct 
{
    const char *name;
    int nargs;
    void *func;
} CMDS[] = {
    { "dhcp",   1, do_dhcp },
    { "up",     1, ifc_up },
    { "down",   1, ifc_down },
    { "deldefault", 1, ifc_remove_default_route },
    { "hwaddr", 2, set_hwaddr },
    { 0, 0, 0 },
};

static int call_func(void *_func, unsigned nargs, char **args)
{
    switch(nargs){
    case 1: {
        int (*func)(char *a0) = _func;
        return func(args[0]);
    }
    case 2: {
        int (*func)(char *a0, char *a1) = _func;
        return func(args[0], args[1]);
    }
    case 3: {
        int (*func)(char *a0, char *a1, char *a2) = _func;
        return func(args[0], args[1], args[2]);
    }
    default:
        return -1;
    }
}

int main(int argc, char **argv)
{
    char *iname;
    int n;
    
    if(ifc_init()) {
        die("Cannot perform requested operation");
    }

    if(argc == 1) {
        int result = dump_interfaces();
        ifc_close();
        return result;
    }

    if(argc < 3) usage();

    iname = argv[1];
    if(strlen(iname) > 16) usage();

    argc -= 2;
    argv += 2;
    while(argc > 0) {
        for(n = 0; CMDS[n].name; n++){
            if(!strcmp(argv[0], CMDS[n].name)) {
                char *cmdname = argv[0];
                int nargs = CMDS[n].nargs;
                
                argv[0] = iname;
                if(argc < nargs) {
                    fprintf(stderr, "not enough arguments for '%s'\n", cmdname);
                    ifc_close();
                    exit(1);
                }
                if(call_func(CMDS[n].func, nargs, argv)) {
                    fprintf(stderr, "action '%s' failed (%s)\n", cmdname, strerror(errno));
                    ifc_close();
                    exit(1);
                }
                argc -= nargs;
                argv += nargs;
                goto done;
            }
        }
        fprintf(stderr,"no such action '%s'\n", argv[0]);
        usage();
    done:
        ;
    }
    ifc_close();

    return 0;
}

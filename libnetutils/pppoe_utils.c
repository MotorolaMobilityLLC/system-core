/*
 * Copyright 2008, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 *
 *     http://www.apache.org/licenses/LICENSE-2.0 
 *
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */

/* Utilities for managing the dhcpcd DHCP client daemon */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <cutils/properties.h>
#include <errno.h>
#include <fcntl.h>

#ifdef ANDROID
#define LOG_TAG "PPPOEUtils"
#include <cutils/log.h>
#else
#include <stdio.h>
#include <string.h>
#define ALOGD printf
#define ALOGE printf
#endif

static const char PPPOE_DAEMON_NAME[]        = "pppoe_wlan0";
static const char PPPOE_DAEMON_PROP_NAME[]   = "init.svc.pppoe_wlan0";
static const char HOSTNAME_PROP_NAME[] = "net.hostname";
static const char PPPOE_PROP_NAME_PREFIX[]  = "pppoe";
static const int NAP_TIME = 200;   /* wait for 200ms at a time */
                                  /* when polling for property values */
static char errmsg[100];
static char * PPPOE_RESULT_KEY= "net.pppoe.status";

#define INITIAL_STATUS "-2"
#define PATH_OF_PID "/data/misc/ppp/"

static void clear_ip_info()
{
    char prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];

	char interface[PROPERTY_VALUE_MAX];
	property_get("net.pppoe.interface", interface, NULL);
	ALOGD("clear_ip_info: pppoe_interface=%s", interface);

	snprintf(prop_name, sizeof(prop_name), "net.%s.local-ip", interface);
    property_set(prop_name, "");

	snprintf(prop_name, sizeof(prop_name), "net.%s.remote-ip", interface);
    property_set(prop_name, "");

	snprintf(prop_name, sizeof(prop_name), "net.%s.gw", interface);
    property_set(prop_name, "");

	snprintf(prop_name, sizeof(prop_name), "net.%s.dns1", interface);
    property_set(prop_name, "");

	snprintf(prop_name, sizeof(prop_name), "net.%s.dns2", interface);
    property_set(prop_name, "");
}


/*
 * Wait for a system property to be assigned a specified value.
 * If desired_value is NULL, then just wait for the property to
 * be created with any value. maxwait is the maximum amount of
 * time in seconds to wait before giving up.
 */
static int wait_for_property(const char *name, const char *desired_value, int maxwait)
{
    char value[PROPERTY_VALUE_MAX] = {'\0'};
    int maxnaps = (maxwait * 1000) / NAP_TIME;

    if (maxnaps < 1) {
        maxnaps = 1;
    }

    while (maxnaps-- > 0) {
        usleep(NAP_TIME * 1000);
        if (property_get(name, value, NULL)) {
            if (desired_value == NULL || 
                    strcmp(value, desired_value) == 0) {
                return 0;
            }
        }
    }
    return -1; /* failure */
}

static int fill_ip_info( char *iplocal,
		char *ipremote,
		char *gateway,
		char *dns1,
		char *dns2,
		char *ppplinkname)
{
	char prop_name[PROPERTY_KEY_MAX];
    char prop_value[PROPERTY_VALUE_MAX];

	//char interface[PROPERTY_VALUE_MAX];
	property_get("net.pppoe.interface", ppplinkname, NULL);
	ALOGD("fill_ip_info: pppoe_interface=%s", ppplinkname);
	
	snprintf(prop_name, sizeof(prop_name), "net.%s.local-ip", ppplinkname);
    property_get(prop_name, iplocal, NULL);
	ALOGD(",iplocal=%s", iplocal);

	snprintf(prop_name, sizeof(prop_name), "net.%s.remote-ip", ppplinkname);
    property_get(prop_name, ipremote, NULL);
	ALOGD(",ipremote=%s", ipremote);

	snprintf(prop_name, sizeof(prop_name), "net.%s.gw", ppplinkname);
    property_get(prop_name, gateway, NULL);
	ALOGD(",gateway=%s", gateway);

	snprintf(prop_name, sizeof(prop_name), "net.%s.dns1", ppplinkname);
    property_get(prop_name, dns1, NULL);
	ALOGD(",dns1=%s", dns1);

	snprintf(prop_name, sizeof(prop_name), "net.%s.dns2", ppplinkname);
    property_get(prop_name, dns2, NULL);
	ALOGD(",dns2=%s\n", dns2);

	return 0;
}

/*
 * Start the PPPOE client daemon, and wait for it to finish
 * configuring the interface.
 *
 * The device init.rc file needs a corresponding entry for this work.
 *
 * Example:
 * service pppoe_<interface> /system/bin/pppoe .....
 */
int PPPOE_do_request(const char *interface, int timeout_sec, const char *usr, const char *passwd, int interval, int failure, int mtu, int mru, int mss,
		char* iplocal, char* ipremote, char* gateway, char* dns1, char* dns2, char* ppplinkname)
{
    char pppoe_result_value[PROPERTY_VALUE_MAX] = {'\0'};
    char daemon_cmd[92/*64*/];
    const char *ctrl_prop = "ctl.start";
    const char *desired_status = "running";
	int ret;
 
	char value[PROPERTY_VALUE_MAX] = {'\0'};
	property_get(PPPOE_DAEMON_PROP_NAME, value, NULL);
	if (strcmp(value, desired_status) == 0)
	{
		ALOGE("duplicate: init.svc.pppoe* is running, cannot start twice.");
		return -2;
	}

	if (timeout_sec < 5)
	{
        snprintf(errmsg, sizeof(errmsg), "%s", "Timeout setting: too short. Use default value(5s),instead.");
		timeout_sec = 5;
	}

    /* Erase any previous setting of the dhcp result property */
    property_set(PPPOE_RESULT_KEY, "");

	snprintf(daemon_cmd, sizeof(daemon_cmd), "%s:%s %d %d %d %s %s %d %d", PPPOE_DAEMON_NAME,
			interface, mss, mtu, mru, usr, passwd, interval, failure);

	ALOGD("Start command:%s\n", daemon_cmd);
	ALOGD("timeout_sec=%d\n", timeout_sec);


    property_set(ctrl_prop, daemon_cmd);

    if (wait_for_property(PPPOE_DAEMON_PROP_NAME, desired_status, 5) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for PPPOE to start");
		ALOGE("%s", "init.svc.pppoe* != running.");

        return -2;
    }

    /* Wait for the daemon to return a result */
    if (wait_for_property(PPPOE_RESULT_KEY, NULL, timeout_sec) < 0) {
        snprintf(errmsg, sizeof(errmsg), "%s", "Timed out waiting for PPPOE to finish");
		ALOGE("%s", "net.pppoe.status == NULL.");
        return -2;
    }

	property_get(PPPOE_RESULT_KEY, pppoe_result_value, NULL);
	if (strcmp(pppoe_result_value, "0") == 0)
	{
		fill_ip_info(iplocal, ipremote, gateway, dns1, dns2, ppplinkname);
	}
	else
	{
		ALOGE("net.pppoe.status == %s.", pppoe_result_value);
	}

	ret = atoi(pppoe_result_value);
	ALOGD("pppoe_do_request return value: %d\n", ret);
	return ret;
}


#define MAXPATHLEN 128
static pid_t read_pid(void)
{
	FILE *fp;
	pid_t pid;
	char pidfile[MAXPATHLEN];

	char iface[PROPERTY_VALUE_MAX];
	property_get("net.pppoe.interface", iface, NULL);

	snprintf(pidfile, MAXPATHLEN, "%s%s.pid", PATH_OF_PID, iface);
	if ((fp = fopen(pidfile, "r")) == NULL) 
	{
		ALOGE("%s", "Failed to open pid file.");
		return 0;
	}
	if (fscanf(fp, "%d", &pid) != 1)
		pid = 0;
	fclose(fp);
	return pid;
}
/**
 * Stop the PPPOE client daemon.
 */
int PPPOE_stop(const char *interface)
{
	char command[PROPERTY_VALUE_MAX];
	pid_t pid = read_pid();
	if (pid > 0)
	{
		snprintf(command, PROPERTY_VALUE_MAX, "kill -9 %d", pid);
		ALOGD("system: %s", command);
		if (-1 == system(command))
		{
			ALOGE("Failed to execute kill system command.");
			return -1;
		}
		clear_ip_info();
		return 0;
	}
	else
	{
		ALOGE("pid less than 0");
		return -1;
	}
	
    /* Stop the daemon and wait until it's reported to be stopped */
	/*
    const char *ctrl_prop = "ctl.stop";

    property_set(ctrl_prop, PPPOE_DAEMON_NAME);

    if (wait_for_property(PPPOE_DAEMON_PROP_NAME, "stopped", 5) < 0) {
		ALOGD("%s", "Fail: pppoe service not set to Stopped in 5 seconds.");
        return -1;
    }

    property_set(PPPOE_RESULT_KEY, "-2");

	clear_ip_info();

    return 0;
	*/
}

char *PPPOE_get_errmsg() {
    return errmsg;
}

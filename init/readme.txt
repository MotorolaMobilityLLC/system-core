
Android Init Language
---------------------

The Android Init Language consists of four broad classes of statements,
which are Actions, Commands, Services, and Options.

All of these are line-oriented, consisting of tokens separated by
whitespace.  The c-style backslash escapes may be used to insert
whitespace into a token.  Double quotes may also be used to prevent
whitespace from breaking text into multiple tokens.  The backslash,
when it is the last character on a line, may be used for line-folding.

Lines which start with a # (leading whitespace allowed) are comments.

Actions and Services implicitly declare a new section.  All commands
or options belong to the section most recently declared.  Commands
or options before the first section are ignored.

Actions and Services have unique names.  If a second Action or Service
is declared with the same name as an existing one, it is ignored as
an error.  (??? should we override instead)


Actions
-------
Actions are named sequences of commands.  Actions have a trigger which
is used to determine when the action should occur.  When an event
occurs which matches an action's trigger, that action is added to
the tail of a to-be-executed queue (unless it is already on the
queue).

Each action in the queue is dequeued in sequence and each command in
that action is executed in sequence.  Init handles other activities
(device creation/destruction, property setting, process restarting)
"between" the execution of the commands in activities.

Actions take the form of:

on <trigger>
   <command>
   <command>
   <command>


Services
--------
Services are programs which init launches and (optionally) restarts
when they exit.  Services take the form of:

service <name> <pathname> [ <argument> ]*
   <option>
   <option>
   ...


Options
-------
Options are modifiers to services.  They affect how and when init
runs the service.

critical
   This is a device-critical service. If it exits more than four times in
   four minutes, the device will reboot into recovery mode.

disabled
   This service will not automatically start with its class.
   It must be explicitly started by name.

setenv <name> <value>
   Set the environment variable <name> to <value> in the launched process.

socket <name> <type> <perm> [ <user> [ <group> [ <seclabel> ] ] ]
   Create a unix domain socket named /dev/socket/<name> and pass
   its fd to the launched process.  <type> must be "dgram", "stream" or "seqpacket".
   User and group default to 0.
   'seclabel' is the SELinux security context for the socket.
   It defaults to the service security context, as specified by seclabel or
   computed based on the service executable file security context.

user <username>
   Change to username before exec'ing this service.
   Currently defaults to root.  (??? probably should default to nobody)
   Currently, if your process requires linux capabilities then you cannot use
   this command. You must instead request the capabilities in-process while
   still root, and then drop to your desired uid.

group <groupname> [ <groupname> ]*
   Change to groupname before exec'ing this service.  Additional
   groupnames beyond the (required) first one are used to set the
   supplemental groups of the process (via setgroups()).
   Currently defaults to root.  (??? probably should default to nobody)

seclabel <seclabel>
  Change to 'seclabel' before exec'ing this service.
  Primarily for use by services run from the rootfs, e.g. ueventd, adbd.
  Services on the system partition can instead use policy-defined transitions
  based on their file security context.
  If not specified and no transition is defined in policy, defaults to the init context.

oneshot
   Do not restart the service when it exits.

class <name>
   Specify a class name for the service.  All services in a
   named class may be started or stopped together.  A service
   is in the class "default" if one is not specified via the
   class option.

onrestart
    Execute a Command (see below) when service restarts.


Triggers
--------
   Triggers are strings which can be used to match certain kinds
   of events and used to cause an action to occur.

boot
   This is the first trigger that will occur when init starts
   (after /init.conf is loaded)

<name>=<value>
   Triggers of this form occur when the property <name> is set
   to the specific value <value>.

   One can also test multiple properties to execute a group
   of commands. For example:

   on property:test.a=1 && property:test.b=1
       setprop test.c 1

   The above stub sets test.c to 1 only when
   both test.a=1 and test.b=1


Commands
--------

exec [ <seclabel> [ <user> [ <group> ]* ] ] -- <command> [ <argument> ]*
   Fork and execute command with the given arguments. The command starts
   after "--" so that an optional security context, user, and supplementary
   groups can be provided. No other commands will be run until this one
   finishes.

execonce <path> [ <argument> ]*
   Fork and execute a program (<path>).  This will block until
   the program completes execution.  This command can be run at most
   once during init's lifetime. Subsequent invocations are ignored.
   It is best to avoid execonce as unlike the builtin commands, it runs
   the risk of getting init "stuck".

export <name> <value>
   Set the environment variable <name> equal to <value> in the
   global environment (which will be inherited by all processes
   started after this command is executed)

ifup <interface>
   Bring the network interface <interface> online.

import <filename>
   Parse an init config file, extending the current configuration.

hostname <name>
   Set the host name.

chdir <directory>
   Change working directory.

chmod <octal-mode> <path>
   Change file access permissions.

chown <owner> <group> <path>
   Change file owner and group.

chroot <directory>
  Change process root directory.

class_start <serviceclass>
   Start all services of the specified class if they are
   not already running.

class_stop <serviceclass>
   Stop all services of the specified class if they are
   currently running.

domainname <name>
   Set the domain name.

enable <servicename>
   Turns a disabled service into an enabled one as if the service did not
   specify disabled.
   If the service is supposed to be running, it will be started now.
   Typically used when the bootloader sets a variable that indicates a specific
   service should be started when needed. E.g.
     on property:ro.boot.myfancyhardware=1
        enable my_fancy_service_for_my_fancy_hardware

insmod <path>
   Install the module at <path>

loglevel <level>
   Sets the kernel log level to level. Properties are expanded within <level>.

mkdir <path> [mode] [owner] [group]
   Create a directory at <path>, optionally with the given mode, owner, and
   group. If not provided, the directory is created with permissions 755 and
   owned by the root user and root group. If provided, the mode, owner and group
   will be updated if the directory exists already.

mount <type> <device> <dir> [ <flag> ]* [<options>]
   Attempt to mount the named device at the directory <dir>
   <device> may be of the form mtd@name to specify a mtd block
   device by name.
   <flag>s include "ro", "rw", "remount", "noatime", ...
   <options> include "barrier=1", "noauto_da_alloc", "discard", ... as
   a comma separated string, eg: barrier=1,noauto_da_alloc

restorecon <path> [ <path> ]*
   Restore the file named by <path> to the security context specified
   in the file_contexts configuration.
   Not required for directories created by the init.rc as these are
   automatically labeled correctly by init.

restorecon_recursive <path> [ <path> ]*
   Recursively restore the directory tree named by <path> to the
   security contexts specified in the file_contexts configuration.

setcon <seclabel>
   Set the current process security context to the specified string.
   This is typically only used from early-init to set the init context
   before any other process is started.

setprop <name> <value>
   Set system property <name> to <value>. Properties are expanded
   within <value>.

setrlimit <resource> <cur> <max>
   Set the rlimit for a resource.

start <service>
   Start a service running if it is not already running.

stop <service>
   Stop a service from running if it is currently running.

symlink <target> <path>
   Create a symbolic link at <path> with the value <target>

sysclktz <mins_west_of_gmt>
   Set the system clock base (0 if system clock ticks in GMT)

trigger <event>
   Trigger an event.  Used to queue an action from another
   action.

wait <path> [ <timeout> ]
  Poll for the existence of the given file and return when found,
  or the timeout has been reached. If timeout is not specified it
  currently defaults to five seconds.

write <path> <content>
   Open the file at <path> and write a string to it with write(2).
   If the file does not exist, it will be created. If it does exist,
   it will be truncated. Properties are expanded within <content>.


Properties
----------
Init updates some system properties to provide some insight into
what it's doing:

init.action
   Equal to the name of the action currently being executed or "" if none

init.command
   Equal to the command being executed or "" if none.

init.svc.<name>
   State of a named service ("stopped", "running", "restarting")


Bootcharting
------------

This version of init contains code to perform "bootcharting": generating log
files that can be later processed by the tools provided by www.bootchart.org.

On the emulator, use the new -bootchart <timeout> option to boot with
bootcharting activated for <timeout> seconds.

On a device, create /data/bootchart/start with a command like the following:

  adb shell 'echo $TIMEOUT > /data/bootchart/start'

Where the value of $TIMEOUT corresponds to the desired bootcharted period in
seconds. Bootcharting will stop after that many seconds have elapsed.
You can also stop the bootcharting at any moment by doing the following:

  adb shell 'echo 1 > /data/bootchart/stop'

Note that /data/bootchart/stop is deleted automatically by init at the end of
the bootcharting. This is not the case with /data/bootchart/start, so don't
forget to delete it when you're done collecting data.

The log files are written to /data/bootchart/. A script is provided to
retrieve them and create a bootchart.tgz file that can be used with the
bootchart command-line utility:

  sudo apt-get install pybootchartgui
  ANDROID_SERIAL=<device serial number>
  $ANDROID_BUILD_TOP/system/core/init/grab-bootchart.sh


Debugging init
--------------
By default, programs executed by init will drop stdout and stderr into
/dev/null. To help with debugging, you can execute your program via the
Android program logwrapper. This will redirect stdout/stderr into the
Android logging system (accessed via logcat).

For example
service akmd /system/bin/logwrapper /sbin/akmd

For quicker turnaround when working on init itself, use:

  mm -j
  m ramdisk-nodeps
  m bootimage-nodeps
  adb reboot bootloader
  fastboot boot $ANDROID_PRODUCT_OUT/boot.img

Alternatively, use the emulator:

  emulator -partition-size 1024 -verbose -show-kernel -no-window

You might want to call klog_set_level(6) after the klog_init() call
so you see the kernel logging in dmesg (or the emulator output).

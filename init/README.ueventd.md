# Ueventd
-------
Ueventd manages `/dev`, sets permissions for `/sys`, and handles firmware uevents. It has default
behavior described below, along with a scripting language that allows customizing this behavior,
built on the same parser as init.

Ueventd has one generic customization parameter, the size of rcvbuf_size for the ueventd socket. It
is customized by the `uevent_socket_rcvbuf_size` parameter, which takes the format of

    uevent_socket_rcvbuf_size <size>
For example

    uevent_socket_rcvbuf_size 16M
Sets the uevent socket rcvbuf_size to 16 megabytes.

## /dev
----
Ueventd listens to the kernel uevent sockets and creates/deletes nodes in `/dev` based on the
incoming add/remove uevents. It defaults to using `0600` mode and `root` user/group. It always
creates the nodes with the SELabel from the current loaded SEPolicy. It has three default behaviors
for the node path:

  1. Block devices are created as `/dev/block/<basename uevent DEVPATH>`. There are symlinks created
     to this node at `/dev/block/<type>/<parent device>/<basename uevent DEVPATH>`,
     `/dev/block/<type>/<parent device>/by-name/<uevent PARTNAME>`, and `/dev/block/by-name/<uevent
     PARTNAME>` if the device is a boot device.
  2. USB devices are created as `/dev/<uevent DEVNAME>` if `DEVNAME` was specified for the uevent,
     otherwise as `/dev/bus/usb/<bus_id>/<device_id>` where `bus_id` is `uevent MINOR / 128 + 1` and
     `device_id` is `uevent MINOR % 128 + 1`.
  3. All other devices are created as `/dev/<basename uevent DEVPATH>`

The permissions can be modified using a ueventd.rc script and a line that beings with `/dev`. These
lines take the format of

    devname mode uid gid
For example

    /dev/null 0666 root root
When `/dev/null` is created, its mode will be set to `0666`, its user to `root` and its group to
`root`.

The path can be modified using a ueventd.rc script and a `subsystem` section. There are three to set
for a subsystem: the subsystem name, which device name to use, and which directory to place the
device in. The section takes the below format of

    subsystem <subsystem_name>
      devname uevent_devname|uevent_devpath
      [dirname <directory>]

`subsystem_name` is used to match uevent `SUBSYSTEM` value

`devname` takes one of two options
  1. `uevent_devname` specifies that the name of the node will be the uevent `DEVNAME`
  2. `uevent_devpath` specified that the name of the node will be basename uevent `DEVPATH`

`dirname` is an optional parameter that specifies a directory within `/dev` where the node will be
created.

For example

    subsystem sound
      devname uevent_devpath
      dirname /dev/snd
Indicates that all uevents with `SUBSYSTEM=sound` will create nodes as `/dev/snd/<basename uevent
DEVPATH>`.

## /sys
----
Ueventd by default takes no action for `/sys`, however it can be instructed to set permissions for
certain files in `/sys` when matching uevents are generated. This is done using a ueventd.rc script
and a line that begins with `/sys`. These lines take the format of

    nodename attr mode uid gid
For example

    /sys/devices/system/cpu/cpu* cpufreq/scaling_max_freq 0664 system system
When a uevent that matches the pattern `/sys/devices/system/cpu/cpu*` is sent, the matching sysfs
attribute, `cpufreq/scaling_max_freq`, will have its mode set to `0664`, its user to to `system` and
its group set to `system`.

Note that `*` matches as a wildcard and can be used anywhere in a path.

## Firmware loading
----------------
Ueventd by default serves firmware requests by searching through a list of firmware directories
for a file matching the uevent `FIRMWARE`. It then forks a process to serve this firmware to the
kernel.

The list of firmware directories is customized by a `firmware_directories` line in a ueventd.rc
file. This line takes the format of

    firmware_directories <firmware_directory> [ <firmware_directory> ]*
For example

    firmware_directories /etc/firmware/ /odm/firmware/ /vendor/firmware/ /firmware/image/
Adds those 4 directories, in that order to the list of firmware directories that will be tried by
ueventd. Note that this option always accumulates to the list; it is not possible to remove previous
entries.

Ueventd will wait until after `post-fs` in init, to keep retrying before believing the firmwares are
not present.

The exact firmware file to be served can be customized by running an external program by a
`external_firmware_handler` line in a ueventd.rc file. This line takes the format of

    external_firmware_handler <devpath> <user name to run as> <path to external program>
For example

    external_firmware_handler /devices/leds/red/firmware/coeffs.bin system /vendor/bin/led_coeffs.bin
Will launch `/vendor/bin/led_coeffs.bin` as the system user instead of serving the default firmware
for `/devices/leds/red/firmware/coeffs.bin`.

Ueventd will provide the uevent `DEVPATH` and `FIRMWARE` to this external program on the environment
via environment variables with the same names. Ueventd will use the string written to stdout as the
new name of the firmware to load. It will still look for the new firmware in the list of firmware
directories stated above. It will also reject file names with `..` in them, to prevent leaving these
directories. If stdout cannot be read, or the program returns with any exit code other than
`EXIT_SUCCESS`, or the program crashes, the default firmware from the uevent will be loaded.

Ueventd will additionally log all messages sent to stderr from the external program to the serial
console after the external program has exited.

## Coldboot
--------
Ueventd must create devices in `/dev` for all devices that have already sent their uevents before
ueventd has started. To do so, when ueventd is started it does what it calls a 'coldboot' on `/sys`,
in which it writes 'add' to every 'uevent' file that it finds in `/sys/class`, `/sys/block`, and
`/sys/devices`. This causes the kernel to regenerate the uevents for these paths, and thus for
ueventd to create the nodes.

For boot time purposes, this is done in parallel across a set of child processes. `ueventd.cpp` in
this directory contains documentation on how the parallelization is done.

There is an option to parallelize the restorecon function during cold boot as well. This should only
be done for devices that do not use genfscon, which is the recommended method for labeling sysfs
nodes. To enable this option, use the below line in a ueventd.rc script:

    parallel_restorecon enabled

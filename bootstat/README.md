# bootstat #

The bootstat command records boot events (e.g., `firmware_loaded`,
`boot_complete`) and the relative time at which these events occurred. The
command also aggregates boot event metrics locally and logs the metrics for
analysis.

    Usage: bootstat [options]
    options include:
      -d              Dump the boot event records to the console.
      -h              Show this help.
      -l              Log all metrics to logstorage.
      -r              Record the relative time of a named boot event.

## Relative time ##

The timestamp recorded by bootstat is the uptime of the system, i.e., the
number of seconds since the system booted.

## Recording boot events ##

To record the relative time of an event during the boot phase, call `bootstat`
with the `-r` option and the name of the boot event.

    $ bootstat -r boot_complete

The relative time at which the command runs is recorded along with the name of
the boot event to be persisted.

## Logging boot events ##

To log the persisted boot events, call `bootstat` with the `-l` option.

    $ bootstat -l

bootstat logs all boot events recorded using the `-r` option to the EventLog
using the Tron histogram. These logs may be uploaded by interested parties
for aggregation and analysis of boot time across different devices and
versions.

## Printing boot events ##

To print the set of persisted boot events, call `bootstat` with the `-p` option.

    $ bootstat -p
    Boot events:
    ------------
    boot_complete   71
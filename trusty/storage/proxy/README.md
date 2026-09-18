# Storage Proxy Daemon (`storageproxyd`)

The storage proxy daemon is used by the secure storage server in Trusty to
access storage devices. It provides access to non-secure storage and also
proxies access to the RPMB partition on the MMC or UFS device. The RPMB device
has been provisioned in the factory with a key that is only accessible to the
Trusty instance on the same device. Since Trusty does not have direct access to
the MMC or UFS device, the packets need to be forwarded. Trusty prepares signed
RPMB packets that are sent to the UFS/MMC device, which in turn responds with
signed packets that are forwarded back to Trusty.

## Recommended Configuration

The recommended configuration requires two dedicated partitions for secure
storage. One for the non-persistent secure storage, which will be wiped on
factory resets, and one for persistent secure storage which persists across
factory resets.

-   Use `--file_storage_mapping` for the non-persistent partition (e.g.,
    `0:/dev/block/by-name/secure_storage`). This creates a symlink in the
    `--data_path` directory, which is used to detect factory resets.
-   Use `--file_storage_mapping_no_link` for the persistent partition (e.g.,
    `persist/0:/dev/block/by-name/secure_storage_persist`). This mapping does
    not create a symlink.
-   To support Dynamic System Updates (DSU), `--max_file_size_from` must be
    specified to constrain file sizes when a dedicated partition is not used.
    This should be set to the block device of the non-persistent partition. For
    more details on DSU, see the
    [Android documentation](https://developer.android.com/topic/dsu).

## Sample `init.rc` Entry

Below is a sample `init.rc` service definition for `storageproxyd`. The actual
paths for devices and data may vary based on the specific hardware and
configuration.

```rc
service storageproxyd /system/bin/storageproxyd \
        --trusty_dev /dev/trusty-ipc-dev0 \
        --rpmb_dev /dev/block/by-name/mmcblk0rpmb \
        --data_path /data/secure_storage \
        --dev_type mmc \
        --file_storage_mapping 0:/dev/block/by-name/secure_storage \
        --file_storage_mapping_no_link persist/0:/dev/block/by-name/secure_storage_persist \
        --max_file_size_from /dev/block/by-name/secure_storage
    user system
    group system

on post-fs
    start storageproxyd

on post-fs-data
    mkdir /data/secure_storage 0770 system system
    restart storageproxyd
```

## Early Boot Initialization

It is necessary to restart `storageproxyd` after the `/data` partition is
mounted. This is because some clients, like KeyMint, require access to secure
storage before the `/data` partition is available.

The `storageproxyd` daemon is started early in the boot process (e.g., `on
post-fs`) to provide access to the persistent secure storage partition and the
RPMB partition. However, since the `--data_path` directory is located on
`/data`, the non-persistent storage is not available at this stage.

Once the `/data` partition is mounted (`on post-fs-data`), the data directory
must be created if it does not already exist (e.g., on first boot after a
factory reset). The service is then restarted. This allows `storageproxyd` to
create the symlink for the non-persistent storage partition within its data
directory, making it fully operational.

## Usage

```
storageproxyd -d <trusty_dev> -p <data_path> -r <rpmb_dev> -t <dev_type> [-m <file>] [-f <file>:<mapping>] [-g <file>:<mapping>]
```

## Options

Short Option | Long Option                      | Description
------------ | -------------------------------- | -----------
`-h`         | `--help`                         | Show the help message and exit.
`-d`         | `--trusty_dev`                   | **Required.** Specifies the Trusty device path.
`-p`         | `--data_path`                    | **Required.** Specifies the root path for secure storage data.
`-r`         | `--rpmb_dev`                     | **Required.** Specifies the RPMB device path.
`-t`         | `--dev_type`                     | **Required.** Specifies the device type. Available options are `mmc`, `virt`, `sock`, and `ufs`.
`-m`         | `--max_file_size_from`           | Specifies a file or block device from which to query the maximum size for file-backed storage. This constrains the size of file-based storage.
`-f`         | `--file_storage_mapping`         | Maps a secure storage file to a block device. `storageproxyd` will create the necessary symlinks in the root data path. The format is `<file>:<mapping>`. This option can be used multiple times.
`-g`         | `--file_storage_mapping_no_link` | Similar to `-f`, but `storageproxyd` will not create a symlink. The format is `<file>:<mapping>`. This option can be used multiple times.

use crate::Error;
use log::warn;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use rustutils::android::system_properties::error::PropertyWatcherError;
use rustutils::android::system_properties::PropertyWatcher;

const PREFETCH_RECORD_PROPERTY_STOP: &str = "prefetch_boot.record_stop";

/// Directory prefixes for virtual or temporary filesystems to be ignored during prefetch
/// recording and replaying.
pub static EXCLUDE_PATHS: &[&str] =
    &["/dev/", "/proc/", "/sys/", "/tmp/", "/run/", "/config/", "/mnt/", "/storage/"];

fn is_prefetch_enabled() -> Result<bool, Error> {
    rustutils::android::system_properties::read_bool("ro.prefetch_boot.enabled", false).map_err(
        |e| Error::Custom { error: format!("Failed to read ro.prefetch_boot.enabled: {e}") },
    )
}

fn wait_for_property_true(
    property_name: &str,
    timeout: Option<Duration>,
) -> Result<(), PropertyWatcherError> {
    let mut prop = PropertyWatcher::new(property_name)?;
    prop.wait_for_value("1", timeout)?;
    Ok(())
}

fn ensure_metadata_files(ready_path: &Path, fingerprint_path: &Path) -> Result<bool, Error> {
    let mut metadata_files_exist = true;

    // If metadata is wiped, need to create ready file and fingerprint file.
    if !ready_path.exists() {
        File::create(ready_path)
            .map_err(|_| Error::Custom { error: "File Creation failed".to_string() })?;
        metadata_files_exist = false;
    }

    if !fingerprint_path.exists() {
        write_build_fingerprint(fingerprint_path)?;
        metadata_files_exist = false;
    }
    Ok(metadata_files_exist)
}

fn is_saved_fingerprint_current(fingerprint_path: &Path) -> Result<bool, Error> {
    // Read the fingerprint from the file, or return empty string if the file does not exist.
    let saved_fingerprint = std::fs::read_to_string(fingerprint_path).unwrap_or_default();

    let current_device_fingerprint =
        rustutils::android::system_properties::read("ro.build.fingerprint").map_err(|e| {
            Error::Custom { error: format!("Failed to read ro.build.fingerprint: {e}") }
        })?;

    Ok(current_device_fingerprint.is_some_and(|fp| fp == saved_fingerprint.trim()))
}

/// Wait for record to stop
pub fn wait_for_record_stop() {
    wait_for_property_true(PREFETCH_RECORD_PROPERTY_STOP, None).unwrap_or_else(|e| {
        warn!("failed to wait for {PREFETCH_RECORD_PROPERTY_STOP} with error: {e}")
    });
}

/// Checks if we can perform replay phase.
/// Ensure that the pack file exists and is up-to-date, returns false otherwise.
pub fn can_perform_replay(pack_path: &Path, fingerprint_path: &Path) -> Result<bool, Error> {
    if !is_prefetch_enabled()? {
        return Ok(false);
    }

    if !pack_path.exists() || !fingerprint_path.exists() {
        return Ok(false);
    }

    let saved_fingerprint = std::fs::read_to_string(fingerprint_path)?;

    let current_device_fingerprint =
        rustutils::android::system_properties::read("ro.build.fingerprint").map_err(|e| {
            Error::Custom { error: format!("Failed to read ro.build.fingerprint: {e}") }
        })?;

    Ok(current_device_fingerprint.is_some_and(|fp| fp == saved_fingerprint.trim()))
}

/// Checks if we can perform record phase or if we should prepare device to record in the next boot.
///
/// Ensure that following conditions hold:
///   - File specified in ready_path exists. otherwise, create a new file and return false.
///   - fingerprint contents are different from the current device fingerprint.
///   - pack file does not exist.
///
/// If pack file exists but the fingerprint is different, it means we are in a new version
/// first boot (either OTA update or rollback) so we should not record in this boot, but
/// instead prepare the device to record from the next boot. So we delete both pack and
/// fingerprint files and create a new fingerprint, then return false.
pub fn can_perform_record(
    ready_path: &Path,
    pack_path: &Path,
    fingerprint_path: &Path,
) -> Result<bool, Error> {
    if !is_prefetch_enabled()? {
        return Ok(false);
    }

    if !ensure_metadata_files(ready_path, fingerprint_path)? {
        return Ok(false);
    }

    if is_saved_fingerprint_current(fingerprint_path)? {
        // Not a new version and pack file already exists, do nothing.
        if pack_path.exists() {
            Ok(false)
        // It's a second reboot after an update, or the pack file went missing, so we should record
        } else {
            Ok(true)
        }
    } else {
        // It is a first boot of a new update or rollback, ensure pack file is deleted.
        if pack_path.exists() {
            std::fs::remove_file(pack_path)
                .map_err(|_| Error::Custom { error: "Failed to remove pack file".to_string() })?;
        }
        // Update fingerprint value so we can issue a record in the next reboot.
        write_build_fingerprint(fingerprint_path)?;
        Ok(false)
    }
}

/// Write build finger print to associate prefetch pack file
pub fn write_build_fingerprint(fingerprint_path: &Path) -> Result<(), Error> {
    let mut build_fingerprint_file =
        OpenOptions::new().write(true).create(true).truncate(true).open(fingerprint_path).map_err(
            |source| Error::Create { source, path: fingerprint_path.to_str().unwrap().to_owned() },
        )?;

    let device_build_fingerprint =
        rustutils::android::system_properties::read("ro.build.fingerprint").unwrap_or_default();
    let device_build_fingerprint = device_build_fingerprint.unwrap_or_default();

    build_fingerprint_file.write_all(device_build_fingerprint.as_bytes())?;

    Ok(())
}

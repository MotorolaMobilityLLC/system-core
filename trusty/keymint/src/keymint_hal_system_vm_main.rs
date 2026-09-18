//
// Copyright (C) 2025 The Android Open-Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! This module implements the HAL service for Keymint (Rust) interacting with
//! the Trusty VM.

use android_trusty_commservice::aidl::android::trusty::commservice::ICommService::ICommService;
use android_trusty_provisioning::aidl::android::trusty::provisioning::IProvisioning::IProvisioning;
use anyhow::{anyhow, bail, Context, Result};
use binder::{self, AccessorProvider, ProcessState, Strong};
use clap::Parser;
use kmr_hal::{register_binder_services, send_hal_info, Hal, SerializedChannel, ALL_HALS};
use log::{error, info, warn};
use std::{
    ops::DerefMut,
    panic,
    path::PathBuf,
    sync::{Arc, Mutex},
};

const SERVICE_INSTANCE: &str = "default";

const ACCESSOR_COMM_SERVICE_NAME: &str = "android.os.IAccessor/ICommService/security_vm_keymint";
const INTERNAL_RPC_COMM_SERVICE_NAME: &str =
    "android.trusty.commservice.ICommService/security_vm_keymint";
const ACCESSOR_PROVISIONING_SERVICE_NAME: &str =
    "android.os.IAccessor/IProvisioning/security_vm_keymint";
const INTERNAL_RPC_PROVISIONING_SERVICE_NAME: &str =
    "android.trusty.provisioning.IProvisioning/security_vm_keymint";

#[derive(Debug)]
struct CommServiceChannel {
    comm_service: Strong<dyn ICommService>,
}

impl SerializedChannel for CommServiceChannel {
    const MAX_SIZE: usize = 4000;
    fn execute(&mut self, serialized_req: &[u8]) -> binder::Result<Vec<u8>> {
        self.comm_service.execute_transact(serialized_req)
    }
}

/// Helper struct to provide convenient access to the locked channel.
struct HalChannel(Arc<Mutex<CommServiceChannel>>);

impl HalChannel {
    /// Executes a closure with a mutable reference to the inner channel.
    fn with<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut CommServiceChannel) -> Result<R>,
    {
        let mut channel = self.0.lock().map_err(|_| anyhow!("Mutex was poisoned"))?;
        f(channel.deref_mut())
    }
}

impl From<CommServiceChannel> for HalChannel {
    fn from(channel: CommServiceChannel) -> Self {
        Self(Arc::new(Mutex::new(channel)))
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// HALs to skip registering, e.g., --skip-hal shared-secret
    #[arg(long = "skip-hal", value_parser = parse_hal)]
    skip_hals: Vec<Hal>,

    /// Path to the UDS certificates file for injection.
    #[arg(long, value_name = "FILE")]
    set_uds_certs: Option<PathBuf>,
}

fn parse_hal(s: &str) -> Result<Hal, String> {
    match s {
        "keymint-device" => Ok(Hal::KeyMintDevice),
        "remotely-provisioned-component" => Ok(Hal::RemotelyProvisionedComponent),
        "secure-clock" => Ok(Hal::SecureClock),
        "shared-secret" => Ok(Hal::SharedSecret),
        _ => Err(format!("Unknown HAL: {s}")),
    }
}

fn main() {
    if let Err(e) = inner_main() {
        panic!("HAL service failed: {e:?}");
    }
}

fn inner_main() -> Result<()> {
    let args = Args::parse();
    setup_logging_and_panic_hook();

    info!("Trusty KM HAL service is starting.");
    if cfg!(feature = "vm_rot_nonsecure") {
        warn!("Trusty KM HAL: non-secure RoT initialization.");
    }
    if cfg!(feature = "vm_reprovisioning_via_hal") {
        // only works when provisioning is allowed
        // shall only be used on test devices as  this erases
        // previous provisioning
        // note: only enabled on userdebug and eng builds
        warn!("Trusty KM HAL: Reprovisioning from android properties!");
    }

    info!("Starting thread pool.");
    ProcessState::start_thread_pool();

    // TODO(b/429217397): Use a proper way to register an accessor and get the internal RPC
    // service via accessor here.
    let _accessor_provider =
        AccessorProvider::new(&[INTERNAL_RPC_COMM_SERVICE_NAME.to_owned()], |s| {
            binder::wait_for_service(ACCESSOR_COMM_SERVICE_NAME)
                .and_then(|service| binder::Accessor::from_binder(s, service))
        })
        .ok_or(anyhow!("failed to create commservice accessor provider"))?;
    let comm_service = binder::wait_for_interface(INTERNAL_RPC_COMM_SERVICE_NAME)
        .context("failed to get ICommService interface from accessor")?;
    let channel: HalChannel = CommServiceChannel { comm_service }.into();

    #[cfg(feature = "vm_rot_nonsecure")]
    kmr_hal_nonsecure::send_boot_info(&channel.0)?;

    #[cfg(feature = "vm_reprovisioning_via_hal")]
    kmr_hal_nonsecure::send_attestation_id_info(&channel.0)?;

    let hals_to_register: Vec<_> =
        ALL_HALS.iter().filter(|&x| !args.skip_hals.contains(x)).copied().collect();

    register_binder_services(&channel.0, hals_to_register.as_slice(), SERVICE_INSTANCE)?;

    // Send the HAL service information to the TA
    channel.with(|c| send_hal_info(c).context("failed to populate HAL info"))?;

    if let Some(uds_certs_path) = args.set_uds_certs {
        info!("Attempting to inject UDS certs from {:?}", uds_certs_path);
        let _prov_accessor =
            AccessorProvider::new(&[INTERNAL_RPC_PROVISIONING_SERVICE_NAME.to_owned()], move |s| {
                binder::wait_for_service(ACCESSOR_PROVISIONING_SERVICE_NAME)
                    .and_then(|service| binder::Accessor::from_binder(s, service))
            })
            .ok_or(anyhow!("failed to create provisioning accessor provider"))?;
        let provisioning =
            binder::get_interface::<dyn IProvisioning>(INTERNAL_RPC_PROVISIONING_SERVICE_NAME)
                .context("Failed to connect to Provisioning service")?;

        // TODO(b/478166729): Fetch uds_certs from the file system
        // Pass an empty slice &[] to simulate empty data
        provisioning.setUdsCerts(&[]).context("Failed to get uds_certs")?;
        info!("Successfully injected UdsCerts");
    }

    info!("Successfully registered KeyMint HAL services. Joining thread pool now.");

    ProcessState::join_thread_pool();
    bail!("Binder thread pool exited unexpectedly, terminating HAL service.");
}

fn setup_logging_and_panic_hook() {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keymint-hal-trusty-vm")
            .with_max_level(log::LevelFilter::Info)
            .with_log_buffer(android_logger::LogId::System),
    );
    // In case of a panic, log it before the process terminates.
    panic::set_hook(Box::new(|panic_info| {
        error!("PANIC: {panic_info}");
    }));
}

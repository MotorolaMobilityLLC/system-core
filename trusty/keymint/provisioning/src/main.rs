// Copyright 2025, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! KeyMint provisioning tool

use android_trusty_provisioning::aidl::android::trusty::provisioning::IProvisioning::{
    AttestationIds::AttestationIds, IProvisioning, SigningAlgorithm::SigningAlgorithm,
};
use anyhow::{bail, ensure, Context, Result};
use binder::{self, AccessorProvider, Strong};
use cbor_util::{
    deserialize, parse_value_array, parse_value_map, value_to_bytes, value_to_map, value_to_text,
};
use ciborium::value::Value;
use clap::{Args, Parser, Subcommand};
use der::{Decode, Reader};
use log::{error, info, LevelFilter};
use rustutils::android::system_properties;
use std::fs;
use std::path::{Path, PathBuf};
use x509_cert::Certificate;

mod attestation;

const ACCESSOR_SERVICE_NAME: &str = "android.os.IAccessor/IProvisioning/security_vm_keymint";
const INTERNAL_RPC_SERVICE_NAME: &str =
    "android.trusty.provisioning.IProvisioning/security_vm_keymint";
const HOST_UDS_CERTS_PATH: &str = "/mnt/vendor/persist/uds_certs";

#[derive(Parser, Debug)]
#[clap(about = "KeyMint provisioning tool")]
struct Cli {
    #[clap(subcommand)]
    action: Action,
}

#[derive(clap::ValueEnum, Clone, Debug, PartialEq, Eq)]
enum UdsCertsTarget {
    /// Provision UDS certificates to the host's persistent storage.
    Host,
}

#[derive(Subcommand, Debug, Clone)]
enum Action {
    /// Fetch attestation IDs from the KeyMint.
    #[clap(visible_alias = "get-attestation-ids")]
    GetAttestationIds,

    /// Provisions attestation IDs to the KeyMint.
    #[clap(visible_alias = "set-attestation-ids")]
    SetAttestationIds(Box<AttestationIdsArgs>),

    /// Appends UDS certificate chains.
    #[clap(visible_alias = "append-uds-certs")]
    AppendUdsCerts(AppendUdsCertsArgs),

    /// Fetch UDS certificates from the host persistence layer
    #[clap(visible_alias = "get-uds-certs")]
    GetUdsCerts(UdsCertsArgs),

    /// Parse xml and set attestation keys and certificates
    #[clap(visible_alias = "set-attestation-keys")]
    SetAttestationKeys(SetAttestationKeysArgs),
}

#[derive(Args, Clone, Debug)]
struct SetAttestationKeysArgs {
    /// Path to the attestation keys data file to provision
    #[arg(value_hint = clap::ValueHint::FilePath)]
    input_file: PathBuf,
}

#[derive(Debug)]
struct UdsCerts {
    signer_name: String,
    // CBOR-encoded array of bstr.
    certs: Vec<u8>,
}

impl UdsCerts {
    fn try_from_cbor(k: Value, v: Value, context: &'static str) -> Result<Self> {
        Ok(Self { signer_name: value_to_text(k, context)?, certs: value_to_bytes(v, context)? })
    }

    fn into_cbor_entry(self) -> (Value, Value) {
        (Value::Text(self.signer_name), Value::Bytes(self.certs))
    }
}

#[derive(Args, Clone, Debug)]
struct AppendUdsCertsArgs {
    /// Path to the UDS certificate chain file to provision.
    #[arg(value_hint = clap::ValueHint::FilePath)]
    input_file: PathBuf,

    /// The target for provisioning the UDS certificates.
    #[arg(long, value_enum)]
    target: UdsCertsTarget,
}

#[derive(Args, Clone, Debug)]
struct UdsCertsArgs {
    #[arg(long, value_enum)]
    target: UdsCertsTarget,
}

#[derive(Args, Clone, Debug, Default)]
struct AttestationIdsArgs {
    /// Set brand.
    #[arg(long, short = 'b')]
    brand: Option<String>,

    /// Set device.
    #[arg(long, short = 'd')]
    device: Option<String>,

    /// Set product.
    #[arg(long, short = 'p')]
    product: Option<String>,

    /// Set serial.
    #[arg(long, short = 's')]
    serial: Option<String>,

    /// Set manufacturer.
    #[arg(long, short = 'M')]
    manufacturer: Option<String>,

    /// Set model.
    #[arg(long, short = 'm')]
    model: Option<String>,

    /// Set MEID.
    #[arg(long)]
    meid: Option<String>,

    /// Set IMEI (slot 0).
    #[arg(long)]
    imei: Option<String>,

    /// Set second IMEI (slot 1).
    #[arg(long)]
    imei2: Option<String>,
}

fn main() {
    if let Err(e) = try_main() {
        error!("Provisioning failed: {:?}", e);
        panic!("provisioning failed: {:?}", e)
    }
}

fn try_main() -> Result<()> {
    android_logger::init_once(
        android_logger::Config::default()
            .with_tag("keymint-provisioning-tool")
            .with_max_level(LevelFilter::Info)
            .with_log_buffer(android_logger::LogId::System),
    );
    let cli = Cli::parse();
    info!("Tool started. Arguments: {:?}", cli);

    let _accessor_provider = AccessorProvider::new(&[INTERNAL_RPC_SERVICE_NAME.to_owned()], |s| {
        binder::wait_for_service(ACCESSOR_SERVICE_NAME)
            .and_then(|service| binder::Accessor::from_binder(s, service))
    });
    let provisioning_service: Strong<dyn IProvisioning> =
        binder::wait_for_interface(INTERNAL_RPC_SERVICE_NAME)?;

    info!("Starting command: {:?}", cli.action);
    match &cli.action {
        Action::GetAttestationIds => {
            get_attestation_ids(&provisioning_service)?;
        }
        Action::SetAttestationIds(args) => {
            set_attestation_ids(&provisioning_service, args)?;
        }
        Action::AppendUdsCerts(args) => {
            append_uds_certs(args)?;
        }
        Action::GetUdsCerts(args) => {
            print_uds_certs(args)?;
        }
        Action::SetAttestationKeys(args) => {
            set_attestation_keys(&provisioning_service, args)?;
        }
    }
    info!("Completed command successfully: {:?}", cli.action);

    Ok(())
}

fn set_attestation_keys(
    provisioning_service: &Strong<dyn IProvisioning>,
    args: &SetAttestationKeysArgs,
) -> Result<()> {
    let file = fs::File::open(&args.input_file)
        .with_context(|| format!("Failed to open input file from {}", args.input_file.display()))?;
    let attestation_keys = attestation::get_attestation_keys(file)?;
    for attestation_key in attestation_keys {
        let algorithm = get_signing_algorithm(attestation_key.algorithm)?;
        // TODO(b/478175656): update provisionAttestationKey api to accept certificate chain
        // to consolidate provisioning of key material, clearing of existing cert chain
        // and provision the new cert chain
        provisioning_service.provisionAttestationKey(algorithm, &attestation_key.key)?;

        for cert in attestation_key.certs {
            provisioning_service.appendAttestationCertChain(algorithm, &cert)?;
        }
    }
    Ok(())
}

fn get_signing_algorithm(algorithm: String) -> Result<SigningAlgorithm> {
    match algorithm.as_str() {
        "rsa" => Ok(SigningAlgorithm::RSA),
        "ecdsa" => Ok(SigningAlgorithm::EC),
        unknown_algorithm => bail!("Unknown Algorithm {}", unknown_algorithm),
    }
}

fn load_uds_certs<P: AsRef<Path>>(path: P) -> Result<Vec<UdsCerts>> {
    let data = fs::read(path.as_ref())
        .with_context(|| format!("Failed to read file {:?}", path.as_ref()))?;

    let cert_entries = parse_value_map(&data, "parse Uds certs map")?
        .into_iter()
        .map(|(k, v)| UdsCerts::try_from_cbor(k, v, "converting to UdsCerts"))
        .collect::<Result<Vec<_>>>()?;

    for entry in &cert_entries {
        let cert_values = parse_value_array(&entry.certs, "input cert chain")?;

        ensure!(!cert_values.is_empty(), "Signer '{}' has an empty cert chain", entry.signer_name);

        for (i, val) in cert_values.into_iter().enumerate() {
            let der = value_to_bytes(val, "cert der")?;

            Certificate::from_der(&der).with_context(|| {
                format!("Invalid X.509 at index {} for {}", i, entry.signer_name)
            })?;
        }
    }

    Ok(cert_entries)
}

fn merge_uds_certs<P, Q>(dest_path: P, input_path: Q) -> Result<Vec<UdsCerts>>
where
    P: AsRef<Path>,
    Q: AsRef<Path>,
{
    let dest_path = dest_path.as_ref();
    let input_path = input_path.as_ref();

    let input_uds_certs = load_uds_certs(input_path)?;
    let mut existing_uds_certs = if dest_path.exists() {
        load_uds_certs(dest_path)?
    } else {
        info!("Destination {:?} does not exist. Starting with empty certs.", dest_path);
        Vec::new()
    };

    for input_cert in input_uds_certs {
        existing_uds_certs.retain(|c| c.signer_name != input_cert.signer_name);
        existing_uds_certs.push(input_cert);
    }

    Ok(existing_uds_certs)
}

fn append_uds_certs(args: &AppendUdsCertsArgs) -> Result<()> {
    ensure!(args.target == UdsCertsTarget::Host, "Currently only --target host is supported");

    let uds_certs_store_path = Path::new(HOST_UDS_CERTS_PATH);

    let merged_uds_certs = merge_uds_certs(uds_certs_store_path, &args.input_file)?;

    ensure!(!merged_uds_certs.is_empty(), "Merged UDS certs is empty");

    let merged_uds_certs_map: Vec<(Value, Value)> =
        merged_uds_certs.into_iter().map(|cert| cert.into_cbor_entry()).collect();

    if let Some(parent_dir) = uds_certs_store_path.parent() {
        fs::create_dir_all(parent_dir)
            .with_context(|| format!("Failed to create parent directory {:?}", parent_dir))?;
    }

    let uds_certs_store_file = fs::File::create(uds_certs_store_path)
        .with_context(|| format!("Failed to create destination file {:?}", uds_certs_store_path))?;
    ciborium::into_writer(&Value::Map(merged_uds_certs_map), uds_certs_store_file)
        .with_context(|| "Failed to write CBOR map to file")?;

    info!("Successfully wrote UDS certs to host persistent storage at {:?}", uds_certs_store_path);
    Ok(())
}

fn set_attestation_ids(
    provisioning_service: &Strong<dyn IProvisioning>,
    args: &AttestationIdsArgs,
) -> Result<()> {
    let attest_ids = collect_attestation_ids(args)?;

    provisioning_service
        .provisionAttestationIds(&attest_ids)
        .context("provision Attestation IDs via RPC binder")?;
    info!("Attestation IDs provisioned successfully.");
    Ok(())
}

fn get_attestation_ids(provisioning_service: &Strong<dyn IProvisioning>) -> Result<()> {
    let attest_ids: AttestationIds =
        provisioning_service.getAttestationIds().context("get attestation IDs via RPC binder")?;
    info!("Fetched Attestation IDs.");
    print_attestation_ids(&attest_ids);
    Ok(())
}

fn print_attestation_ids(ids: &AttestationIds) {
    println!("AttestationIds {{");
    println!("  brand: {:?}", ids.brand);
    println!("  device: {:?}", ids.device);
    println!("  product: {:?}", ids.product);
    println!("  serial: {:?}", ids.serial);
    println!("  imei: {:?}", ids.imei);
    println!("  imei2: {:?}", ids.imei2);
    println!("  meid:  {:?}", ids.meid);
    println!("  manufacturer: {:?}", ids.manufacturer);
    println!("  model: {:?}", ids.model);
    println!("}}");
}

fn collect_attestation_ids(args: &AttestationIdsArgs) -> Result<AttestationIds> {
    // Use CLI arg if present, otherwise fallback to system property
    let arg_or_prop = |arg: &Option<String>, prop: &str| -> Result<Vec<u8>> {
        match arg {
            Some(s) => Ok(s.as_bytes().to_vec()),
            None => get_prop(prop),
        }
    };

    // Use CLI arg if present, otherwise default to empty
    let arg_or_default = |arg: &Option<String>| -> Vec<u8> {
        arg.as_ref().map(|s| s.as_bytes().to_vec()).unwrap_or_default()
    };

    Ok(AttestationIds {
        brand: arg_or_prop(&args.brand, "ro.product.brand")?,
        device: arg_or_prop(&args.device, "ro.product.device")?,
        product: arg_or_prop(&args.product, "ro.product.name")?,
        serial: arg_or_prop(&args.serial, "ro.serialno")?,
        manufacturer: arg_or_prop(&args.manufacturer, "ro.product.manufacturer")?,
        model: arg_or_prop(&args.model, "ro.product.model")?,
        imei: arg_or_default(&args.imei),
        imei2: arg_or_default(&args.imei2),
        meid: arg_or_default(&args.meid),
    })
}

fn get_prop(prop_name: &str) -> Result<Vec<u8>> {
    Ok(system_properties::read(prop_name)?.unwrap_or_default().into())
}

fn print_uds_certs(args: &UdsCertsArgs) -> Result<()> {
    ensure!(args.target == UdsCertsTarget::Host, "Only --target host is supported");

    let uds_certs = fs::read(HOST_UDS_CERTS_PATH)
        .with_context(|| format!("Read UdsCerts from {}", HOST_UDS_CERTS_PATH))?;

    let uds_certs_value = deserialize(&uds_certs).context("UdsCerts deserialize CBOR value")?;
    let uds_certs_map = value_to_map(uds_certs_value, "UdsCerts CBOR value to map")?;

    if uds_certs_map.is_empty() {
        println!("No UDS certificates found in {}.", HOST_UDS_CERTS_PATH);
        return Ok(());
    }

    for (signer_name, certs) in uds_certs_map {
        let signer = value_to_text(signer_name, "UdsCerts get signer name")?;
        let certs = value_to_bytes(certs, "UdsCerts get certificate bytes")?;

        println!("SignerName: {}", signer);

        print_certs(&certs)?;
    }
    Ok(())
}

fn print_certs(certs: &[u8]) -> Result<()> {
    let mut reader = der::SliceReader::new(certs)?;
    while !reader.is_finished() {
        let cert_bytes = reader.tlv_bytes()?;
        let certificate =
            Certificate::from_der(cert_bytes).context("Parse certificate from DER")?;
        println!("{:#?}", certificate);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cbor_util::serialize;
    use ciborium::cbor;
    use tempfile::TempDir;

    /// The test certificate is used for testing only
    const TEST_CERTIFICATE: &[u8] = &[
        0x30, 0x82, 0x01, 0xee, 0x30, 0x82, 0x01, 0x94, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x10,
        0x59, 0xae, 0x50, 0x98, 0x95, 0xe1, 0x34, 0x25, 0xf1, 0x21, 0x93, 0xc0, 0x4c, 0xe5, 0x24,
        0x66, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x41,
        0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x1c, 0x44, 0x72, 0x6f, 0x69,
        0x64, 0x20, 0x55, 0x6e, 0x72, 0x65, 0x67, 0x69, 0x73, 0x74, 0x65, 0x72, 0x65, 0x64, 0x20,
        0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x43, 0x41, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03,
        0x55, 0x04, 0x0a, 0x13, 0x0f, 0x47, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x20, 0x54, 0x65, 0x73,
        0x74, 0x20, 0x4c, 0x4c, 0x43, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x32, 0x30, 0x35,
        0x31, 0x34, 0x33, 0x39, 0x33, 0x39, 0x5a, 0x17, 0x0d, 0x32, 0x34, 0x30, 0x32, 0x31, 0x34,
        0x31, 0x34, 0x33, 0x39, 0x33, 0x39, 0x5a, 0x30, 0x39, 0x31, 0x29, 0x30, 0x27, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x13, 0x20, 0x35, 0x39, 0x61, 0x65, 0x35, 0x30, 0x39, 0x38, 0x39, 0x35,
        0x65, 0x31, 0x33, 0x34, 0x32, 0x35, 0x66, 0x31, 0x32, 0x31, 0x39, 0x33, 0x63, 0x30, 0x34,
        0x63, 0x65, 0x35, 0x32, 0x34, 0x36, 0x36, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04,
        0x0a, 0x13, 0x03, 0x54, 0x45, 0x45, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48,
        0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
        0x42, 0x00, 0x04, 0x30, 0x32, 0xcd, 0x95, 0x12, 0xb0, 0x71, 0x8b, 0xb7, 0x14, 0x44, 0x26,
        0x58, 0xd5, 0x82, 0x8c, 0x25, 0x55, 0x2c, 0x6d, 0xef, 0x98, 0xe3, 0x4f, 0x88, 0xd0, 0x74,
        0x82, 0x09, 0x3e, 0x8d, 0x6c, 0xf0, 0xf2, 0x18, 0xd5, 0x83, 0x0e, 0x0d, 0xf2, 0xce, 0xc5,
        0x15, 0x38, 0xe5, 0x6a, 0xe6, 0x4d, 0x4d, 0x95, 0x15, 0xb7, 0x24, 0xe7, 0xcb, 0x4b, 0x63,
        0x42, 0x21, 0xbc, 0x36, 0xc6, 0x0a, 0xd8, 0xa3, 0x76, 0x30, 0x74, 0x30, 0x1d, 0x06, 0x03,
        0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x39, 0x81, 0x41, 0x0a, 0xb9, 0xf3, 0xf4, 0x5b,
        0x75, 0x97, 0x4a, 0x46, 0xd6, 0x30, 0x9e, 0x1d, 0x7a, 0x3b, 0xec, 0xa8, 0x30, 0x1f, 0x06,
        0x03, 0x55, 0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x82, 0xbd, 0x00, 0xde, 0xcb,
        0xc5, 0xe7, 0x72, 0x87, 0x3d, 0x1c, 0x0a, 0x1e, 0x78, 0x4f, 0xf5, 0xd3, 0xc1, 0x3e, 0xb8,
        0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
        0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
        0x02, 0x02, 0x04, 0x30, 0x11, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02,
        0x01, 0x1e, 0x04, 0x03, 0xa1, 0x01, 0x08, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
        0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xae, 0xd8, 0x40,
        0x9e, 0x37, 0x3e, 0x5c, 0x9c, 0xe2, 0x93, 0x3d, 0x8c, 0xf7, 0x05, 0x10, 0xe7, 0xd1, 0x2b,
        0x87, 0x8a, 0xee, 0xd6, 0x1e, 0x6c, 0x3b, 0xd2, 0x91, 0x3e, 0xa5, 0xdf, 0x91, 0x20, 0x02,
        0x20, 0x7f, 0x0f, 0x29, 0x54, 0x60, 0x80, 0x07, 0x50, 0x5f, 0x56, 0x6b, 0x9f, 0xe0, 0x94,
        0xb4, 0x3f, 0x3b, 0x0f, 0x61, 0xa0, 0x33, 0x40, 0xe6, 0x1a, 0x42, 0xda, 0x4b, 0xa4, 0xfd,
        0x92, 0xb9, 0x0f,
    ];

    fn write_test_file(path: &Path, signer: &str, certs: Vec<&[u8]>) -> Result<Vec<u8>> {
        let cert_values: Vec<Value> = certs.into_iter().map(|c| Value::Bytes(c.to_vec())).collect();

        let inner_array_serialized = serialize(&Value::Array(cert_values))?;
        let outer_map = cbor!({
            signer => Value::Bytes(inner_array_serialized.clone())
        })?;

        fs::write(path, serialize(&outer_map)?)?;
        Ok(inner_array_serialized)
    }

    #[test]
    fn loading_nonexistent_file_fails() -> Result<()> {
        let test_dir = TempDir::new()?;
        let file_path = test_dir.path().join("nonexistent.cbor");
        let result = load_uds_certs(&file_path);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn loading_empty_file_fails() -> Result<()> {
        let test_dir = TempDir::new()?;
        let file_path = test_dir.path().join("empty.cbor");
        fs::write(&file_path, [])?;
        let result = load_uds_certs(&file_path);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn loading_valid_uds_certs_succeeds() -> Result<()> {
        let test_dir = TempDir::new()?;
        let file_path = test_dir.path().join("valid.cbor");

        let expected_blob = write_test_file(&file_path, "s1", vec![TEST_CERTIFICATE])?;

        let certs = load_uds_certs(&file_path)?;
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].signer_name, "s1");
        assert_eq!(certs[0].certs, expected_blob);

        let decoded: Vec<Vec<u8>> = ciborium::from_reader(&certs[0].certs[..])?;
        assert_eq!(decoded[0], TEST_CERTIFICATE);
        Ok(())
    }

    #[test]
    fn converting_cbor_with_invalid_types_to_uds_certs_fails() -> Result<()> {
        let context = "test";

        let bad_key = cbor!(123)?;
        let val = cbor!(b"\x01")?;
        assert!(UdsCerts::try_from_cbor(bad_key, val, context).is_err());

        let key = cbor!("s1")?;
        let bad_val = cbor!("not bytes")?;
        assert!(UdsCerts::try_from_cbor(key, bad_val, context).is_err());
        Ok(())
    }

    #[test]
    fn loading_an_uds_certs_file_with_invalid_type_fails() -> Result<()> {
        let test_dir = TempDir::new()?;
        let file_path = test_dir.path().join("corrupt.cbor");

        write_test_file(&file_path, "s1", vec![b"not a real certificate"])?;

        let result = load_uds_certs(&file_path);
        assert!(result.is_err());

        let err_msg = format!("{:#}", result.unwrap_err()).to_lowercase();
        assert!(err_msg.contains("x.509") || err_msg.contains("der"));
        Ok(())
    }

    #[test]
    fn merging_new_signer_to_empty_store_succeeds() -> Result<()> {
        let test_dir = TempDir::new()?;
        let dest_path = test_dir.path().join("dest.cbor");
        let input_path = test_dir.path().join("input.cbor");

        let cert_list = write_test_file(&input_path, "s_a", vec![TEST_CERTIFICATE])?;

        let merged = merge_uds_certs(&dest_path, &input_path)?;
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].signer_name, "s_a");
        assert_eq!(merged[0].certs, cert_list);
        Ok(())
    }

    #[test]
    fn merging_existing_signer_updates_store_succeeds() -> Result<()> {
        let test_dir = TempDir::new()?;
        let dest_path = test_dir.path().join("dest.cbor");
        let input_path = test_dir.path().join("input.cbor");
        write_test_file(&dest_path, "s_a", vec![TEST_CERTIFICATE])?;
        let new_blob = write_test_file(&input_path, "s_a", vec![TEST_CERTIFICATE])?;
        let merged = merge_uds_certs(&dest_path, &input_path)?;
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].signer_name, "s_a");
        assert_eq!(merged[0].certs, new_blob);
        Ok(())
    }

    #[test]
    fn merging_mixed_new_and_existing_signers_succeeds() -> Result<()> {
        let test_dir = TempDir::new()?;
        let dest_path = test_dir.path().join("dest.cbor");
        let input_path = test_dir.path().join("input.cbor");
        write_test_file(&dest_path, "s_a", vec![TEST_CERTIFICATE])?;
        let cert_values = vec![Value::Bytes(TEST_CERTIFICATE.to_vec())];
        let cert_list_serialized = serialize(&Value::Array(cert_values))?;
        let input_map = cbor!({
            "s_a" => Value::Bytes(cert_list_serialized.clone()),
            "s_b" => Value::Bytes(cert_list_serialized.clone())
        })?;
        fs::write(&input_path, serialize(&input_map)?)?;
        let merged = merge_uds_certs(&dest_path, &input_path)?;
        assert_eq!(merged.len(), 2);
        let s_a = merged.iter().find(|c| c.signer_name == "s_a").unwrap();
        let s_b = merged.iter().find(|c| c.signer_name == "s_b").unwrap();
        assert_eq!(s_a.certs, cert_list_serialized);
        assert_eq!(s_b.certs, cert_list_serialized);
        Ok(())
    }

    #[test]
    fn merging_with_non_text_key_fails() -> Result<()> {
        let test_dir = TempDir::new()?;
        let dest_path = test_dir.path().join("dest.cbor");
        let input_path = test_dir.path().join("input.cbor");
        let input_val = Value::Map(vec![(Value::Integer(1u8.into()), Value::Bytes(vec![5]))]);
        fs::write(&input_path, serialize(&input_val)?)?;
        let result = merge_uds_certs(&dest_path, &input_path);
        assert!(result.is_err());
        let err_msg = format!("{:#}", result.unwrap_err());
        assert!(err_msg.to_lowercase().contains("tstr"));
        Ok(())
    }

    #[test]
    fn merging_with_empty_input_file_fails() -> Result<()> {
        let test_dir = TempDir::new()?;
        let dest_path = test_dir.path().join("dest.cbor");
        let input_path = test_dir.path().join("input.cbor");
        fs::write(&input_path, [])?;
        let result = merge_uds_certs(&dest_path, &input_path);
        assert!(result.is_err());
        Ok(())
    }
}

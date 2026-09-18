// Copyright 2026, The Android Open Source Project
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

//! Parse and Fetch attestation keys data

use anyhow::{anyhow, Result};
use std::fs;
use xml::{
    attribute::OwnedAttribute,
    reader::{EventReader, XmlEvent},
};

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct AttestationKey {
    pub(crate) algorithm: String,
    pub(crate) key: Vec<u8>,
    pub(crate) certs: Vec<Vec<u8>>,
}

pub(crate) fn get_attestation_keys(file: fs::File) -> Result<Vec<AttestationKey>> {
    let mut xml_events_reader = EventReader::new(file);
    let mut attestation_keys = vec![];

    loop {
        match xml_events_reader.next()? {
            XmlEvent::StartElement { name, attributes, .. } => {
                if name.local_name.as_str() == "Key" {
                    let algorithm = get_key_algorithm(attributes)?;
                    let attestation_key = AttestationKey { algorithm, key: vec![], certs: vec![] };
                    attestation_keys.push(attestation_key);
                }
            }
            XmlEvent::EndDocument => break,
            _ => continue,
        }
    }

    Ok(attestation_keys)
}

fn get_key_algorithm(attributes: Vec<OwnedAttribute>) -> Result<String> {
    attributes
        .into_iter()
        .find(|attribute| attribute.name.borrow().local_name == "algorithm")
        .map(|attribute| attribute.value)
        .ok_or(anyhow!("Missing algorithm attribute"))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validate_get_attestation_keys() -> Result<()> {
        let file = fs::File::open("set_attestation_key/keymaster_soft_attestation_keys.xml")?;
        let attestation_keys = get_attestation_keys(file)?;
        assert_eq!(attestation_keys.len(), 2);
        let expected_attestation_key_0 =
            AttestationKey { algorithm: "rsa".to_string(), key: vec![], certs: vec![] };
        assert_eq!(attestation_keys[0], expected_attestation_key_0);
        Ok(())
    }
}

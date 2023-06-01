// Copyright (c) 2018-2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]

use mc_attest_core::SecurityVersion;
use mc_attest_verifier_config::{TrustedMeasurement, TrustedMrSignerMeasurement};
use mc_sgx_css::Signature;

pub fn sigstruct() -> Signature {
    Signature::try_from(&include_bytes!(env!("MCBUILD_ENCLAVE_CSS_PATH"))[..])
        .expect("Could not read ingest enclave metadata")
}

pub const CONFIG_ADVISORIES: &[&str] = &[];
pub const HARDENING_ADVISORIES: &[&str] = &["INTEL-SA-00334", "INTEL-SA-00615", "INTEL-SA-00657"];

pub fn mr_signer_measurement(
    override_minimum_svn: impl Into<Option<SecurityVersion>>,
) -> TrustedMeasurement {
    let signature = sigstruct();

    let mr_signer = TrustedMrSignerMeasurement::new(
        &signature.mrsigner(),
        signature.product_id(),
        override_minimum_svn
            .into()
            .unwrap_or_else(|| signature.version()),
        CONFIG_ADVISORIES,
        HARDENING_ADVISORIES,
    );
    mr_signer.into()
}
